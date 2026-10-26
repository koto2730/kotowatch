//go:build windows

package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"kotowatch/internal/model"
	"kotowatch/internal/procstore"
)

var (
	modadvapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW   = modadvapi32.NewProc("StartTraceW")
	procControlTraceW = modadvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = modadvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW    = modadvapi32.NewProc("OpenTraceW")
	procProcessTrace  = modadvapi32.NewProc("ProcessTrace")
	procCloseTrace    = modadvapi32.NewProc("CloseTrace")

	modtdh                     = windows.NewLazySystemDLL("tdh.dll")
	procTdhGetEventInformation = modtdh.NewProc("TdhGetEventInformation")
	procTdhGetPropertySize     = modtdh.NewProc("TdhGetPropertySize")
	procTdhGetProperty         = modtdh.NewProc("TdhGetProperty")
)

const (
	wnodeFlagTracedGuid          = 0x00020000
	eventTraceRealTimeMode       = 0x00000100
	processTraceModeRealTime     = 0x00000100
	processTraceModeEventRecord  = 0x10000000
	eventTraceControlStop        = 1
	eventControlCodeDisable      = 0
	eventControlCodeEnable       = 1
	traceLevelInformation        = 4
	traceLevelVerbose            = 5
	invalidProcessTraceHandle    = ^uintptr(0)
	etwSessionName               = "kotowatch-etw-session"
)

var (
	// {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716} Microsoft-Windows-Kernel-Process
	guidKernelProcess = windows.GUID{
		Data1: 0x22fb2cd6, Data2: 0x0e7b, Data3: 0x422b,
		Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16},
	}
	// {1c95126e-7eea-49a9-a3fe-a378b03ddb4d} Microsoft-Windows-DNS-Client
	guidDNSClient = windows.GUID{
		Data1: 0x1c95126e, Data2: 0x7eea, Data3: 0x49a9,
		Data4: [8]byte{0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d},
	}
	// {7dd42a49-5329-4832-8dfd-43d979153a88} Microsoft-Windows-Kernel-Network
	guidKernelNetwork = windows.GUID{
		Data1: 0x7dd42a49, Data2: 0x5329, Data3: 0x4832,
		Data4: [8]byte{0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88},
	}
	// {edd08927-9cc4-4e65-b970-c2560fb5c289} Microsoft-Windows-Kernel-File
	guidKernelFile = windows.GUID{
		Data1: 0xedd08927, Data2: 0x9cc4, Data3: 0x4e65,
		Data4: [8]byte{0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89},
	}
)

type wnodeHeader struct {
	BufferSize        uint32
	ProviderId        uint32
	HistoricalContext uint64
	TimeStamp         int64
	Guid              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadId      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

type enableTraceParameters struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32
	SourceId         windows.GUID
	EnableFilterDesc uintptr
	FilterDescCount  uint32
}

// eventTraceLogfileW matches the 64-bit Windows EVENT_TRACE_LOGFILEW layout (456 bytes).
type eventTraceLogfileW struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        [88]byte
	LogfileHeader       [288]byte
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	_pad0               uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	_pad1               uint32
	Context             uintptr
}

type eventDescriptor struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	ProviderId      windows.GUID
	EventDescriptor eventDescriptor
	ProcessorTime   uint64
	ActivityId      windows.GUID
}

type etwBufferContext struct {
	ProcessorNumber uint8
	Alignment       uint8
	LoggerId        uint16
}

type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     etwBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

type propertyDataDescriptor struct {
	PropertyName uintptr
	ArrayIndex   uint32
	Reserved     uint32
}

type eventPropertyInfo struct {
	Flags      uint32
	NameOffset uint32
	InType     uint16
	OutType    uint16
	MapOffset  uint32
	Count      uint16
	Length     uint16
	Reserved   uint32
}

type traceEventInfoHeader struct {
	ProviderGuid          windows.GUID
	EventGuid             windows.GUID
	EventDescriptor       eventDescriptor
	DecodingSource        uint32
	ProviderNameOffset    uint32
	LevelNameOffset       uint32
	ChannelNameOffset     uint32
	KeywordsNameOffset    uint32
	TaskNameOffset        uint32
	OpcodeNameOffset      uint32
	EventMessageOffset    uint32
	ProviderMessageOffset uint32
	BinaryXMLOffset       uint32
	BinaryXMLLength       uint32
	EventNameOffset       uint32
	RelatedActivityIDName uint32
	PropertyCount         uint32
	TopLevelPropertyCount uint32
	Flags                 uint32
}

var (
	etwGlobalMu     sync.RWMutex
	etwGlobalEngine *etwEngine
	etwCallbackPtr  = windows.NewCallback(etwEventRecordCallback)
)

type etwEngine struct {
	store      *procstore.Store
	out        chan<- model.Event
	selfPID    uint32
	watchPaths []string
	ntDriveMap map[string]string
}

func startETWSession(ctx context.Context, store *procstore.Store, watchPaths []string, out chan<- model.Event) error {
	nameUTF16, err := windows.UTF16FromString(etwSessionName)
	if err != nil {
		return err
	}

	// Stop any leftover session with the same name first.
	_ = stopETWSessionByName(nameUTF16)

	bufSize := int(unsafe.Sizeof(eventTraceProperties{})) + len(nameUTF16)*2 + 1024
	propBuf := make([]byte, bufSize)
	props := (*eventTraceProperties)(unsafe.Pointer(&propBuf[0]))
	props.Wnode.BufferSize = uint32(bufSize)
	props.Wnode.ClientContext = 1
	props.Wnode.Flags = wnodeFlagTracedGuid
	props.LogFileMode = eventTraceRealTimeMode
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))

	var hSession uintptr
	ret, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&hSession)),
		uintptr(unsafe.Pointer(&nameUTF16[0])),
		uintptr(unsafe.Pointer(props)),
	)
	if windows.Errno(ret) != windows.ERROR_SUCCESS {
		return fmt.Errorf("StartTraceW failed: %w", windows.Errno(ret))
	}

	// Enable providers:
	// 1. Kernel-Process (Keyword 0x10 = WINEVENT_KEYWORD_PROCESS)
	_ = enableProvider(hSession, &guidKernelProcess, traceLevelInformation, 0x10)
	// 2. DNS-Client
	_ = enableProvider(hSession, &guidDNSClient, traceLevelInformation, 0xFFFFFFFFFFFFFFFF)
	// 3. Kernel-Network (Keyword 0x30 = IPv4 + IPv6 TCP/UDP)
	_ = enableProvider(hSession, &guidKernelNetwork, traceLevelInformation, 0x30)
	// 4. Kernel-File (Keyword 0x10 | 0x200 | 0x400 | 0x800 | 0x1000 = FileName, Create, DeletePath, RenamePath)
	_ = enableProvider(hSession, &guidKernelFile, traceLevelInformation, 0x1E10)

	engine := &etwEngine{
		store:      store,
		out:        out,
		selfPID:    windows.GetCurrentProcessId(),
		watchPaths: watchPaths,
		ntDriveMap: buildNTDriveMap(),
	}
	etwGlobalMu.Lock()
	etwGlobalEngine = engine
	etwGlobalMu.Unlock()

	var logfile eventTraceLogfileW
	logfile.LoggerName = &nameUTF16[0]
	logfile.ProcessTraceMode = processTraceModeRealTime | processTraceModeEventRecord
	logfile.EventRecordCallback = etwCallbackPtr

	traceHandle, _, lastErr := procOpenTraceW.Call(uintptr(unsafe.Pointer(&logfile)))
	if traceHandle == invalidProcessTraceHandle {
		_ = stopETWSessionByName(nameUTF16)
		return fmt.Errorf("OpenTraceW failed: %w", lastErr)
	}

	// Close trace when context is canceled.
	go func() {
		<-ctx.Done()
		_, _, _ = procCloseTrace.Call(traceHandle)
		_ = enableProviderDisable(hSession, &guidKernelProcess)
		_ = enableProviderDisable(hSession, &guidDNSClient)
		_ = enableProviderDisable(hSession, &guidKernelNetwork)
		_ = enableProviderDisable(hSession, &guidKernelFile)
		_ = stopETWSessionByName(nameUTF16)
	}()

	// Run ProcessTrace blocking in a dedicated goroutine.
	go func() {
		handleArr := [1]uintptr{traceHandle}
		_, _, _ = procProcessTrace.Call(
			uintptr(unsafe.Pointer(&handleArr[0])),
			1,
			0,
			0,
		)
	}()

	return nil
}

func stopETWSessionByName(nameUTF16 []uint16) error {
	bufSize := int(unsafe.Sizeof(eventTraceProperties{})) + len(nameUTF16)*2 + 1024
	propBuf := make([]byte, bufSize)
	props := (*eventTraceProperties)(unsafe.Pointer(&propBuf[0]))
	props.Wnode.BufferSize = uint32(bufSize)
	ret, _, _ := procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(&nameUTF16[0])),
		uintptr(unsafe.Pointer(props)),
		eventTraceControlStop,
	)
	if windows.Errno(ret) != windows.ERROR_SUCCESS && windows.Errno(ret) != windows.ERROR_MORE_DATA {
		return windows.Errno(ret)
	}
	return nil
}

func enableProvider(hSession uintptr, guid *windows.GUID, level uint8, matchAnyKeyword uint64) error {
	var params enableTraceParameters
	params.Version = 2
	ret, _, _ := procEnableTraceEx2.Call(
		hSession,
		uintptr(unsafe.Pointer(guid)),
		eventControlCodeEnable,
		uintptr(level),
		uintptr(matchAnyKeyword),
		0,
		0,
		uintptr(unsafe.Pointer(&params)),
	)
	if windows.Errno(ret) != windows.ERROR_SUCCESS {
		return windows.Errno(ret)
	}
	return nil
}

func enableProviderDisable(hSession uintptr, guid *windows.GUID) error {
	ret, _, _ := procEnableTraceEx2.Call(
		hSession,
		uintptr(unsafe.Pointer(guid)),
		eventControlCodeDisable,
		0,
		0,
		0,
		0,
		0,
	)
	if windows.Errno(ret) != windows.ERROR_SUCCESS {
		return windows.Errno(ret)
	}
	return nil
}

func etwEventRecordCallback(recPtr uintptr) uintptr {
	if recPtr == 0 {
		return 0
	}
	etwGlobalMu.RLock()
	eng := etwGlobalEngine
	etwGlobalMu.RUnlock()
	if eng == nil {
		return 0
	}

	rec := (*eventRecord)(unsafe.Pointer(recPtr))
	eng.handleRecord(rec)
	return 0
}

func (e *etwEngine) handleRecord(rec *eventRecord) {
	prov := rec.EventHeader.ProviderId
	id := rec.EventHeader.EventDescriptor.Id
	headerPID := rec.EventHeader.ProcessId

	if headerPID == e.selfPID {
		return
	}

	switch prov {
	case guidKernelProcess:
		// Event ID 1 = ProcessStart
		if id == 1 {
			props := extractTDHProperties(rec)
			pid := parseUint32Prop(props["ProcessID"], headerPID)
			if pid == e.selfPID || pid == 0 {
				return
			}
			ppid := parseUint32Prop(props["ParentProcessID"], 0)
			imgName := e.normalizePath(parseStringProp(props["ImageName"]))
			cmdLine := parseStringProp(props["CommandLine"])

			info := e.store.Upsert(procstore.ProcessInfo{
				PID:         pid,
				PPID:        ppid,
				ExePath:     imgName,
				Name:        filepath.Base(imgName),
				CommandLine: cmdLine,
			})
			if !e.store.ShouldEmitProcess(info.PID) {
				return
			}
			parent := e.store.Get(info.PPID)

			e.emit(model.Event{
				Timestamp:   time.Now(),
				Type:        model.EventProcess,
				Action:      "START",
				PID:         info.PID,
				PPID:        info.PPID,
				ProcessName: info.Name,
				ExePath:     info.ExePath,
				CommandLine: info.CommandLine,
				ParentName:  parent.Name,
				User:        info.User,
			})
		}

	case guidDNSClient:
		// Event ID 3006 / 3008 / 3020 = DNS Query / Response
		if id == 3006 || id == 3008 || id == 3020 {
			props := extractTDHProperties(rec)
			qName := strings.TrimSuffix(strings.TrimSpace(parseStringProp(props["QueryName"])), ".")
			if qName == "" || strings.HasSuffix(qName, ".local") || !strings.Contains(qName, ".") {
				return
			}
			results := parseStringProp(props["QueryResults"])
			var ips []string
			for _, part := range strings.Split(results, ";") {
				part = strings.TrimSpace(part)
				if net.ParseIP(part) != nil {
					ips = append(ips, part)
				}
			}
			if len(ips) > 0 {
				e.store.RecordDNS(qName, ips)
			}
			// Emit on 3008 (completed) or 3006 if no results yet
			if id == 3008 || id == 3020 {
				info := e.store.Get(headerPID)
				parent := e.store.Get(info.PPID)
				remoteIP := ""
				if len(ips) > 0 {
					remoteIP = ips[0]
				}
				e.emit(model.Event{
					Timestamp:   time.Now(),
					Type:        model.EventDNS,
					Action:      "QUERY",
					PID:         headerPID,
					PPID:        info.PPID,
					ProcessName: info.Name,
					ExePath:     info.ExePath,
					CommandLine: info.CommandLine,
					ParentName:  parent.Name,
					User:        info.User,
					Domain:      qName,
					RemoteAddr:  remoteIP,
					Direction:   "outbound",
				})
			}
		}

	case guidKernelNetwork:
		// Event ID 12 = TCPv4 Connect, 15 = TCPv4 Accept, 28 = TCPv6 Connect, 31 = TCPv6 Accept
		if id == 12 || id == 15 || id == 28 || id == 31 {
			props := extractTDHProperties(rec)
			pid := parseUint32Prop(props["PID"], headerPID)
			if pid == e.selfPID || pid == 0 {
				return
			}
			saddr := parseIPProp(props["saddr"])
			daddr := parseIPProp(props["daddr"])
			sport := parsePortProp(props["sport"])
			dport := parsePortProp(props["dport"])

			if daddr == "127.0.0.1" || daddr == "::1" || daddr == "0.0.0.0" || daddr == "" || daddr == saddr {
				return
			}

			action := "CONNECT"
			direction := "outbound"
			if id == 15 || id == 31 {
				action = "ACCEPT"
				direction = "inbound"
			}

			info := e.store.Get(pid)
			parent := e.store.Get(info.PPID)
			domain := e.store.LookupDomain(daddr)

			e.emit(model.Event{
				Timestamp:   time.Now(),
				Type:        model.EventNetwork,
				Action:      action,
				PID:         pid,
				PPID:        info.PPID,
				ProcessName: info.Name,
				ExePath:     info.ExePath,
				CommandLine: info.CommandLine,
				ParentName:  parent.Name,
				User:        info.User,
				LocalAddr:   saddr,
				LocalPort:   sport,
				RemoteAddr:  daddr,
				RemotePort:  dport,
				Domain:      domain,
				Direction:   direction,
			})
		}

	case guidKernelFile:
		// Event ID 11 = NameDelete, 19 = Rename, 26 = DeletePath, 30 = CreateNewFile
		if id == 11 || id == 19 || id == 26 || id == 30 {
			props := extractTDHProperties(rec)
			rawPath := parseStringProp(props["FileName"])
			if rawPath == "" {
				rawPath = parseStringProp(props["FilePath"])
			}
			if rawPath == "" {
				return
			}
			dosPath := e.normalizePath(rawPath)
			if !e.shouldReportFile(dosPath) {
				return
			}

			action := "CREATE"
			switch id {
			case 11, 26:
				action = "DELETE"
			case 19:
				action = "RENAME"
			case 30:
				action = "CREATE"
			}

			info := e.store.Get(headerPID)
			parent := e.store.Get(info.PPID)
			e.emit(model.Event{
				Timestamp:   time.Now(),
				Type:        model.EventFile,
				Action:      action,
				PID:         headerPID,
				PPID:        info.PPID,
				ProcessName: info.Name,
				ExePath:     info.ExePath,
				CommandLine: info.CommandLine,
				ParentName:  parent.Name,
				User:        info.User,
				FilePath:    dosPath,
			})
		}
	}
}

func (e *etwEngine) emit(ev model.Event) {
	select {
	case e.out <- ev:
	default:
	}
}

func (e *etwEngine) shouldReportFile(dosPath string) bool {
	lower := strings.ToLower(dosPath)
	// Ignore noisy browser/temp/cache paths unless explicitly watched
	if strings.Contains(lower, `\appdata\local\temp\`) ||
		strings.Contains(lower, `\appdata\local\google\chrome\user data\`) ||
		strings.Contains(lower, `\appdata\local\microsoft\edge\user data\`) ||
		strings.HasSuffix(lower, ".tmp") ||
		strings.HasSuffix(lower, ".etl") ||
		strings.HasSuffix(lower, ".log") {
		return false
	}
	for _, wp := range e.watchPaths {
		if wp != "" && strings.HasPrefix(lower, strings.ToLower(wp)) {
			return true
		}
	}
	return false
}

func (e *etwEngine) normalizePath(p string) string {
	p = strings.TrimSpace(p)
	for ntPrefix, drive := range e.ntDriveMap {
		if strings.HasPrefix(strings.ToLower(p), strings.ToLower(ntPrefix)+`\`) {
			return drive + p[len(ntPrefix):]
		}
	}
	return p
}

func buildNTDriveMap() map[string]string {
	m := make(map[string]string)
	for c := 'A'; c <= 'Z'; c++ {
		drive := fmt.Sprintf("%c:", c)
		driveUTF16, err := windows.UTF16PtrFromString(drive)
		if err != nil {
			continue
		}
		var target [windows.MAX_PATH]uint16
		n, err := windows.QueryDosDevice(driveUTF16, &target[0], uint32(len(target)))
		if err == nil && n > 0 {
			ntPath := windows.UTF16ToString(target[:n])
			if ntPath != "" {
				m[ntPath] = drive
			}
		}
	}
	return m
}

func extractTDHProperties(rec *eventRecord) map[string][]byte {
	var bufSize uint32
	ret, _, _ := procTdhGetEventInformation.Call(
		uintptr(unsafe.Pointer(rec)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&bufSize)),
	)
	if windows.Errno(ret) != windows.ERROR_INSUFFICIENT_BUFFER || bufSize == 0 || bufSize > 65536 {
		return nil
	}

	infoBuf := make([]byte, bufSize)
	ret, _, _ = procTdhGetEventInformation.Call(
		uintptr(unsafe.Pointer(rec)),
		0,
		0,
		uintptr(unsafe.Pointer(&infoBuf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
	)
	if windows.Errno(ret) != windows.ERROR_SUCCESS {
		return nil
	}

	hdr := (*traceEventInfoHeader)(unsafe.Pointer(&infoBuf[0]))
	count := int(hdr.TopLevelPropertyCount)
	if count == 0 || count > 64 {
		return nil
	}

	props := make(map[string][]byte, count)
	basePtr := uintptr(unsafe.Pointer(&infoBuf[0]))
	propArrayOffset := unsafe.Sizeof(traceEventInfoHeader{})
	propStep := unsafe.Sizeof(eventPropertyInfo{})

	for i := 0; i < count; i++ {
		propInfo := (*eventPropertyInfo)(unsafe.Pointer(basePtr + propArrayOffset + uintptr(i)*propStep))
		if propInfo.NameOffset == 0 || int(propInfo.NameOffset) >= len(infoBuf) {
			continue
		}
		namePtr := (*uint16)(unsafe.Pointer(basePtr + uintptr(propInfo.NameOffset)))
		propName := windows.UTF16PtrToString(namePtr)
		if propName == "" {
			continue
		}

		desc := propertyDataDescriptor{
			PropertyName: basePtr + uintptr(propInfo.NameOffset),
			ArrayIndex:   0xFFFFFFFF,
		}
		var propSize uint32
		r1, _, _ := procTdhGetPropertySize.Call(
			uintptr(unsafe.Pointer(rec)),
			0,
			0,
			1,
			uintptr(unsafe.Pointer(&desc)),
			uintptr(unsafe.Pointer(&propSize)),
		)
		if windows.Errno(r1) != windows.ERROR_SUCCESS || propSize == 0 || propSize > 32768 {
			continue
		}

		valBuf := make([]byte, propSize)
		r2, _, _ := procTdhGetProperty.Call(
			uintptr(unsafe.Pointer(rec)),
			0,
			0,
			1,
			uintptr(unsafe.Pointer(&desc)),
			uintptr(propSize),
			uintptr(unsafe.Pointer(&valBuf[0])),
		)
		if windows.Errno(r2) == windows.ERROR_SUCCESS {
			props[propName] = valBuf
		}
	}

	return props
}

func parseUint32Prop(b []byte, fallback uint32) uint32 {
	if len(b) >= 4 {
		return binary.LittleEndian.Uint32(b[:4])
	}
	return fallback
}

func parseStringProp(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if len(b)%2 == 0 && len(b) >= 2 {
		u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), len(b)/2)
		return windows.UTF16ToString(u16)
	}
	return strings.TrimRight(string(b), "\x00")
}

func parseIPProp(b []byte) string {
	if len(b) == 4 || len(b) == 16 {
		return net.IP(b).String()
	}
	return ""
}

func parsePortProp(b []byte) uint16 {
	if len(b) >= 2 {
		// Network byte order (BigEndian) in ETW Kernel-Network
		return binary.BigEndian.Uint16(b[:2])
	}
	return 0
}
