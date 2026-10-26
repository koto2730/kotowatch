//go:build windows

package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/sys/windows"

	"kotowatch/internal/model"
	"kotowatch/internal/procstore"
)

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	afInet                       = 2
	tcpTableOwnerPidConnections  = 4
	mibTcpStateEstab             = 5
	mibTcpStateSynSent           = 3
	mibTcpStateSynRcvd           = 4
)

type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// WindowsCollector collects Process, Network, DNS, and File events on Windows.
type WindowsCollector struct {
	store      *procstore.Store
	watchPaths []string
	mode       string
}

// New creates a new OS-specific collector for Windows.
func New(store *procstore.Store, watchPaths []string) Collector {
	mode := "User-Mode Fallback (Non-Admin)"
	if procstore.IsAdmin() {
		mode = "ETW Real-Time Kernel Trace (Administrator)"
	}
	return &WindowsCollector{
		store:      store,
		watchPaths: watchPaths,
		mode:       mode,
	}
}

// Mode returns the current collection mode description.
func (c *WindowsCollector) Mode() string {
	return c.mode
}

// Start begins event collection on Windows.
func (c *WindowsCollector) Start(ctx context.Context, out chan<- model.Event) error {
	if procstore.IsAdmin() {
		if err := startETWSession(ctx, c.store, c.watchPaths, out); err != nil {
			c.mode = fmt.Sprintf("User-Mode Fallback (ETW Error: %v)", err)
		}
	}

	// Start fsnotify directory watcher for configured paths.
	go c.runFileWatcher(ctx, out)

	// Run fast process & TCP table delta complement (deduplicated with ETW via procstore).
	go c.runUserModeFallback(ctx, out)

	return nil
}

func (c *WindowsCollector) runFileWatcher(ctx context.Context, out chan<- model.Event) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	defer watcher.Close()

	for _, p := range c.watchPaths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			_ = watcher.Add(p)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			action := ""
			switch {
			case ev.Has(fsnotify.Remove):
				action = "DELETE"
			case ev.Has(fsnotify.Rename):
				action = "RENAME"
			case ev.Has(fsnotify.Create):
				action = "CREATE"
			case ev.Has(fsnotify.Write):
				action = "WRITE"
			}
			if action == "" {
				continue
			}
			select {
			case out <- model.Event{
				Timestamp:   time.Now(),
				Type:        model.EventFile,
				Action:      action,
				ProcessName: "(fsnotify)",
				FilePath:    ev.Name,
			}:
			default:
			}
		case <-watcher.Errors:
		}
	}
}

func (c *WindowsCollector) runUserModeFallback(ctx context.Context, out chan<- model.Event) {
	selfPID := windows.GetCurrentProcessId()
	seenConns := make(map[string]time.Time, 512)

	// Populate initial TCP connections so we only report newly established connections.
	for _, row := range getActiveTCPConnections() {
		key := formatConnKey(row)
		seenConns[key] = time.Now()
	}

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 1. Check new processes
			newProcs := c.store.RefreshSnapshot()
			for _, info := range newProcs {
				if info.PID == selfPID || info.PID == 0 {
					continue
				}
				if !c.store.ShouldEmitProcess(info.PID) {
					continue
				}
				parent := c.store.Get(info.PPID)
				select {
				case out <- model.Event{
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
				}:
				default:
				}
			}

			// 2. Check new TCP connections
			rows := getActiveTCPConnections()
			currentKeys := make(map[string]bool, len(rows))
			for _, row := range rows {
				if row.OwningPid == selfPID || row.OwningPid == 0 {
					continue
				}
				if row.State != mibTcpStateEstab && row.State != mibTcpStateSynSent && row.State != mibTcpStateSynRcvd {
					continue
				}
				key := formatConnKey(row)
				currentKeys[key] = true
				if _, exists := seenConns[key]; exists {
					continue
				}
				seenConns[key] = time.Now()

				localIP := uint32ToIP(row.LocalAddr)
				remoteIP := uint32ToIP(row.RemoteAddr)
				if remoteIP == "127.0.0.1" || remoteIP == "0.0.0.0" || remoteIP == localIP {
					continue
				}
				localPort := ntohs(row.LocalPort)
				remotePort := ntohs(row.RemotePort)

				direction := "outbound"
				action := "CONNECT"
				if localPort == 3389 || localPort == 22 || localPort == 5985 || localPort == 5986 || localPort == 445 {
					direction = "inbound"
					action = "ACCEPT"
				}

				info := c.store.Get(row.OwningPid)
				parent := c.store.Get(info.PPID)
				domain := c.store.LookupDomain(remoteIP)

				select {
				case out <- model.Event{
					Timestamp:   time.Now(),
					Type:        model.EventNetwork,
					Action:      action,
					PID:         row.OwningPid,
					PPID:        info.PPID,
					ProcessName: info.Name,
					ExePath:     info.ExePath,
					CommandLine: info.CommandLine,
					ParentName:  parent.Name,
					User:        info.User,
					LocalAddr:   localIP,
					LocalPort:   localPort,
					RemoteAddr:  remoteIP,
					RemotePort:  remotePort,
					Domain:      domain,
					Direction:   direction,
				}:
				default:
				}
			}

			// Cleanup closed connections
			for k := range seenConns {
				if !currentKeys[k] {
					delete(seenConns, k)
				}
			}
		}
	}
}

func getActiveTCPConnections() []mibTcpRowOwnerPid {
	var size uint32
	_, _, _ = procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		afInet,
		tcpTableOwnerPidConnections,
		0,
	)
	if size == 0 || size > 4*1024*1024 {
		return nil
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		afInet,
		tcpTableOwnerPidConnections,
		0,
	)
	if windows.Errno(ret) != windows.ERROR_SUCCESS || len(buf) < 4 {
		return nil
	}

	numEntries := binary.LittleEndian.Uint32(buf[:4])
	if numEntries == 0 || numEntries > 65536 {
		return nil
	}
	rowSize := uint32(unsafe.Sizeof(mibTcpRowOwnerPid{}))
	if uint32(len(buf)) < 4+numEntries*rowSize {
		return nil
	}

	rows := unsafe.Slice((*mibTcpRowOwnerPid)(unsafe.Pointer(&buf[4])), int(numEntries))
	result := make([]mibTcpRowOwnerPid, len(rows))
	copy(result, rows)
	return result
}

func uint32ToIP(addr uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], addr)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func ntohs(port uint32) uint16 {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], uint16(port))
	return binary.BigEndian.Uint16(b[:])
}

func formatConnKey(r mibTcpRowOwnerPid) string {
	return fmt.Sprintf("%d:%d:%d->%d:%d", r.OwningPid, r.LocalAddr, r.LocalPort, r.RemoteAddr, r.RemotePort)
}
