//go:build windows

package procstore

import (
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modntdll                      = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationProcess = modntdll.NewProc("NtQueryInformationProcess")
)

const (
	// ProcessCommandLineInformation retrieves the UNICODE_STRING command line of a target process (Windows 8.1+).
	processCommandLineInformation = 60
)

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// ProcessInfo holds cached metadata for a running or recently started process.
type ProcessInfo struct {
	PID         uint32
	PPID        uint32
	Name        string
	ExePath     string
	CommandLine string
	User        string
	UpdatedAt   time.Time
}

// Store maintains a thread-safe mapping of PID -> ProcessInfo and IP -> Domain name.
type Store struct {
	mu           sync.RWMutex
	procs        map[uint32]ProcessInfo
	emittedProcs map[uint32]bool
	dnsByIP      map[string]string
}

// NewStore creates and initializes a process and DNS store, taking an initial snapshot of running processes.
func NewStore() *Store {
	s := &Store{
		procs:        make(map[uint32]ProcessInfo, 512),
		emittedProcs: make(map[uint32]bool, 512),
		dnsByIP:      make(map[string]string, 512),
	}
	for _, p := range s.RefreshSnapshot() {
		s.emittedProcs[p.PID] = true
	}
	return s
}

// ShouldEmitProcess returns true once per newly started PID to prevent duplicate emissions between ETW and snapshot collectors.
func (s *Store) ShouldEmitProcess(pid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.emittedProcs[pid] {
		return false
	}
	s.emittedProcs[pid] = true
	return true
}

// IsAdmin checks whether the current process is running with elevated Administrator privileges.
func IsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

// RecordDNS caches resolved IP addresses for a queried domain name so network events can show the domain.
func (s *Store) RecordDNS(domain string, ips []string) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			s.dnsByIP[ip] = domain
		}
	}
}

// LookupDomain returns the most recently resolved domain name for an IP address, if known.
func (s *Store) LookupDomain(ip string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dnsByIP[ip]
}

// Upsert stores or updates process information, enriching missing fields from the OS if the process is still alive.
func (s *Store) Upsert(info ProcessInfo) ProcessInfo {
	if info.PID == 0 {
		return info
	}
	if info.ExePath == "" || info.CommandLine == "" || info.User == "" {
		queried := QueryProcessByPID(info.PID)
		if info.ExePath == "" {
			info.ExePath = queried.ExePath
		}
		if info.Name == "" {
			info.Name = queried.Name
		}
		if info.CommandLine == "" {
			info.CommandLine = queried.CommandLine
		}
		if info.User == "" {
			info.User = queried.User
		}
	}
	if info.Name == "" && info.ExePath != "" {
		info.Name = filepath.Base(info.ExePath)
	}
	info.UpdatedAt = time.Now()

	s.mu.Lock()
	s.procs[info.PID] = info
	s.mu.Unlock()
	return info
}

// Get retrieves process info by PID, querying the OS on cache miss.
func (s *Store) Get(pid uint32) ProcessInfo {
	if pid == 0 {
		return ProcessInfo{PID: 0, Name: "System Idle"}
	}
	if pid == 4 {
		return ProcessInfo{PID: 4, Name: "System", User: "NT AUTHORITY\\SYSTEM"}
	}

	s.mu.RLock()
	info, ok := s.procs[pid]
	s.mu.RUnlock()

	if ok && (info.CommandLine != "" || info.Name != "") {
		return info
	}

	queried := QueryProcessByPID(pid)
	if ok {
		if queried.Name == "" {
			queried.Name = info.Name
		}
		if queried.PPID == 0 {
			queried.PPID = info.PPID
		}
	}
	if queried.Name != "" || queried.CommandLine != "" {
		s.mu.Lock()
		s.procs[pid] = queried
		s.mu.Unlock()
	}
	return queried
}

// RefreshSnapshot scans all running processes via Toolhelp32 and returns newly seen processes since the previous snapshot.
func (s *Store) RefreshSnapshot() []ProcessInfo {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return nil
	}

	var newProcs []ProcessInfo
	seen := make(map[uint32]bool, 512)

	for {
		pid := pe.ProcessID
		ppid := pe.ParentProcessID
		name := windows.UTF16ToString(pe.ExeFile[:])
		seen[pid] = true

		s.mu.RLock()
		existing, exists := s.procs[pid]
		s.mu.RUnlock()

		if !exists {
			info := QueryProcessByPID(pid)
			info.PID = pid
			info.PPID = ppid
			if info.Name == "" {
				info.Name = name
			}
			info.UpdatedAt = time.Now()

			s.mu.Lock()
			s.procs[pid] = info
			s.mu.Unlock()

			newProcs = append(newProcs, info)
		} else if existing.PPID == 0 && ppid != 0 {
			existing.PPID = ppid
			s.mu.Lock()
			s.procs[pid] = existing
			s.mu.Unlock()
		}

		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}

	return newProcs
}

// QueryProcessByPID opens a process with PROCESS_QUERY_LIMITED_INFORMATION and queries its path, command line, and user.
func QueryProcessByPID(pid uint32) ProcessInfo {
	info := ProcessInfo{
		PID:       pid,
		UpdatedAt: time.Now(),
	}
	if pid == 0 || pid == 4 {
		info.Name = "System"
		return info
	}

	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return info
	}
	defer windows.CloseHandle(hProc)

	// 1. Query full executable image path
	var buf [windows.MAX_PATH * 2]uint16
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(hProc, 0, &buf[0], &size); err == nil && size > 0 {
		info.ExePath = windows.UTF16ToString(buf[:size])
		info.Name = filepath.Base(info.ExePath)
	}

	// 2. Query full command line via NtQueryInformationProcess(ProcessCommandLineInformation = 60)
	info.CommandLine = queryProcessCommandLine(hProc)

	// 3. Query process owner (DOMAIN\User)
	info.User = queryProcessUser(hProc)

	return info
}

func queryProcessCommandLine(hProc windows.Handle) string {
	var returnLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		uintptr(hProc),
		uintptr(processCommandLineInformation),
		0,
		0,
		uintptr(unsafe.Pointer(&returnLen)),
	)
	// STATUS_INFO_LENGTH_MISMATCH (0xC0000004) or STATUS_BUFFER_OVERFLOW (0x80000005) or STATUS_BUFFER_TOO_SMALL (0xC0000023)
	if returnLen == 0 || returnLen > 65536 {
		_ = status
		return ""
	}

	buf := make([]byte, returnLen)
	status, _, _ = procNtQueryInformationProcess.Call(
		uintptr(hProc),
		uintptr(processCommandLineInformation),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(returnLen),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if status != 0 {
		return ""
	}

	us := (*unicodeString)(unsafe.Pointer(&buf[0]))
	if us.Length == 0 || us.Buffer == nil {
		return ""
	}
	charCount := int(us.Length / 2)
	slice := unsafe.Slice(us.Buffer, charCount)
	return windows.UTF16ToString(slice)
}

func queryProcessUser(hProc windows.Handle) string {
	var token windows.Token
	if err := windows.OpenProcessToken(hProc, windows.TOKEN_QUERY, &token); err != nil {
		return ""
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil || tokenUser == nil || tokenUser.User.Sid == nil {
		return ""
	}
	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}
