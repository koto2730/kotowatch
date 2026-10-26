//go:build darwin || linux

package procstore

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

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

// ShouldEmitProcess returns true once per newly started PID to prevent duplicate emissions.
func (s *Store) ShouldEmitProcess(pid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.emittedProcs[pid] {
		return false
	}
	s.emittedProcs[pid] = true
	return true
}

// IsAdmin checks whether the current process is running as root (EUID == 0).
func IsAdmin() bool {
	return os.Geteuid() == 0
}

// RecordDNS caches resolved IP addresses for a queried domain name.
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

// LookupDomain returns the most recently resolved domain name for an IP address.
func (s *Store) LookupDomain(ip string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dnsByIP[ip]
}

// Upsert stores or updates process information, enriching missing fields if needed.
func (s *Store) Upsert(info ProcessInfo) ProcessInfo {
	if info.PID == 0 {
		return info
	}
	if info.CommandLine == "" || info.Name == "" || info.User == "" {
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
		if info.PPID == 0 {
			info.PPID = queried.PPID
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
		return ProcessInfo{PID: 0, Name: "kernel_task"}
	}
	if pid == 1 {
		return ProcessInfo{PID: 1, Name: "launchd", User: "root"}
	}

	s.mu.RLock()
	info, ok := s.procs[pid]
	s.mu.RUnlock()

	if ok && (info.CommandLine != "" || info.Name != "") {
		return info
	}

	queried := QueryProcessByPID(pid)
	if queried.Name != "" || queried.CommandLine != "" {
		s.mu.Lock()
		s.procs[pid] = queried
		s.mu.Unlock()
	}
	return queried
}

// RefreshSnapshot scans all running processes via `ps` and returns newly discovered processes.
func (s *Store) RefreshSnapshot() []ProcessInfo {
	cmd := exec.Command("ps", "-axo", "pid=,ppid=,user=,args=")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var newProcs []ProcessInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		info, ok := parsePSLine(line)
		if !ok || info.PID == 0 {
			continue
		}

		s.mu.RLock()
		_, exists := s.procs[info.PID]
		s.mu.RUnlock()

		if !exists {
			s.mu.Lock()
			s.procs[info.PID] = info
			s.mu.Unlock()
			newProcs = append(newProcs, info)
		}
	}
	return newProcs
}

// QueryProcessByPID queries a single PID via `ps`.
func QueryProcessByPID(pid uint32) ProcessInfo {
	info := ProcessInfo{PID: pid, UpdatedAt: time.Now()}
	cmd := exec.Command("ps", "-p", strconv.FormatUint(uint64(pid), 10), "-o", "pid=,ppid=,user=,args=")
	out, err := cmd.Output()
	if err != nil {
		return info
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if parsed, ok := parsePSLine(line); ok {
			return parsed
		}
	}
	return info
}

func parsePSLine(line string) (ProcessInfo, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return ProcessInfo{}, false
	}
	pid64, err1 := strconv.ParseUint(fields[0], 10, 32)
	ppid64, err2 := strconv.ParseUint(fields[1], 10, 32)
	if err1 != nil || err2 != nil {
		return ProcessInfo{}, false
	}
	user := fields[2]

	// Extract full command line (everything starting from the 4th field)
	idx := 0
	for i := 0; i < 3; i++ {
		for idx < len(line) && (line[idx] == ' ' || line[idx] == '\t') {
			idx++
		}
		for idx < len(line) && line[idx] != ' ' && line[idx] != '\t' {
			idx++
		}
	}
	cmdLine := strings.TrimSpace(line[idx:])
	exePath := fields[3]
	name := filepath.Base(exePath)

	return ProcessInfo{
		PID:         uint32(pid64),
		PPID:        uint32(ppid64),
		Name:        name,
		ExePath:     exePath,
		CommandLine: cmdLine,
		User:        user,
		UpdatedAt:   time.Now(),
	}, true
}
