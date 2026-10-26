//go:build darwin || linux

package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"kotowatch/internal/model"
	"kotowatch/internal/procstore"
)

// UnixCollector collects Process, Network, and File events on macOS and Linux.
type UnixCollector struct {
	store      *procstore.Store
	watchPaths []string
	mode       string
}

// New creates a new OS-specific collector for macOS / Linux.
func New(store *procstore.Store, watchPaths []string) Collector {
	mode := "User-Mode Monitor (ps + lsof + kqueue/fsnotify)"
	if procstore.IsAdmin() {
		if runtime.GOOS == "darwin" {
			mode = "macOS Root Monitor (Endpoint Security eslogger + lsof + kqueue)"
		} else {
			mode = "Linux Root Monitor (procfs + lsof + inotify)"
		}
	}
	return &UnixCollector{
		store:      store,
		watchPaths: watchPaths,
		mode:       mode,
	}
}

// Mode returns the current collection mode description.
func (c *UnixCollector) Mode() string {
	return c.mode
}

// Start begins event collection on macOS / Linux.
func (c *UnixCollector) Start(ctx context.Context, out chan<- model.Event) error {
	if procstore.IsAdmin() && runtime.GOOS == "darwin" {
		go c.runMacOSESLogger(ctx, out)
	}
	go c.runFileWatcher(ctx, out)
	go c.runProcessAndNetworkMonitor(ctx, out)
	return nil
}

// esloggerJSON models the subset of `/usr/bin/eslogger` JSON output on macOS 13+.
type esloggerJSON struct {
	EventType int `json:"event_type"`
	Process   struct {
		AuditToken struct {
			PID  uint32 `json:"pid"`
			EUID uint32 `json:"euid"`
		} `json:"audit_token"`
		PPID       uint32 `json:"ppid"`
		Executable struct {
			Path string `json:"path"`
		} `json:"executable"`
	} `json:"process"`
	Event struct {
		Exec *struct {
			Target struct {
				AuditToken struct {
					PID uint32 `json:"pid"`
				} `json:"audit_token"`
				PPID       uint32 `json:"ppid"`
				Executable struct {
					Path string `json:"path"`
				} `json:"executable"`
			} `json:"target"`
			Args []string `json:"args"`
		} `json:"exec"`
		Unlink *struct {
			Target struct {
				Path string `json:"path"`
			} `json:"target"`
		} `json:"unlink"`
	} `json:"event"`
}

func (c *UnixCollector) runMacOSESLogger(ctx context.Context, out chan<- model.Event) {
	if _, err := os.Stat("/usr/bin/eslogger"); err != nil {
		return
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/eslogger", "exec", "unlink")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	selfPID := uint32(os.Getpid())
	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 256*1024)
	scanner.Buffer(buf, 2*1024*1024)

	for scanner.Scan() {
		var rec esloggerJSON
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Event.Exec != nil {
			pid := rec.Event.Exec.Target.AuditToken.PID
			if pid == 0 || pid == selfPID {
				continue
			}
			ppid := rec.Event.Exec.Target.PPID
			exePath := rec.Event.Exec.Target.Executable.Path
			cmdLine := strings.Join(rec.Event.Exec.Args, " ")

			info := c.store.Upsert(procstore.ProcessInfo{
				PID:         pid,
				PPID:        ppid,
				Name:        filepath.Base(exePath),
				ExePath:     exePath,
				CommandLine: cmdLine,
			})
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
		} else if rec.Event.Unlink != nil {
			filePath := rec.Event.Unlink.Target.Path
			if !c.isWatchedPath(filePath) {
				continue
			}
			pid := rec.Process.AuditToken.PID
			info := c.store.Get(pid)
			parent := c.store.Get(info.PPID)
			select {
			case out <- model.Event{
				Timestamp:   time.Now(),
				Type:        model.EventFile,
				Action:      "DELETE",
				PID:         pid,
				PPID:        info.PPID,
				ProcessName: info.Name,
				ExePath:     info.ExePath,
				CommandLine: info.CommandLine,
				ParentName:  parent.Name,
				User:        info.User,
				FilePath:    filePath,
			}:
			default:
			}
		}
	}
}

func (c *UnixCollector) isWatchedPath(p string) bool {
	for _, wp := range c.watchPaths {
		if wp != "" && strings.HasPrefix(p, wp) {
			return true
		}
	}
	return false
}

func (c *UnixCollector) runFileWatcher(ctx context.Context, out chan<- model.Event) {
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

type unixTCPConn struct {
	PID        uint32
	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	State      string
}

func (c *UnixCollector) runProcessAndNetworkMonitor(ctx context.Context, out chan<- model.Event) {
	selfPID := uint32(os.Getpid())
	seenConns := make(map[string]bool, 512)

	for _, conn := range getActiveUnixTCPConnections(selfPID) {
		seenConns[formatUnixConnKey(conn)] = true
	}

	procTicker := time.NewTicker(250 * time.Millisecond)
	netTicker := time.NewTicker(750 * time.Millisecond)
	defer procTicker.Stop()
	defer netTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-procTicker.C:
			newProcs := c.store.RefreshSnapshot()
			for _, info := range newProcs {
				if info.PID == selfPID || info.PID == 0 {
					continue
				}
				// Ignore kotowatch's own child ps/lsof commands
				if info.PPID == selfPID && (info.Name == "ps" || info.Name == "lsof") {
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

		case <-netTicker.C:
			conns := getActiveUnixTCPConnections(selfPID)
			current := make(map[string]bool, len(conns))
			for _, conn := range conns {
				key := formatUnixConnKey(conn)
				current[key] = true
				if seenConns[key] {
					continue
				}
				seenConns[key] = true

				if conn.RemoteAddr == "127.0.0.1" || conn.RemoteAddr == "::1" || conn.RemoteAddr == "" || conn.RemoteAddr == conn.LocalAddr {
					continue
				}

				direction := "outbound"
				action := "CONNECT"
				switch conn.LocalPort {
				case 22, 23, 445, 2375, 2376, 3283, 3389, 5900, 6379, 10250:
					direction = "inbound"
					action = "ACCEPT"
				}

				info := c.store.Get(conn.PID)
				parent := c.store.Get(info.PPID)
				domain := c.store.LookupDomain(conn.RemoteAddr)

				select {
				case out <- model.Event{
					Timestamp:   time.Now(),
					Type:        model.EventNetwork,
					Action:      action,
					PID:         conn.PID,
					PPID:        info.PPID,
					ProcessName: info.Name,
					ExePath:     info.ExePath,
					CommandLine: info.CommandLine,
					ParentName:  parent.Name,
					User:        info.User,
					LocalAddr:   conn.LocalAddr,
					LocalPort:   conn.LocalPort,
					RemoteAddr:  conn.RemoteAddr,
					RemotePort:  conn.RemotePort,
					Domain:      domain,
					Direction:   direction,
				}:
				default:
				}
			}
			for k := range seenConns {
				if !current[k] {
					delete(seenConns, k)
				}
			}
		}
	}
}

func getActiveUnixTCPConnections(selfPID uint32) []unixTCPConn {
	if runtime.GOOS == "linux" {
		if conns := getLinuxProcNetTCP(selfPID); len(conns) > 0 {
			return conns
		}
	}
	cmd := exec.Command("lsof", "-iTCP", "-n", "-P", "-F", "pnT")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var conns []unixTCPConn
	var curPID uint32
	var curState string
	var curName string

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}
		prefix := line[0]
		val := line[1:]

		switch prefix {
		case 'p':
			if pid64, err := strconv.ParseUint(val, 10, 32); err == nil {
				curPID = uint32(pid64)
			}
		case 'n':
			curName = val
		case 'T':
			if strings.HasPrefix(val, "ST=") {
				curState = val[3:]
				if (curState == "ESTABLISHED" || curState == "SYN_SENT") && curPID != 0 && curPID != selfPID && strings.Contains(curName, "->") {
					if conn, ok := parseLsofEndpoints(curPID, curName, curState); ok {
						conns = append(conns, conn)
					}
				}
			}
		}
	}
	return conns
}

// getLinuxProcNetTCP parses /proc/net/tcp and maps socket inodes to owning PIDs via /proc/<pid>/fd.
func getLinuxProcNetTCP(selfPID uint32) []unixTCPConn {
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil
	}

	type rawSock struct {
		localAddr  string
		localPort  uint16
		remoteAddr string
		remotePort uint16
		state      string
		inode      string
	}
	var socks []rawSock
	inodeSet := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		st := fields[3]
		// 01 = TCP_ESTABLISHED, 02 = TCP_SYN_SENT
		if st != "01" && st != "02" {
			continue
		}
		lAddr, lPort, ok1 := parseHexIPPort(fields[1])
		rAddr, rPort, ok2 := parseHexIPPort(fields[2])
		if !ok1 || !ok2 || rAddr == "127.0.0.1" || rAddr == "0.0.0.0" || rAddr == lAddr {
			continue
		}
		inode := fields[9]
		if inode == "0" || inode == "" {
			continue
		}
		stateStr := "ESTABLISHED"
		if st == "02" {
			stateStr = "SYN_SENT"
		}
		socks = append(socks, rawSock{
			localAddr:  lAddr,
			localPort:  lPort,
			remoteAddr: rAddr,
			remotePort: rPort,
			state:      stateStr,
			inode:      inode,
		})
		inodeSet[inode] = true
	}
	if len(socks) == 0 {
		return nil
	}

	inodeToPID := make(map[string]uint32, len(inodeSet))
	procEntries, err := os.ReadDir("/proc")
	if err == nil {
		for _, pe := range procEntries {
			if !pe.IsDir() {
				continue
			}
			pid64, err := strconv.ParseUint(pe.Name(), 10, 32)
			if err != nil || uint32(pid64) == selfPID {
				continue
			}
			fdDir := filepath.Join("/proc", pe.Name(), "fd")
			fds, err := os.ReadDir(fdDir)
			if err != nil {
				continue
			}
			for _, fd := range fds {
				target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
				if err != nil {
					continue
				}
				if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
					ino := target[8 : len(target)-1]
					if inodeSet[ino] {
						inodeToPID[ino] = uint32(pid64)
					}
				}
			}
		}
	}

	var conns []unixTCPConn
	for _, s := range socks {
		pid := inodeToPID[s.inode]
		if pid == selfPID {
			continue
		}
		conns = append(conns, unixTCPConn{
			PID:        pid,
			LocalAddr:  s.localAddr,
			LocalPort:  s.localPort,
			RemoteAddr: s.remoteAddr,
			RemotePort: s.remotePort,
			State:      s.state,
		})
	}
	return conns
}

func parseHexIPPort(s string) (string, uint16, bool) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || len(parts[0]) != 8 {
		return "", 0, false
	}
	ipVal, err1 := strconv.ParseUint(parts[0], 16, 32)
	portVal, err2 := strconv.ParseUint(parts[1], 16, 16)
	if err1 != nil || err2 != nil {
		return "", 0, false
	}
	ip := fmt.Sprintf("%d.%d.%d.%d", byte(ipVal), byte(ipVal>>8), byte(ipVal>>16), byte(ipVal>>24))
	return ip, uint16(portVal), true
}

func parseLsofEndpoints(pid uint32, endpoints string, state string) (unixTCPConn, bool) {
	parts := strings.SplitN(endpoints, "->", 2)
	if len(parts) != 2 {
		return unixTCPConn{}, false
	}
	lAddr, lPort, ok1 := splitHostPort(parts[0])
	rAddr, rPort, ok2 := splitHostPort(parts[1])
	if !ok1 || !ok2 {
		return unixTCPConn{}, false
	}
	return unixTCPConn{
		PID:        pid,
		LocalAddr:  lAddr,
		LocalPort:  lPort,
		RemoteAddr: rAddr,
		RemotePort: rPort,
		State:      state,
	}, true
}

func splitHostPort(s string) (string, uint16, bool) {
	idx := strings.LastIndexByte(s, ':')
	if idx <= 0 || idx == len(s)-1 {
		return "", 0, false
	}
	host := strings.Trim(s[:idx], "[]")
	port64, err := strconv.ParseUint(s[idx+1:], 10, 16)
	if err != nil {
		return "", 0, false
	}
	return host, uint16(port64), true
}

func formatUnixConnKey(c unixTCPConn) string {
	return fmt.Sprintf("%d:%s:%d->%s:%d", c.PID, c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort)
}
