package model

import "time"

// EventType represents the category of monitored system activity.
type EventType string

const (
	EventProcess EventType = "PROC"
	EventNetwork EventType = "NET"
	EventDNS     EventType = "DNS"
	EventFile    EventType = "FILE"
)

// Event represents a normalized OS activity event across Process, Network, DNS, and File monitors.
type Event struct {
	Timestamp   time.Time
	Type        EventType
	Action      string // e.g., "START", "CONNECT", "ACCEPT", "QUERY", "CREATE", "WRITE", "DELETE", "RENAME"
	PID         uint32
	PPID        uint32
	ProcessName string
	ExePath     string
	CommandLine string
	ParentName  string
	User        string

	// Network / DNS fields
	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	Domain     string
	Direction  string // "outbound" or "inbound"

	// File fields
	FilePath string
}

// Alert represents a security rule match on an Event.
type Alert struct {
	RuleID      string
	Severity    string // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Description string
	Event       Event
}
