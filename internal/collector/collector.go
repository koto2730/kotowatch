package collector

import (
	"context"

	"kotowatch/internal/model"
)

// Collector defines the OS-agnostic interface for streaming system events.
type Collector interface {
	// Start begins collecting events and sending them to out until ctx is canceled.
	Start(ctx context.Context, out chan<- model.Event) error
	// Mode returns a description of the active collection mechanism (e.g., "ETW Kernel Trace (Admin)" or "User-Mode Fallback").
	Mode() string
}
