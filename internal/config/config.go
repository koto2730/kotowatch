package config

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level YAML configuration for kotowatch.
type Config struct {
	WatchPaths []string `yaml:"watch_paths"`
	Rules      []Rule   `yaml:"rules"`
}

// Rule defines a detection rule for process, network, dns, or file events.
type Rule struct {
	ID          string `yaml:"id"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
	Type        string `yaml:"type"` // "process", "network", "dns", "file"

	// Process & Common matching criteria
	ProcessNames          []string `yaml:"process_names,omitempty"`
	ExcludeProcessNames   []string `yaml:"exclude_process_names,omitempty"`
	ParentNames           []string `yaml:"parent_names,omitempty"`
	ExePathContains       []string `yaml:"exe_path_contains,omitempty"`
	CommandContains       []string `yaml:"command_contains,omitempty"`
	CommandAll            []string `yaml:"command_all,omitempty"`
	ExcludeCommandContains []string `yaml:"exclude_command_contains,omitempty"`
	UsersContain          []string `yaml:"users_contain,omitempty"`

	// Network / DNS matching criteria
	Direction         string   `yaml:"direction,omitempty"` // "inbound", "outbound"
	LocalPorts        []uint16 `yaml:"local_ports,omitempty"`
	RemotePorts       []uint16 `yaml:"remote_ports,omitempty"`
	RemoteIPsContain  []string `yaml:"remote_ips_contain,omitempty"`
	DomainsContain    []string `yaml:"domains_contain,omitempty"`

	// File matching criteria
	Actions             []string `yaml:"actions,omitempty"` // "CREATE", "WRITE", "DELETE", "RENAME"
	PathContains        []string `yaml:"path_contains,omitempty"`
	ExcludePathContains []string `yaml:"exclude_path_contains,omitempty"`
	Extensions          []string `yaml:"extensions,omitempty"` // e.g. [".exe", ".ps1", ".bat"]
}

// Load reads and parses the YAML configuration file, expanding environment variables in watch_paths.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	var expanded []string
	for _, p := range cfg.WatchPaths {
		ep := expandWindowsEnv(p)
		if ep != "" {
			expanded = append(expanded, ep)
		}
	}
	cfg.WatchPaths = expanded
	return &cfg, nil
}

// expandWindowsEnv expands ~, %VAR%, and $VAR style environment variables.
func expandWindowsEnv(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "~/") || strings.HasPrefix(s, `~\`) || s == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if s == "~" {
				s = home
			} else {
				s = home + s[1:]
			}
		}
	}
	for {
		start := strings.IndexByte(s, '%')
		if start == -1 {
			break
		}
		end := strings.IndexByte(s[start+1:], '%')
		if end == -1 {
			break
		}
		end += start + 1
		key := s[start+1 : end]
		val := os.Getenv(key)
		s = s[:start] + val + s[end+1:]
	}
	return os.ExpandEnv(s)
}
