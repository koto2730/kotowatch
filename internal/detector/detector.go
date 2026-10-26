package detector

import (
	"path/filepath"
	"strings"

	"kotowatch/internal/config"
	"kotowatch/internal/model"
)

// Detector evaluates incoming OS events against configured detection rules.
type Detector struct {
	rules []config.Rule
}

// New creates a Detector with the provided rules.
func New(rules []config.Rule) *Detector {
	return &Detector{rules: rules}
}

// Evaluate checks an Event against all rules and returns any matching Alerts.
func (d *Detector) Evaluate(ev model.Event) []model.Alert {
	var alerts []model.Alert
	for _, r := range d.rules {
		if matchesRule(r, ev) {
			sev := strings.ToUpper(r.Severity)
			if sev == "" {
				sev = "MEDIUM"
			}
			alerts = append(alerts, model.Alert{
				RuleID:      r.ID,
				Severity:    sev,
				Description: r.Description,
				Event:       ev,
			})
		}
	}
	return alerts
}

func matchesRule(r config.Rule, ev model.Event) bool {
	if len(r.ExcludeProcessNames) > 0 && containsIgnoreCase(r.ExcludeProcessNames, ev.ProcessName) {
		return false
	}
	if len(r.ExcludeCommandContains) > 0 && containsSubstringIgnoreCase(ev.CommandLine, r.ExcludeCommandContains) {
		return false
	}
	if len(r.UsersContain) > 0 && !containsSubstringIgnoreCase(ev.User, r.UsersContain) {
		return false
	}

	ruleType := strings.ToLower(strings.TrimSpace(r.Type))
	switch ruleType {
	case "process":
		if ev.Type != model.EventProcess {
			return false
		}
		return matchProcessRule(r, ev)
	case "network":
		if ev.Type != model.EventNetwork && ev.Type != model.EventDNS {
			return false
		}
		return matchNetworkRule(r, ev)
	case "dns":
		if ev.Type != model.EventDNS {
			return false
		}
		return matchNetworkRule(r, ev)
	case "file":
		if ev.Type != model.EventFile {
			return false
		}
		return matchFileRule(r, ev)
	default:
		return false
	}
}

func matchProcessRule(r config.Rule, ev model.Event) bool {
	if len(r.ProcessNames) > 0 && !containsIgnoreCase(r.ProcessNames, ev.ProcessName) {
		return false
	}
	if len(r.ParentNames) > 0 && !containsIgnoreCase(r.ParentNames, ev.ParentName) {
		return false
	}
	if len(r.ExePathContains) > 0 {
		targetPath := ev.ExePath
		if targetPath == "" {
			targetPath = ev.CommandLine
		}
		if !containsSubstringIgnoreCase(targetPath, r.ExePathContains) {
			return false
		}
	}
	if len(r.CommandContains) > 0 && !containsSubstringIgnoreCase(ev.CommandLine, r.CommandContains) {
		return false
	}
	if len(r.CommandAll) > 0 && !containsAllSubstringsIgnoreCase(ev.CommandLine, r.CommandAll) {
		return false
	}
	return len(r.ProcessNames) > 0 ||
		len(r.ParentNames) > 0 ||
		len(r.ExePathContains) > 0 ||
		len(r.CommandContains) > 0 ||
		len(r.CommandAll) > 0 ||
		len(r.UsersContain) > 0
}

func matchNetworkRule(r config.Rule, ev model.Event) bool {
	if len(r.ProcessNames) > 0 && !containsIgnoreCase(r.ProcessNames, ev.ProcessName) {
		return false
	}
	if r.Direction != "" && !strings.EqualFold(r.Direction, ev.Direction) {
		return false
	}
	if len(r.LocalPorts) > 0 && !containsPort(r.LocalPorts, ev.LocalPort) {
		return false
	}
	if len(r.RemotePorts) > 0 && !containsPort(r.RemotePorts, ev.RemotePort) {
		return false
	}
	if len(r.RemoteIPsContain) > 0 && !containsSubstringIgnoreCase(ev.RemoteAddr, r.RemoteIPsContain) {
		return false
	}
	if len(r.DomainsContain) > 0 {
		target := ev.Domain
		if target == "" {
			target = ev.RemoteAddr
		}
		if !containsSubstringIgnoreCase(target, r.DomainsContain) {
			return false
		}
	}
	return len(r.ProcessNames) > 0 ||
		r.Direction != "" ||
		len(r.LocalPorts) > 0 ||
		len(r.RemotePorts) > 0 ||
		len(r.RemoteIPsContain) > 0 ||
		len(r.DomainsContain) > 0
}

func matchFileRule(r config.Rule, ev model.Event) bool {
	if len(r.ExcludePathContains) > 0 && containsSubstringIgnoreCase(ev.FilePath, r.ExcludePathContains) {
		return false
	}
	if len(r.ProcessNames) > 0 && !containsIgnoreCase(r.ProcessNames, ev.ProcessName) {
		return false
	}
	if len(r.Actions) > 0 && !containsIgnoreCase(r.Actions, ev.Action) {
		return false
	}
	if len(r.PathContains) > 0 && !containsSubstringIgnoreCase(ev.FilePath, r.PathContains) {
		return false
	}
	if len(r.Extensions) > 0 {
		ext := filepath.Ext(ev.FilePath)
		if !containsIgnoreCase(r.Extensions, ext) {
			return false
		}
	}
	return len(r.ProcessNames) > 0 ||
		len(r.Actions) > 0 ||
		len(r.PathContains) > 0 ||
		len(r.Extensions) > 0
}

func containsIgnoreCase(list []string, target string) bool {
	if target == "" {
		return false
	}
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), target) {
			return true
		}
	}
	return false
}

func containsSubstringIgnoreCase(haystack string, needles []string) bool {
	if haystack == "" {
		return false
	}
	lowerHay := strings.ToLower(haystack)
	for _, n := range needles {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && strings.Contains(lowerHay, n) {
			return true
		}
	}
	return false
}

func containsAllSubstringsIgnoreCase(haystack string, needles []string) bool {
	if haystack == "" {
		return false
	}
	lowerHay := strings.ToLower(haystack)
	for _, n := range needles {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && !strings.Contains(lowerHay, n) {
			return false
		}
	}
	return true
}

func containsPort(ports []uint16, target uint16) bool {
	if target == 0 {
		return false
	}
	for _, p := range ports {
		if p == target {
			return true
		}
	}
	return false
}
