// Package risk provides deterministic, explainable command-risk heuristics.
package risk

import (
	"regexp"
	"strings"
)

// Level is the deterministic severity assigned to a command before it runs.
type Level string

const (
	// Low indicates that no elevated-risk pattern matched.
	Low Level = "low"
	// Medium indicates a command with meaningful but bounded impact.
	Medium Level = "medium"
	// High indicates a command that can affect many files or external state.
	High Level = "high"
	// Critical indicates a command that can cross privilege or data-loss boundaries.
	Critical Level = "critical"
)

// Analysis contains explainable, rule-based risk metadata.
type Analysis struct {
	Level   Level    `json:"level"`
	Reasons []string `json:"reasons"`
}

var (
	recursiveDelete = regexp.MustCompile(`(?i)\brm\s+[^\n;]*-[^\n;]*r`)
	pipeToShell     = regexp.MustCompile(`(?i)(curl|wget)\b[^\n|]*\|\s*(sh|bash|zsh|fish)\b`)
)

// Analyze classifies common high-impact commands. It deliberately does not
// claim to parse every shell grammar or provide containment.
func Analyze(command string) Analysis {
	lower := strings.ToLower(strings.TrimSpace(command))
	result := Analysis{Level: Low}
	add := func(level Level, reason string) {
		if severity(level) > severity(result.Level) {
			result.Level = level
		}
		result.Reasons = append(result.Reasons, reason)
	}

	if recursiveDelete.MatchString(lower) {
		add(High, "recursive deletion can affect many files")
	}
	if strings.Contains(lower, "--no-preserve-root") {
		add(Critical, "root-preservation safeguards are disabled")
	}
	if strings.Contains(lower, "git reset --hard") {
		add(High, "hard reset discards working-tree changes")
	}
	if strings.Contains(lower, "git clean") {
		add(High, "Git cleanup can remove untracked or ignored files")
	}
	if strings.Contains(lower, "sudo ") || strings.HasPrefix(lower, "sudo") {
		add(Critical, "privilege escalation changes the trust boundary")
	}
	if strings.Contains(lower, "shutdown") || strings.Contains(lower, "reboot") {
		add(Critical, "system availability may be affected")
	}
	if strings.Contains(lower, "mkfs") || strings.Contains(lower, "dd ") {
		add(Critical, "raw device or filesystem operations can destroy data")
	}
	if pipeToShell.MatchString(lower) {
		add(High, "downloaded content is executed by a shell")
	}
	if strings.Contains(lower, "docker") || strings.Contains(lower, "podman") {
		add(Medium, "container commands can expose host capabilities")
	}
	if strings.Contains(lower, "kubectl") || strings.Contains(lower, "terraform destroy") {
		add(High, "infrastructure state may be changed or destroyed")
	}
	if strings.Contains(lower, "chmod") || strings.Contains(lower, "chown") {
		add(Medium, "permissions or ownership may be changed")
	}
	if len(result.Reasons) == 0 {
		result.Reasons = []string{"no elevated-risk pattern matched"}
	}
	return result
}

func severity(level Level) int {
	switch level {
	case Medium:
		return 1
	case High:
		return 2
	case Critical:
		return 3
	default:
		return 0
	}
}
