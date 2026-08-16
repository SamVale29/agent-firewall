package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/SamVale29/agent-firewall/pkg/policy"
)

// Engine evaluates one immutable effective policy relative to a repository.
type Engine struct {
	Policy policy.Policy
	Root   string
}

// New creates an evaluator with an absolute repository root.
func New(config policy.Policy, root string) Engine {
	abs, err := filepath.Abs(root)
	if err == nil {
		root = abs
	}
	return Engine{Policy: config, Root: root}
}

// EvaluatePath explains whether a path is allowed, requires approval, or is
// denied. Deny rules always win over broader allow rules.
func (e Engine) EvaluatePath(input string) policy.Result {
	normalized := e.normalizePath(input)
	if matched, rule := e.matchesPath(normalized, e.Policy.Filesystem.Deny); matched {
		return policy.Result{Decision: policy.DecisionDeny, ResourceType: policy.ResourcePath, Resource: input, Rule: "filesystem.deny: " + rule, Reason: "The path is protected by a deny rule."}
	}
	if matched, rule := e.matchesPath(normalized, e.Policy.Filesystem.Ask); matched {
		return policy.Result{Decision: policy.DecisionAsk, ResourceType: policy.ResourcePath, Resource: input, Rule: "filesystem.ask: " + rule, Reason: "The path requires an explicit decision."}
	}
	if matched, rule := e.matchesPath(normalized, e.Policy.Filesystem.ReadOnly); matched {
		return policy.Result{Decision: policy.DecisionAllow, ResourceType: policy.ResourcePath, Resource: input, Rule: "filesystem.read_only: " + rule, Reason: "The path is available read-only to an enforcing backend."}
	}
	if matched, rule := e.matchesPath(normalized, e.Policy.Filesystem.Allow); matched {
		return policy.Result{Decision: policy.DecisionAllow, ResourceType: policy.ResourcePath, Resource: input, Rule: "filesystem.allow: " + rule, Reason: "The path matches an allowed repository rule."}
	}
	return policy.Result{Decision: e.Policy.Filesystem.Default, ResourceType: policy.ResourcePath, Resource: input, Rule: "filesystem.default", Reason: "No more specific filesystem rule matched."}
}

// EvaluateNetwork evaluates a hostname without pretending that a backend can
// enforce it. Backend capability checks decide whether it can be applied.
func (e Engine) EvaluateNetwork(host string) policy.Result {
	host = strings.ToLower(strings.TrimSpace(host))
	if matched, rule := matchNamed(host, e.Policy.Network.Deny); matched {
		return policy.Result{Decision: policy.DecisionDeny, ResourceType: policy.ResourceNetwork, Resource: host, Rule: "network.deny: " + rule, Reason: "The destination is denied by policy."}
	}
	if matched, rule := matchNamed(host, e.Policy.Network.Ask); matched {
		return policy.Result{Decision: policy.DecisionAsk, ResourceType: policy.ResourceNetwork, Resource: host, Rule: "network.ask: " + rule, Reason: "The destination requires an explicit decision."}
	}
	if matched, rule := matchNamed(host, e.Policy.Network.Allow); matched {
		return policy.Result{Decision: policy.DecisionAllow, ResourceType: policy.ResourceNetwork, Resource: host, Rule: "network.allow: " + rule, Reason: "The destination matches an allowed network rule."}
	}
	return policy.Result{Decision: e.Policy.Network.Default, ResourceType: policy.ResourceNetwork, Resource: host, Rule: "network.default", Reason: "No more specific network rule matched."}
}

// EvaluateShell performs deterministic pre-flight evaluation of the command
// passed to afw run. It does not inspect arbitrary child-process syscalls.
func (e Engine) EvaluateShell(command string) policy.Result {
	if matched, rule := matchCommand(command, e.Policy.Shell.Deny); matched {
		return policy.Result{Decision: policy.DecisionDeny, ResourceType: policy.ResourceShell, Resource: command, Rule: "shell.deny: " + rule, Reason: "The command matches a blocked shell rule."}
	}
	if matched, rule := matchCommand(command, e.Policy.Shell.Ask); matched {
		return policy.Result{Decision: policy.DecisionAsk, ResourceType: policy.ResourceShell, Resource: command, Rule: "shell.ask: " + rule, Reason: "The command is destructive or high impact and needs approval."}
	}
	if matched, rule := matchCommand(command, e.Policy.Shell.Allow); matched {
		return policy.Result{Decision: policy.DecisionAllow, ResourceType: policy.ResourceShell, Resource: command, Rule: "shell.allow: " + rule, Reason: "The command matches an explicit allow rule."}
	}
	return policy.Result{Decision: e.Policy.Shell.Default, ResourceType: policy.ResourceShell, Resource: command, Rule: "shell.default", Reason: "No more specific shell rule matched."}
}

// FilterEnvironment builds a child environment from an explicit allowlist and
// deny patterns. It returns names removed for audit and dry-run reporting.
func (e Engine) FilterEnvironment(parent []string) (filtered []string, removed []string) {
	for _, entry := range parent {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			continue
		}
		if matchesAny(key, e.Policy.Environment.Deny) || !matchesAny(key, e.Policy.Environment.Inherit) {
			removed = append(removed, key)
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, removed
}

func (e Engine) normalizePath(input string) string {
	value := strings.TrimSpace(input)
	if value == "" {
		value = "."
	}
	if value == "~" || strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			if value == "~" {
				value = home
			} else {
				value = filepath.Join(home, value[2:])
			}
		}
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(e.Root, value)
	}
	value = filepath.Clean(value)
	return canonicalizePath(value)
}

func (e Engine) matchesPath(path string, patterns []string) (bool, string) {
	for _, raw := range patterns {
		pattern := raw
		if pattern == "" {
			continue
		}
		if pattern == "~" || strings.HasPrefix(pattern, "~/") || strings.HasPrefix(pattern, `~\`) {
			if home, err := os.UserHomeDir(); err == nil {
				if pattern == "~" {
					pattern = home
				} else {
					pattern = filepath.Join(home, pattern[2:])
				}
			}
		} else if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(e.Root, pattern)
		}
		pattern = filepath.Clean(pattern)
		if globMatch(pattern, path) {
			return true, raw
		}
	}
	return false, ""
}

func canonicalizePath(value string) string {
	if resolved, err := filepath.EvalSymlinks(value); err == nil {
		return filepath.Clean(resolved)
	}
	current := value
	var suffix []string
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err == nil {
				for index := len(suffix) - 1; index >= 0; index-- {
					resolved = filepath.Join(resolved, suffix[index])
				}
				return filepath.Clean(resolved)
			}
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
	return filepath.Clean(value)
}

func matchNamed(value string, patterns []string) (bool, string) {
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == value || (strings.HasPrefix(pattern, "*.") && strings.HasSuffix(value, pattern[1:])) || globMatch(pattern, value) {
			return true, pattern
		}
	}
	return false, ""
}

func matchCommand(command string, patterns []string) (bool, string) {
	lower := strings.ToLower(strings.TrimSpace(command))
	for _, pattern := range patterns {
		candidate := strings.ToLower(strings.TrimSpace(pattern))
		if candidate == "" {
			continue
		}
		if strings.Contains(lower, candidate) {
			return true, pattern
		}
	}
	return false, ""
}

func matchesAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if globMatch(strings.ToLower(pattern), strings.ToLower(value)) {
			return true
		}
	}
	return false
}

func globMatch(pattern, value string) bool {
	pattern = filepath.ToSlash(pattern)
	value = filepath.ToSlash(value)
	if pattern == value {
		return true
	}
	if strings.HasSuffix(pattern, "/**") && value == strings.TrimSuffix(pattern, "/**") {
		return true
	}
	var builder strings.Builder
	builder.WriteString("^")
	for index := 0; index < len(pattern); index++ {
		character := pattern[index]
		switch character {
		case '*':
			if index+1 < len(pattern) && pattern[index+1] == '*' {
				builder.WriteString(".*")
				index++
			} else {
				builder.WriteString("[^/]*")
			}
		case '?':
			builder.WriteString("[^/]")
		default:
			builder.WriteString(regexp.QuoteMeta(string(character)))
		}
	}
	builder.WriteString("$")
	matched, err := regexp.MatchString(builder.String(), value)
	return err == nil && matched
}

// ExplainPath returns a human-oriented explanation and retains the structured
// result for callers that need JSON output.
func (e Engine) ExplainPath(path string) (policy.Result, string) {
	result := e.EvaluatePath(path)
	return result, fmt.Sprintf("%s\n\nMatched:\n%s\n\nReason:\n%s", strings.ToUpper(string(result.Decision)), result.Rule, result.Reason)
}
