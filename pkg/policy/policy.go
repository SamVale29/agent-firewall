// Package policy contains the stable, dependency-free policy model used by
// Agent Firewall. Evaluation remains deterministic and local to the process.
package policy

import (
	"fmt"
	"strings"
)

// Decision is the action a policy takes for a resource.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionAsk   Decision = "ask"
	DecisionDeny  Decision = "deny"
)

// CapabilityLevel describes what a backend can honestly provide.
type CapabilityLevel string

const (
	CapabilityUnsupported CapabilityLevel = "unsupported"
	CapabilityMonitor     CapabilityLevel = "monitor"
	CapabilityEnforce     CapabilityLevel = "enforce"
)

// ResourceType identifies the kind of resource evaluated by a policy.
type ResourceType string

const (
	ResourcePath        ResourceType = "filesystem"
	ResourceNetwork     ResourceType = "network"
	ResourceShell       ResourceType = "shell"
	ResourceEnvironment ResourceType = "environment"
)

// RuleSet is used for network and other named resources.
type RuleSet struct {
	Default Decision
	Allow   []string
	Ask     []string
	Deny    []string
}

// PathRules adds a read-only class to a normal allow/ask/deny rule set.
type PathRules struct {
	Default  Decision
	Allow    []string
	ReadOnly []string
	Ask      []string
	Deny     []string
}

// ShellRules controls pre-flight command decisions. It is not a replacement
// for a process or filesystem sandbox.
type ShellRules struct {
	Default Decision
	Allow   []string
	Ask     []string
	Deny    []string
}

// EnvironmentRules controls which parent environment entries are copied to a
// child process.
type EnvironmentRules struct {
	Inherit []string
	Deny    []string
}

// AuditConfig controls local JSON Lines auditing.
type AuditConfig struct {
	Enabled bool
	Format  string
	Path    string
}

// ContainerConfig contains settings for the Docker-compatible backend.
type ContainerConfig struct {
	Runtime string
	Image   string
	Network string
}

// SandboxConfig selects a backend and its container settings.
type SandboxConfig struct {
	Backend   string
	Container ContainerConfig
}

// Policy is the complete versioned configuration model.
type Policy struct {
	Version     int
	Mode        string
	Filesystem  PathRules
	Network     RuleSet
	Shell       ShellRules
	Environment EnvironmentRules
	Audit       AuditConfig
	Sandbox     SandboxConfig
}

// Result is a structured explanation for one policy evaluation.
type Result struct {
	Decision     Decision     `json:"decision"`
	ResourceType ResourceType `json:"resource_type"`
	Resource     string       `json:"resource"`
	Rule         string       `json:"rule"`
	Reason       string       `json:"reason"`
	Source       string       `json:"source,omitempty"`
}

// Validate checks the schema and values that are security-relevant.
func (p Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("version: expected 1, got %d", p.Version)
	}
	if err := validateMode(p.Mode); err != nil {
		return err
	}
	if err := validateDecision("filesystem.default", p.Filesystem.Default); err != nil {
		return err
	}
	if err := validateDecision("network.default", p.Network.Default); err != nil {
		return err
	}
	if err := validateDecision("shell.default", p.Shell.Default); err != nil {
		return err
	}
	if p.Audit.Format != "jsonl" {
		return fmt.Errorf("audit.format: expected \"jsonl\", got %q", p.Audit.Format)
	}
	if p.Sandbox.Backend != "auto" && p.Sandbox.Backend != "local" && p.Sandbox.Backend != "container" {
		return fmt.Errorf("sandbox.backend: expected auto, local, or container, got %q", p.Sandbox.Backend)
	}
	if strings.TrimSpace(p.Sandbox.Container.Image) == "" {
		return fmt.Errorf("sandbox.container.image: must not be empty")
	}
	return nil
}

func validateMode(mode string) error {
	if mode != "auto" && mode != "monitor" && mode != "enforce" {
		return fmt.Errorf("mode: expected auto, monitor, or enforce, got %q", mode)
	}
	return nil
}

func validateDecision(field string, decision Decision) error {
	if decision != DecisionAllow && decision != DecisionAsk && decision != DecisionDeny {
		return fmt.Errorf("%s: expected one of allow, ask, deny; got %q", field, decision)
	}
	return nil
}
