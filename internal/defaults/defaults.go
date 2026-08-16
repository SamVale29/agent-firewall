// Package defaults provides the conservative built-in Agent Firewall policy.
package defaults

import "github.com/SamVale29/agent-firewall/pkg/policy"

// New returns conservative, readable defaults. The local backend is the
// fallback; it never claims to enforce filesystem or network boundaries.
func New() policy.Policy {
	return policy.Policy{
		Version: 1,
		Mode:    "auto",
		Filesystem: policy.PathRules{
			Default:  policy.DecisionAsk,
			Allow:    []string{"./**"},
			ReadOnly: []string{"../shared/**"},
			Deny: []string{
				"~/.ssh/**",
				"~/.gnupg/**",
				"~/.aws/**",
				"~/.config/gcloud/**",
				"~/.kube/**",
				"~/.git-credentials",
			},
		},
		Network: policy.RuleSet{
			Default: policy.DecisionAsk,
			Allow:   []string{"github.com", "api.github.com", "registry.npmjs.org"},
			Deny:    []string{"169.254.169.254"},
		},
		Shell: policy.ShellRules{
			Default: policy.DecisionAllow,
			Ask: []string{
				"rm", "git reset", "git clean", "docker", "podman", "kubectl",
				"chmod", "chown", "dd", "mkfs", "curl | sh", "wget | sh",
				"terraform destroy",
			},
			Deny: []string{"sudo", "shutdown", "reboot"},
		},
		Environment: policy.EnvironmentRules{
			Inherit: []string{"PATH", "HOME", "LANG", "TERM", "TZ", "USER", "SHELL"},
			Deny: []string{
				"*_SECRET", "*_TOKEN", "*_PASSWORD", "*_PRIVATE_KEY",
				"*_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
				"OPENAI_API_KEY", "ANTHROPIC_API_KEY",
			},
		},
		Audit: policy.AuditConfig{
			Enabled: true,
			Format:  "jsonl",
		},
		Sandbox: policy.SandboxConfig{
			Backend: "auto",
			Container: policy.ContainerConfig{
				Image:   "ubuntu:24.04",
				Network: "policy",
			},
		},
	}
}

// ExampleYAML renders the repository policy created by afw init.
func ExampleYAML() string {
	return `version: 1

mode: auto

filesystem:
  default: ask
  allow:
    - "./**"
  read_only:
    - "../shared/**"
  deny:
    - "~/.ssh/**"
    - "~/.gnupg/**"
    - "~/.aws/**"
    - "~/.config/gcloud/**"
    - "~/.kube/**"
    - "~/.git-credentials"

network:
  default: ask
  allow:
    - "github.com"
    - "api.github.com"
    - "registry.npmjs.org"
  deny:
    - "169.254.169.254"

shell:
  default: allow
  ask:
    - "rm"
    - "git reset"
    - "git clean"
    - "docker"
    - "podman"
    - "kubectl"
    - "chmod"
    - "chown"
    - "dd"
    - "mkfs"
    - "curl | sh"
    - "wget | sh"
    - "terraform destroy"
  deny:
    - "sudo"
    - "shutdown"
    - "reboot"

environment:
  inherit:
    - "PATH"
    - "HOME"
    - "LANG"
    - "TERM"
    - "TZ"
    - "USER"
    - "SHELL"
  deny:
    - "*_SECRET"
    - "*_TOKEN"
    - "*_PASSWORD"
    - "*_PRIVATE_KEY"
    - "*_API_KEY"
    - "AWS_SECRET_ACCESS_KEY"
    - "GITHUB_TOKEN"
    - "OPENAI_API_KEY"
    - "ANTHROPIC_API_KEY"

audit:
  enabled: true
  format: jsonl

sandbox:
  backend: auto
  container:
    image: "ubuntu:24.04"
    network: policy
`
}
