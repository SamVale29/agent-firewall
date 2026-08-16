// Package detect selects a backend without silently downgrading enforce mode.
package detect

import (
	"context"
	"fmt"

	"github.com/SamVale29/agent-firewall/internal/sandbox"
	"github.com/SamVale29/agent-firewall/internal/sandbox/container"
	"github.com/SamVale29/agent-firewall/internal/sandbox/local"
	"github.com/SamVale29/agent-firewall/pkg/policy"
)

// Detect chooses an explicit backend without silently downgrading enforce mode.
func Detect(ctx context.Context, config policy.Policy) (sandbox.Selection, error) {
	localBackend := local.New()
	containerBackend := container.New(config.Sandbox.Container.Runtime)
	switch config.Sandbox.Backend {
	case "local":
		return sandbox.Selection{Backend: localBackend, Mode: "monitor", Capabilities: localBackend.Capabilities(config), Note: "Local execution is best effort; host filesystem and network remain visible."}, nil
	case "container":
		if err := containerBackend.Available(ctx); err != nil {
			return sandbox.Selection{}, fmt.Errorf("container backend requested but unavailable: %w", err)
		}
		capabilities := containerBackend.Capabilities(config)
		if capabilities.Network != policy.CapabilityEnforce {
			return sandbox.Selection{Backend: containerBackend, Mode: "monitor", Capabilities: capabilities, Note: "Container isolation is active, but this policy requests network behavior the backend cannot enforce granularly."}, nil
		}
		return sandbox.Selection{Backend: containerBackend, Mode: "enforce", Capabilities: capabilities}, nil
	case "auto", "":
		if err := containerBackend.Available(ctx); err == nil {
			capabilities := containerBackend.Capabilities(config)
			mode := "enforce"
			note := "Filesystem and process isolation are enforced by the container; network is reported independently."
			if capabilities.Network != policy.CapabilityEnforce {
				mode = "monitor"
				note = "Container isolation is active, but this policy requests network behavior the backend cannot enforce granularly."
			}
			return sandbox.Selection{Backend: containerBackend, Mode: mode, Capabilities: capabilities, Note: note}, nil
		}
		return sandbox.Selection{Backend: localBackend, Mode: "monitor", Capabilities: localBackend.Capabilities(config), Note: "No enforce-capable container runtime is available; local execution is monitor-only."}, nil
	default:
		return sandbox.Selection{}, fmt.Errorf("unknown sandbox backend %q", config.Sandbox.Backend)
	}
}
