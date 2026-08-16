// Package local implements the monitor-only host process backend.
package local

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/SamVale29/agent-firewall/internal/sandbox"
	"github.com/SamVale29/agent-firewall/pkg/policy"
)

// Backend launches on the host with explicit environment filtering. It is a
// monitor backend: it cannot intercept arbitrary filesystem or network syscalls.
type Backend struct{}

// New creates the host-process monitor backend.
func New() Backend { return Backend{} }

// Name returns the stable backend name.
func (Backend) Name() string { return "local" }

// Available reports that local process execution is always available.
func (Backend) Available(context.Context) error { return nil }

// Capabilities reports the monitor-only host boundary and filtered environment.
func (Backend) Capabilities(policy.Policy) sandbox.Capabilities {
	return sandbox.Capabilities{
		Filesystem:  policy.CapabilityMonitor,
		Network:     policy.CapabilityMonitor,
		Environment: policy.CapabilityEnforce,
		Process:     policy.CapabilityMonitor,
		Resources:   policy.CapabilityUnsupported,
	}
}

// Run starts the requested command directly on the host.
func (Backend) Run(ctx context.Context, request sandbox.Request) error {
	if len(request.Command) == 0 {
		return fmt.Errorf("no command supplied")
	}
	command := exec.CommandContext(ctx, request.Command[0], request.Command[1:]...)
	command.Dir = request.Dir
	command.Env = request.Env
	command.Stdin = request.Stdin
	command.Stdout = request.Stdout
	command.Stderr = request.Stderr
	if err := command.Run(); err != nil {
		return sandboxExit(err)
	}
	return nil
}

func sandboxExit(err error) error {
	return sandbox.WrapExitError(err)
}
