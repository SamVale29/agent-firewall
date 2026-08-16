package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"

	"github.com/SamVale29/agent-firewall/pkg/policy"
)

// Capabilities describes independently enforceable controls.
type Capabilities struct {
	Filesystem  policy.CapabilityLevel `json:"filesystem"`
	Network     policy.CapabilityLevel `json:"network"`
	Environment policy.CapabilityLevel `json:"environment"`
	Process     policy.CapabilityLevel `json:"process"`
	Resources   policy.CapabilityLevel `json:"resources"`
}

// Request is the boundary between the CLI and a backend.
type Request struct {
	Command []string
	Dir     string
	Env     []string
	Mode    string
	Policy  policy.Policy
	TTY     bool
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// Backend is deliberately small so native Linux, macOS, and Windows backends
// can be added without changing policy evaluation.
type Backend interface {
	Name() string
	Available(context.Context) error
	Capabilities(policy.Policy) Capabilities
	Run(context.Context, Request) error
}

// Selection records the backend chosen for one invocation.
type Selection struct {
	Backend      Backend
	Mode         string
	Capabilities Capabilities
	Note         string
}

// ExitError preserves a child's exit status for the stable CLI exit contract.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// Code returns a child status or a generic failure status.
func Code(err error) int {
	if err == nil {
		return 0
	}
	var exitError *ExitError
	if errors.As(err, &exitError) {
		return exitError.Code
	}
	return 1
}

// WrapExitError converts an exec status into the stable backend error type.
func WrapExitError(err error) error {
	var processError *exec.ExitError
	if errors.As(err, &processError) {
		return &ExitError{Code: processError.ExitCode(), Err: err}
	}
	return fmt.Errorf("run child process: %w", err)
}
