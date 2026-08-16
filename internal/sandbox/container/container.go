// Package container implements the Docker/Podman process boundary.
package container

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/SamVale29/agent-firewall/internal/sandbox"
	"github.com/SamVale29/agent-firewall/pkg/policy"
)

// Backend uses Docker or Podman as an actual process/container boundary. The
// repository is the only host path mounted by default.
type Backend struct {
	runtime string
}

// New creates a container backend using the configured runtime when provided.
func New(configuredRuntime string) Backend {
	return Backend{runtime: configuredRuntime}
}

// Name returns the stable backend name.
func (b Backend) Name() string { return "container" }

// Runtime returns the configured runtime or the first available Docker-compatible runtime.
func (b Backend) Runtime() string {
	if b.runtime != "" {
		return b.runtime
	}
	if _, err := exec.LookPath("docker"); err == nil {
		return "docker"
	}
	if _, err := exec.LookPath("podman"); err == nil {
		return "podman"
	}
	return ""
}

// Available verifies that the selected runtime can answer an info request.
func (b Backend) Available(ctx context.Context) error {
	runtimeName := b.Runtime()
	if runtimeName == "" {
		return fmt.Errorf("no Docker-compatible runtime found")
	}
	command := exec.CommandContext(ctx, runtimeName, "info")
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s is installed but unavailable: %w", runtimeName, err)
	}
	return nil
}

// Capabilities reports the controls implemented by the container invocation.
func (b Backend) Capabilities(config policy.Policy) sandbox.Capabilities {
	network := policy.CapabilityMonitor
	if networkPolicyCanBeEnforced(config) {
		network = policy.CapabilityEnforce
	}
	return sandbox.Capabilities{
		Filesystem:  policy.CapabilityEnforce,
		Network:     network,
		Environment: policy.CapabilityEnforce,
		Process:     policy.CapabilityEnforce,
		Resources:   policy.CapabilityMonitor,
	}
}

// Run starts the requested command inside the configured container boundary.
func (b Backend) Run(ctx context.Context, request sandbox.Request) error {
	if len(request.Command) == 0 {
		return fmt.Errorf("no command supplied")
	}
	if request.Dir == "" {
		return fmt.Errorf("container backend requires a repository directory")
	}
	capabilities := b.Capabilities(request.Policy)
	if request.Mode == "enforce" {
		if capabilities.Filesystem != policy.CapabilityEnforce || capabilities.Environment != policy.CapabilityEnforce || capabilities.Network != policy.CapabilityEnforce {
			return fmt.Errorf("container backend cannot enforce the complete requested policy: filesystem=%s network=%s environment=%s", capabilities.Filesystem, capabilities.Network, capabilities.Environment)
		}
	}
	runtimeName := b.Runtime()
	if runtimeName == "" {
		return fmt.Errorf("no Docker-compatible runtime found")
	}
	image := request.Policy.Sandbox.Container.Image
	if image == "" {
		return fmt.Errorf("sandbox.container.image is empty")
	}
	args := containerArgs(request, containerUser())

	command := exec.CommandContext(ctx, runtimeName, args...)
	command.Dir = request.Dir
	command.Stdin = request.Stdin
	command.Stdout = request.Stdout
	command.Stderr = request.Stderr
	if err := command.Run(); err != nil {
		return sandbox.WrapExitError(err)
	}
	return nil
}

func containerArgs(request sandbox.Request, user string) []string {
	args := []string{
		"run", "--rm", "--init", "-i",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
		"--pids-limit", "512",
		"--workdir", "/workspace",
		"--mount", "type=bind,src=" + filepath.Clean(request.Dir) + ",dst=/workspace",
	}
	if request.TTY {
		args = append(args, "-t")
	}
	if networkDisabled(request.Policy) {
		args = append(args, "--network", "none")
	}
	if user != "" {
		args = append(args, "--user", user)
	}
	for _, entry := range containerEnvironment(request.Env) {
		args = append(args, "--env", entry)
	}
	args = append(args, request.Policy.Sandbox.Container.Image)
	args = append(args, request.Command...)
	return args
}

func networkPolicyCanBeEnforced(config policy.Policy) bool {
	if config.Network.Default != policy.DecisionDeny || len(config.Network.Allow) != 0 || len(config.Network.Ask) != 0 {
		return false
	}
	networkMode := strings.ToLower(config.Sandbox.Container.Network)
	return networkMode == "" || networkMode == "policy" || networkMode == "none"
}

func networkDisabled(config policy.Policy) bool {
	networkMode := strings.ToLower(config.Sandbox.Container.Network)
	return networkMode == "none" || networkPolicyCanBeEnforced(config)
}

func containerEnvironment(environment []string) []string {
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			continue
		}
		switch key {
		case "HOME":
			value = "/home/agent"
		case "PATH":
			value = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		case "PWD", "OLDPWD":
			continue
		}
		result = append(result, key+"="+value)
	}
	// A container needs a stable HOME even when the host policy did not inherit it.
	if !containsKey(result, "HOME") {
		result = append(result, "HOME=/home/agent")
	}
	return result
}

func containsKey(entries []string, key string) bool {
	for _, entry := range entries {
		if strings.HasPrefix(entry, key+"=") {
			return true
		}
	}
	return false
}
