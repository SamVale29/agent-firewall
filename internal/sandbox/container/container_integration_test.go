//go:build integration

package container

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SamVale29/agent-firewall/internal/defaults"
	enginepolicy "github.com/SamVale29/agent-firewall/internal/policy"
	"github.com/SamVale29/agent-firewall/internal/sandbox"
	publicpolicy "github.com/SamVale29/agent-firewall/pkg/policy"
)

func TestContainerRuntimeSmoke(t *testing.T) {
	backend := smokeBackend(t)
	root := t.TempDir()
	repository := filepath.Join(root, "repository")
	if err := os.Mkdir(repository, 0o755); err != nil {
		t.Fatalf("create repository directory: %v", err)
	}
	outsideName := "agent-firewall-outside-sentinel"
	if err := os.WriteFile(filepath.Join(root, outsideName), []byte("must stay outside"), 0o600); err != nil {
		t.Fatalf("create outside sentinel: %v", err)
	}

	config := smokePolicy()
	filteredEnvironment, _ := enginepolicy.New(config, repository).FilterEnvironment([]string{
		"HOME=/host/home",
		"PATH=/host/path",
		"LANG=C",
		"PWD=" + repository,
		"AFW_SMOKE_SECRET=must-not-cross-boundary",
	})

	command := []string{"sh", "-ceu", fmt.Sprintf(`
test "$HOME" = "/home/agent"
test "$LANG" = "C"
test -z "${AFW_SMOKE_SECRET:-}"
test -w /tmp
printf 'smoke-ok' > /workspace/.agent-firewall-smoke-marker
test "$(cat /workspace/.agent-firewall-smoke-marker)" = "smoke-ok"
test ! -e /%s
if touch /var/tmp/.agent-firewall-readonly 2>/dev/null; then
  echo "container root filesystem is writable" >&2
  exit 10
fi
test "$(wc -l < /proc/net/route)" -eq 1
grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status
`, outsideName)}

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := backend.Run(ctx, sandbox.Request{
		Command: command,
		Dir:     repository,
		Env:     filteredEnvironment,
		Mode:    "enforce",
		Policy:  config,
		Stdout:  &stdout,
		Stderr:  &stderr,
	}); err != nil {
		t.Fatalf("container smoke command failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	marker, err := os.ReadFile(filepath.Join(repository, ".agent-firewall-smoke-marker"))
	if err != nil {
		t.Fatalf("read repository marker: %v", err)
	}
	if string(marker) != "smoke-ok" {
		t.Fatalf("repository marker = %q, want smoke-ok", marker)
	}
}

func TestContainerRuntimePreservesExitCode(t *testing.T) {
	backend := smokeBackend(t)
	config := smokePolicy()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	err := backend.Run(ctx, sandbox.Request{
		Command: []string{"sh", "-c", "exit 23"},
		Dir:     t.TempDir(),
		Mode:    "enforce",
		Policy:  config,
	})
	var exitErr *sandbox.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("container error = %v, want sandbox.ExitError", err)
	}
	if exitErr.Code != 23 {
		t.Fatalf("container exit code = %d, want 23", exitErr.Code)
	}
}

func smokeBackend(t *testing.T) Backend {
	t.Helper()
	runtimeName := os.Getenv("AFW_SMOKE_RUNTIME")
	if runtimeName == "" {
		runtimeName = "docker"
	}
	backend := New(runtimeName)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := backend.Available(ctx); err != nil {
		t.Fatalf("container runtime %q unavailable: %v", runtimeName, err)
	}
	return backend
}

func smokePolicy() publicpolicy.Policy {
	config := defaults.New()
	config.Mode = "enforce"
	config.Network.Default = publicpolicy.DecisionDeny
	config.Network.Allow = nil
	config.Network.Ask = nil
	config.Sandbox.Backend = "container"
	config.Sandbox.Container.Network = "policy"
	return config
}
