package container

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/SamVale29/agent-firewall/internal/sandbox"
	"github.com/SamVale29/agent-firewall/pkg/policy"
)

func TestContainerArgsApplyBoundaryContract(t *testing.T) {
	request := sandbox.Request{
		Command: []string{"codex", "--version"},
		Dir:     "/repo",
		Env:     []string{"HOME=/host/home", "LANG=C", "PWD=/repo"},
		Policy: policy.Policy{
			Network: policy.RuleSet{Default: policy.DecisionDeny},
			Sandbox: policy.SandboxConfig{Container: policy.ContainerConfig{Image: "ubuntu:24.04", Network: "policy"}},
		},
		TTY: true,
	}

	args := containerArgs(request, "1000:1000")
	joined := strings.Join(args, "\x00")

	for _, want := range []string{
		"run", "--rm", "--init", "-i", "-t", "--cap-drop=ALL",
		"--security-opt=no-new-privileges", "--read-only", "--pids-limit",
		"512", "--workdir", "/workspace", "--network", "none", "--user",
		"1000:1000", "ubuntu:24.04", "codex", "--version",
	} {
		if !containsArg(args, want) {
			t.Errorf("container args do not contain %q: %v", want, args)
		}
	}

	wantMount := "--mount\x00type=bind,src=" + filepath.Clean(request.Dir) + ",dst=/workspace"
	if !strings.Contains(joined, wantMount) {
		t.Errorf("container args do not contain repository mount %q: %v", wantMount, args)
	}
	for _, wantEnv := range []string{"HOME=/home/agent", "LANG=C"} {
		if !containsArg(args, wantEnv) {
			t.Errorf("container args do not contain filtered environment %q: %v", wantEnv, args)
		}
	}
	if containsArg(args, "HOME=/host/home") || containsArg(args, "PWD=/repo") {
		t.Fatalf("container args leaked host-sensitive environment: %v", args)
	}
}

func TestContainerArgsRespectNetworkMode(t *testing.T) {
	tests := []struct {
		name       string
		container  string
		defaultNet policy.Decision
		allow      []string
		wantNone   bool
	}{
		{name: "policy deny all", container: "policy", defaultNet: policy.DecisionDeny, wantNone: true},
		{name: "explicit none", container: "none", defaultNet: policy.DecisionAsk, wantNone: true},
		{name: "runtime default", container: "default", defaultNet: policy.DecisionDeny},
		{name: "domain exception", container: "policy", defaultNet: policy.DecisionDeny, allow: []string{"example.com"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := sandbox.Request{
				Command: []string{"agent"},
				Dir:     "/repo",
				Policy: policy.Policy{
					Network: policy.RuleSet{Default: test.defaultNet, Allow: test.allow},
					Sandbox: policy.SandboxConfig{Container: policy.ContainerConfig{Image: "image", Network: test.container}},
				},
			}
			args := containerArgs(request, "")
			gotNone := containsArg(args, "--network") && containsArg(args, "none")
			if gotNone != test.wantNone {
				t.Fatalf("network none = %v, want %v; args = %v", gotNone, test.wantNone, args)
			}
		})
	}
}

func TestContainerEnvironmentAddsStableHome(t *testing.T) {
	got := containerEnvironment([]string{
		"HOME=/host/home",
		"PATH=/host/bin",
		"PWD=/repo",
		"OLDPWD=/old",
		"LANG=C",
		"BROKEN",
	})

	if !containsArg(got, "HOME=/home/agent") {
		t.Fatalf("HOME was not normalized: %v", got)
	}
	if !containsArg(got, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") {
		t.Fatalf("PATH was not normalized: %v", got)
	}
	if !containsArg(got, "LANG=C") {
		t.Fatalf("LANG was not preserved: %v", got)
	}
	for _, forbidden := range []string{"HOME=/host/home", "PATH=/host/bin", "PWD=/repo", "OLDPWD=/old", "BROKEN"} {
		if containsArg(got, forbidden) {
			t.Errorf("environment contains forbidden entry %q: %v", forbidden, got)
		}
	}
}

func TestNetworkPolicyCanBeEnforced(t *testing.T) {
	tests := []struct {
		name      string
		container string
		policy    policy.RuleSet
		want      bool
	}{
		{name: "default policy mode", container: "", policy: policy.RuleSet{Default: policy.DecisionDeny}, want: true},
		{name: "explicit policy mode", container: "policy", policy: policy.RuleSet{Default: policy.DecisionDeny}, want: true},
		{name: "explicit none mode with non-deny policy", container: "none", policy: policy.RuleSet{Default: policy.DecisionAsk}, want: false},
		{name: "runtime default mode", container: "default", policy: policy.RuleSet{Default: policy.DecisionDeny}, want: false},
		{name: "allow exception", container: "policy", policy: policy.RuleSet{Default: policy.DecisionDeny, Allow: []string{"example.com"}}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := policy.Policy{Network: test.policy, Sandbox: policy.SandboxConfig{Container: policy.ContainerConfig{Network: test.container}}}
			if got := networkPolicyCanBeEnforced(value); got != test.want {
				t.Fatalf("networkPolicyCanBeEnforced() = %v, want %v", got, test.want)
			}
		})
	}
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}
