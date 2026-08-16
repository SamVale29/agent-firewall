package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SamVale29/agent-firewall/internal/defaults"
	publicpolicy "github.com/SamVale29/agent-firewall/pkg/policy"
)

func TestEvaluatePathDenyWinsOverAllow(t *testing.T) {
	root := t.TempDir()
	config := defaults.New()
	engine := New(config, root)
	result := engine.EvaluatePath("~/.ssh/id_ed25519")
	if result.Decision != publicpolicy.DecisionDeny {
		t.Fatalf("decision = %q, want deny", result.Decision)
	}
	if result := engine.EvaluatePath("~/.ssh"); result.Decision != publicpolicy.DecisionDeny {
		t.Fatalf("directory decision = %q, want deny", result.Decision)
	}
}

func TestEvaluatePathNormalizesTraversalAndSymlinks(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "safe-link")
	if err := os.Symlink(filepath.Join(home, ".ssh"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	config := defaults.New()
	config.Filesystem.Deny = append(config.Filesystem.Deny, filepath.Join(home, ".ssh", "**"))
	engine := New(config, root)
	result := engine.EvaluatePath(filepath.Join(root, "safe-link", "id_ed25519"))
	if result.Decision != publicpolicy.DecisionDeny {
		t.Fatalf("decision = %q, want deny", result.Decision)
	}
}

func TestFilterEnvironment(t *testing.T) {
	config := defaults.New()
	engine := New(config, t.TempDir())
	filtered, removed := engine.FilterEnvironment([]string{
		"PATH=/bin",
		"LANG=en_US.UTF-8",
		"GITHUB_TOKEN=secret",
		"PROJECT_NAME=agent-firewall",
	})
	if len(filtered) != 2 || len(removed) != 2 {
		t.Fatalf("filtered=%v removed=%v", filtered, removed)
	}
}

func TestEvaluateShellUsesCommandBoundaries(t *testing.T) {
	config := defaults.New()
	engine := New(config, t.TempDir())
	if result := engine.EvaluateShell("printf '%s' format"); result.Decision != publicpolicy.DecisionAllow {
		t.Fatalf("decision = %q, want allow", result.Decision)
	}
	if result := engine.EvaluateShell("rm -rf ./build"); result.Decision != publicpolicy.DecisionAsk {
		t.Fatalf("decision = %q, want ask", result.Decision)
	}
}
