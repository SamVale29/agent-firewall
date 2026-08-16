package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SamVale29/agent-firewall/internal/defaults"
	"github.com/SamVale29/agent-firewall/pkg/policy"
)

func TestLoadAppliesGlobalThenRepositoryPrecedence(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	global := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", global)
	globalPath := filepath.Join(global, "agent-firewall", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(globalPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalPath, []byte("mode: monitor\nshell:\n  default: deny\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".agent-firewall.yaml"), []byte("mode: enforce\nshell:\n  default: allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Policy.Mode != "enforce" || loaded.Policy.Shell.Default != policy.DecisionAllow {
		t.Fatalf("unexpected precedence: mode=%q shell=%q", loaded.Policy.Mode, loaded.Policy.Shell.Default)
	}
	if len(loaded.Sources) != 2 {
		t.Fatalf("sources=%v", loaded.Sources)
	}
}

func TestExamplePolicyLoads(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".agent-firewall.yaml"), []byte(defaults.ExampleYAML()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "missing-global"))
	if _, err := Load(root); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidDecisionIncludesField(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".agent-firewall.yaml"), []byte("network:\n  default: warning\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "missing-global"))
	_, err := Load(root)
	if err == nil || !strings.Contains(err.Error(), "network.default") {
		t.Fatalf("error=%v", err)
	}
}
