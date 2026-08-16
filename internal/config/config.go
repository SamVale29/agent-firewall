package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/SamVale29/agent-firewall/internal/defaults"
	"github.com/SamVale29/agent-firewall/pkg/policy"
)

// Loaded contains the effective policy and the sources used to build it.
type Loaded struct {
	Policy     policy.Policy
	RepoRoot   string
	PolicyPath string
	GlobalPath string
	Sources    []string
}

// FindRepoRoot walks upward from start and returns the closest directory with
// a .git entry. When no repository is found, the absolute start directory is
// returned so relative policies still have deterministic semantics.
func FindRepoRoot(start string) (string, error) {
	abs, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		abs = filepath.Dir(abs)
	}
	for {
		if _, err := os.Stat(filepath.Join(abs, ".git")); err == nil {
			return abs, nil
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return abs, nil
		}
		abs = parent
	}
}

// GlobalConfigPath returns the OS-appropriate global policy location.
func GlobalConfigPath() string {
	if value := os.Getenv("XDG_CONFIG_HOME"); value != "" {
		return filepath.Join(value, "agent-firewall", "config.yaml")
	}
	if value, err := os.UserConfigDir(); err == nil && value != "" {
		return filepath.Join(value, "agent-firewall", "config.yaml")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "agent-firewall", "config.yaml")
	}
	return filepath.Join(".", ".agent-firewall-global.yaml")
}

// AuditPath returns the default local-only JSONL state path.
func AuditPath(configured string) string {
	if configured != "" {
		return expandHome(configured)
	}
	if value, err := os.UserCacheDir(); err == nil && value != "" {
		return filepath.Join(value, "agent-firewall", "audit.jsonl")
	}
	return filepath.Join(".", ".agent-firewall", "audit.jsonl")
}

// Load applies built-in defaults, global configuration, and repository
// configuration in that order. Repository settings take precedence.
func Load(start string) (Loaded, error) {
	root, err := FindRepoRoot(start)
	if err != nil {
		return Loaded{}, err
	}
	effective := defaults.New()
	loaded := Loaded{
		Policy:     effective,
		RepoRoot:   root,
		PolicyPath: filepath.Join(root, ".agent-firewall.yaml"),
		GlobalPath: GlobalConfigPath(),
	}
	if err := applyOptionalFile(&loaded.Policy, loaded.GlobalPath, &loaded.Sources); err != nil {
		return Loaded{}, err
	}
	if err := applyOptionalFile(&loaded.Policy, loaded.PolicyPath, &loaded.Sources); err != nil {
		return Loaded{}, err
	}
	if err := loaded.Policy.Validate(); err != nil {
		return Loaded{}, fmt.Errorf("%s: %w", loaded.PolicyPath, err)
	}
	return loaded, nil
}

func applyOptionalFile(target *policy.Policy, path string, sources *[]string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	values, err := parseYAML(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := applyValues(target, values, ""); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	*sources = append(*sources, path)
	return nil
}

func applyValues(target *policy.Policy, values map[string]any, prefix string) error {
	for key, value := range values {
		field := key
		if prefix != "" {
			field = prefix + "." + key
		}
		switch key {
		case "version":
			integer, err := asInt(value, field)
			if err != nil {
				return err
			}
			target.Version = integer
		case "mode":
			text, err := asString(value, field)
			if err != nil {
				return err
			}
			target.Mode = text
		case "filesystem":
			mapping, err := asMap(value, field)
			if err != nil {
				return err
			}
			if err := applyPathRules(&target.Filesystem, mapping, field); err != nil {
				return err
			}
		case "network":
			mapping, err := asMap(value, field)
			if err != nil {
				return err
			}
			if err := applyRuleSet(&target.Network, mapping, field); err != nil {
				return err
			}
		case "shell":
			mapping, err := asMap(value, field)
			if err != nil {
				return err
			}
			if err := applyShellRules(&target.Shell, mapping, field); err != nil {
				return err
			}
		case "environment":
			mapping, err := asMap(value, field)
			if err != nil {
				return err
			}
			if err := applyEnvironment(&target.Environment, mapping, field); err != nil {
				return err
			}
		case "audit":
			mapping, err := asMap(value, field)
			if err != nil {
				return err
			}
			if err := applyAudit(&target.Audit, mapping, field); err != nil {
				return err
			}
		case "sandbox":
			mapping, err := asMap(value, field)
			if err != nil {
				return err
			}
			if err := applySandbox(&target.Sandbox, mapping, field); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: unknown configuration key", field)
		}
	}
	return nil
}

func applyPathRules(target *policy.PathRules, values map[string]any, field string) error {
	for key, value := range values {
		child := field + "." + key
		switch key {
		case "default":
			decision, err := asDecision(value, child)
			if err != nil {
				return err
			}
			target.Default = decision
		case "allow":
			items, err := asStrings(value, child)
			if err != nil {
				return err
			}
			target.Allow = items
		case "read_only":
			items, err := asStrings(value, child)
			if err != nil {
				return err
			}
			target.ReadOnly = items
		case "ask":
			items, err := asStrings(value, child)
			if err != nil {
				return err
			}
			target.Ask = items
		case "deny":
			items, err := asStrings(value, child)
			if err != nil {
				return err
			}
			target.Deny = items
		default:
			return fmt.Errorf("%s: unknown configuration key", child)
		}
	}
	return nil
}

func applyRuleSet(target *policy.RuleSet, values map[string]any, field string) error {
	for key, value := range values {
		child := field + "." + key
		switch key {
		case "default":
			decision, err := asDecision(value, child)
			if err != nil {
				return err
			}
			target.Default = decision
		case "allow", "ask", "deny":
			items, err := asStrings(value, child)
			if err != nil {
				return err
			}
			switch key {
			case "allow":
				target.Allow = items
			case "ask":
				target.Ask = items
			case "deny":
				target.Deny = items
			}
		default:
			return fmt.Errorf("%s: unknown configuration key", child)
		}
	}
	return nil
}

func applyShellRules(target *policy.ShellRules, values map[string]any, field string) error {
	set := policy.RuleSet{Default: target.Default, Allow: target.Allow, Ask: target.Ask, Deny: target.Deny}
	if err := applyRuleSet(&set, values, field); err != nil {
		return err
	}
	target.Default, target.Allow, target.Ask, target.Deny = set.Default, set.Allow, set.Ask, set.Deny
	return nil
}

func applyEnvironment(target *policy.EnvironmentRules, values map[string]any, field string) error {
	for key, value := range values {
		child := field + "." + key
		switch key {
		case "inherit":
			items, err := asStrings(value, child)
			if err != nil {
				return err
			}
			target.Inherit = items
		case "deny":
			items, err := asStrings(value, child)
			if err != nil {
				return err
			}
			target.Deny = items
		default:
			return fmt.Errorf("%s: unknown configuration key", child)
		}
	}
	return nil
}

func applyAudit(target *policy.AuditConfig, values map[string]any, field string) error {
	for key, value := range values {
		child := field + "." + key
		switch key {
		case "enabled":
			boolean, ok := value.(bool)
			if !ok {
				return fmt.Errorf("%s: expected boolean", child)
			}
			target.Enabled = boolean
		case "format":
			text, err := asString(value, child)
			if err != nil {
				return err
			}
			target.Format = text
		case "path":
			text, err := asString(value, child)
			if err != nil {
				return err
			}
			target.Path = text
		default:
			return fmt.Errorf("%s: unknown configuration key", child)
		}
	}
	return nil
}

func applySandbox(target *policy.SandboxConfig, values map[string]any, field string) error {
	for key, value := range values {
		child := field + "." + key
		switch key {
		case "backend":
			text, err := asString(value, child)
			if err != nil {
				return err
			}
			target.Backend = text
		case "container":
			mapping, err := asMap(value, child)
			if err != nil {
				return err
			}
			for containerKey, containerValue := range mapping {
				containerField := child + "." + containerKey
				text, err := asString(containerValue, containerField)
				if err != nil {
					return err
				}
				switch containerKey {
				case "runtime":
					target.Container.Runtime = text
				case "image":
					target.Container.Image = text
				case "network":
					target.Container.Network = text
				default:
					return fmt.Errorf("%s: unknown configuration key", containerField)
				}
			}
		default:
			return fmt.Errorf("%s: unknown configuration key", child)
		}
	}
	return nil
}

func asMap(value any, field string) (map[string]any, error) {
	mapping, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected a mapping", field)
	}
	return mapping, nil
}

func asString(value any, field string) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s: expected a string", field)
	}
	return text, nil
}

func asInt(value any, field string) (int, error) {
	integer, ok := value.(int)
	if !ok {
		return 0, fmt.Errorf("%s: expected an integer", field)
	}
	return integer, nil
}

func asDecision(value any, field string) (policy.Decision, error) {
	text, err := asString(value, field)
	if err != nil {
		return "", err
	}
	decision := policy.Decision(strings.ToLower(text))
	if decision != policy.DecisionAllow && decision != policy.DecisionAsk && decision != policy.DecisionDeny {
		return "", fmt.Errorf("%s: expected one of allow, ask, deny; got %q", field, text)
	}
	return decision, nil
}

func asStrings(value any, field string) ([]string, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected a list of strings", field)
	}
	result := make([]string, 0, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d]: expected a string", field, index)
		}
		result = append(result, text)
	}
	return result, nil
}

func expandHome(value string) string {
	if value == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, value[2:])
		}
	}
	return value
}

// ProjectSignals returns deterministic facts used by afw init and doctor.
func ProjectSignals(root string) []string {
	checks := []struct {
		name string
		file string
	}{
		{"Go", "go.mod"},
		{"Node.js", "package.json"},
		{"Python", "pyproject.toml"},
		{"Rust", "Cargo.toml"},
		{"Docker", "Dockerfile"},
	}
	var result []string
	for _, check := range checks {
		if _, err := os.Stat(filepath.Join(root, check.file)); err == nil {
			result = append(result, check.name)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		result = append(result, "Git repository")
	}
	if len(result) == 0 {
		result = []string{"Generic project"}
	}
	sort.Strings(result)
	return result
}

// PlatformLabel is kept in config so doctor/status use the same vocabulary.
func PlatformLabel() string { return runtime.GOOS + "/" + runtime.GOARCH }
