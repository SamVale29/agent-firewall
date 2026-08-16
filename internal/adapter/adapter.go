package adapter

import "strings"

// Adapter is an optional seam for agent-specific preparation. The generic run
// path never depends on an adapter or vendor API.
type Adapter interface {
	Name() string
	Detect(command string) bool
	Prepare(command []string) ([]string, error)
}

type generic struct{}

func (generic) Name() string                               { return "generic" }
func (generic) Detect(string) bool                         { return true }
func (generic) Prepare(command []string) ([]string, error) { return command, nil }

// Detect returns a display label without coupling policy to a vendor.
func Detect(command string) string {
	name := strings.TrimSpace(command)
	if index := strings.LastIndexAny(name, "/\\"); index >= 0 {
		name = name[index+1:]
	}
	switch strings.ToLower(name) {
	case "codex":
		return "codex"
	case "claude":
		return "claude"
	default:
		return "generic"
	}
}

func Generic() Adapter { return generic{} }
