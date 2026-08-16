package ui

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/SamVale29/agent-firewall/internal/risk"
	"github.com/SamVale29/agent-firewall/pkg/policy"
)

// Printer keeps human output separate from structured JSON output.
type Printer struct {
	Out   io.Writer
	Err   io.Writer
	Color bool
}

func New(out, err io.Writer, color bool) Printer { return Printer{Out: out, Err: err, Color: color} }

func (p Printer) Header(value string)       { fmt.Fprintln(p.Out, p.paint("1;36", value)) }
func (p Printer) Success(value string)      { fmt.Fprintf(p.Out, "%s %s\n", p.paint("32", "✓"), value) }
func (p Printer) Warning(value string)      { fmt.Fprintf(p.Out, "%s %s\n", p.paint("33", "!"), value) }
func (p Printer) Failure(value string)      { fmt.Fprintf(p.Out, "%s %s\n", p.paint("31", "×"), value) }
func (p Printer) Label(label, value string) { fmt.Fprintf(p.Out, "%-18s %s\n", label, value) }
func (p Printer) Section(value string)      { fmt.Fprintf(p.Out, "\n%s\n", p.paint("1", value)) }

func (p Printer) paint(code, value string) string {
	if !p.Color {
		return value
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func (p Printer) Capability(level policy.CapabilityLevel) string {
	switch level {
	case policy.CapabilityEnforce:
		return p.paint("32", "enforced")
	case policy.CapabilityMonitor:
		return p.paint("33", "monitor")
	default:
		return p.paint("2", "unsupported")
	}
}

func (p Printer) Risk(analysis risk.Analysis) string {
	return p.paint(riskColor(analysis.Level), strings.ToUpper(string(analysis.Level)))
}

func riskColor(level risk.Level) string {
	switch level {
	case risk.Critical:
		return "1;31"
	case risk.High:
		return "31"
	case risk.Medium:
		return "33"
	default:
		return "32"
	}
}

func (p Printer) Box(title string, lines []string) {
	width := len(title) + 6
	for _, line := range lines {
		if len(line)+4 > width {
			width = len(line) + 4
		}
	}
	border := "┌" + strings.Repeat("─", width-2) + "┐"
	fmt.Fprintln(p.Out, border)
	fmt.Fprintf(p.Out, "│ %-*s │\n", width-4, p.paint("1", title))
	fmt.Fprintf(p.Out, "│%s│\n", strings.Repeat(" ", width-2))
	for _, line := range lines {
		fmt.Fprintf(p.Out, "│ %-*s │\n", width-4, line)
	}
	fmt.Fprintf(p.Out, "└%s┘\n", strings.Repeat("─", width-2))
}

// AskApproval provides a safe, session-scoped choice. It never mutates policy
// files, so an accidental approval cannot become permanent.
func (p Printer) AskApproval(in io.Reader, result policy.Result, analysis risk.Analysis, requestedBy string) (bool, error) {
	p.Box("Agent Firewall", []string{
		strings.ToUpper(string(result.Decision)) + " REQUIRED",
		"",
		result.Resource,
		"Risk: " + strings.ToUpper(string(analysis.Level)),
		"Reason: " + result.Reason,
		"Requested by: " + requestedBy,
		"Policy: " + result.Rule,
	})
	fmt.Fprintln(p.Out, "\nAction: [a]llow once, [s]ession, [d]eny (default: deny)")
	reader := bufio.NewReader(in)
	answer, err := reader.ReadString('\n')
	if err != nil && len(answer) == 0 {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "a", "allow", "allow once":
		return true, nil
	case "s", "session", "allow session":
		return true, nil
	default:
		return false, nil
	}
}
