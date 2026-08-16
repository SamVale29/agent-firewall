// Package cli implements the afw command tree and stable exit-code contract.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/SamVale29/agent-firewall/internal/adapter"
	"github.com/SamVale29/agent-firewall/internal/audit"
	"github.com/SamVale29/agent-firewall/internal/config"
	"github.com/SamVale29/agent-firewall/internal/defaults"
	"github.com/SamVale29/agent-firewall/internal/policy"
	"github.com/SamVale29/agent-firewall/internal/redact"
	"github.com/SamVale29/agent-firewall/internal/risk"
	"github.com/SamVale29/agent-firewall/internal/sandbox"
	"github.com/SamVale29/agent-firewall/internal/sandbox/container"
	sandboxdetect "github.com/SamVale29/agent-firewall/internal/sandbox/detect"
	"github.com/SamVale29/agent-firewall/internal/sandbox/local"
	"github.com/SamVale29/agent-firewall/internal/session"
	"github.com/SamVale29/agent-firewall/internal/ui"
	publicpolicy "github.com/SamVale29/agent-firewall/pkg/policy"
)

const (
	// ExitSuccess indicates successful command completion.
	ExitSuccess = 0
	// ExitFailure indicates an unspecified CLI failure.
	ExitFailure = 1
	// ExitInvalidConfig indicates invalid or unreadable policy configuration.
	ExitInvalidConfig = 2
	// ExitPolicyDenied indicates that policy prevented the requested action.
	ExitPolicyDenied = 3
	// ExitUnavailable indicates that the requested backend is unavailable.
	ExitUnavailable = 4
	// ExitSandbox indicates a backend execution failure.
	ExitSandbox = 5
)

// Build metadata is supplied by release automation through -ldflags.
var (
	Version = "0.1.0"
	Commit  = "development"
	Built   = "unknown"
)

type app struct {
	in      io.Reader
	out     io.Writer
	err     io.Writer
	color   bool
	json    bool
	verbose bool
	debug   bool
	printer ui.Printer
	workdir string
}

// Execute runs the CLI and returns a stable process exit code.
func Execute(args []string, in io.Reader, out, errOut io.Writer) int {
	workingDirectory, err := os.Getwd()
	if err != nil {
		workingDirectory = "."
	}
	application := &app{in: in, out: out, err: errOut, color: colorEnabled(in, out), workdir: workingDirectory}
	application.parseGlobal(args)
	application.printer = ui.New(out, errOut, application.color)
	args = application.stripGlobal(args)
	if len(args) == 0 {
		application.help()
		return ExitSuccess
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		application.help()
		return ExitSuccess
	}
	if args[0] == "version" || args[0] == "--version" {
		application.version()
		return ExitSuccess
	}
	switch args[0] {
	case "run":
		return application.run(args[1:])
	case "init":
		return application.init(args[1:])
	case "validate":
		return application.validate(args[1:])
	case "status":
		return application.status(args[1:])
	case "doctor":
		return application.doctor(args[1:])
	case "explain":
		return application.explain(args[1:])
	case "logs":
		return application.logs(args[1:])
	case "config":
		return application.configCommand(args[1:])
	case "completion":
		return application.completion(args[1:])
	case "codex", "claude":
		return application.run(append([]string{"--", args[0]}, args[1:]...))
	default:
		_, _ = fmt.Fprintf(application.err, "afw: unknown command %q\n\n", args[0])
		application.help()
		return ExitFailure
	}
}

func (a *app) parseGlobal(args []string) {
	for _, arg := range args {
		if isTopLevelCommand(arg) || arg == "--" {
			break
		}
		switch arg {
		case "--no-color":
			a.color = false
		case "--color":
			a.color = true
		case "--json":
			a.json = true
		case "--verbose":
			a.verbose = true
		case "--debug":
			a.debug = true
		}
	}
}

func (a *app) stripGlobal(args []string) []string {
	result := make([]string, 0, len(args))
	commandSeen := false
	for _, arg := range args {
		if !commandSeen && isTopLevelCommand(arg) {
			commandSeen = true
			result = append(result, arg)
			continue
		}
		if commandSeen {
			result = append(result, arg)
			continue
		}
		switch arg {
		case "--no-color", "--color", "--json", "--verbose", "--debug":
			continue
		default:
			commandSeen = true
			result = append(result, arg)
		}
	}
	return result
}

func isTopLevelCommand(value string) bool {
	switch value {
	case "run", "init", "validate", "status", "doctor", "explain", "logs", "config", "completion", "version", "help", "codex", "claude":
		return true
	default:
		return false
	}
}

func (a *app) help() {
	_, _ = fmt.Fprint(a.out, `Agent Firewall

A security layer between AI coding agents and your machine.

Usage:
  afw run [flags] -- <command> [args...]
  afw init | validate | status | doctor | explain | logs
  afw config show | path
  afw version | completion <bash|zsh|fish|powershell>

Run flags:
  --mode auto|monitor|enforce
  --dry-run
  --non-interactive
  --ask-policy deny|allow
  --json
  --no-color

Exit codes:
  0 success  1 failure  2 invalid configuration
  3 policy denied  4 sandbox unavailable  5 sandbox failure

Security model:
  The container backend can enforce a repository mount and optional network
  isolation. The local backend is monitor-only for filesystem and network.
`)
}

func (a *app) version() {
	if a.json {
		a.writeJSON(map[string]string{
			"name":     "Agent Firewall",
			"version":  Version,
			"commit":   Commit,
			"built":    Built,
			"go":       runtime.Version(),
			"platform": runtime.GOOS + "/" + runtime.GOARCH,
		})
		return
	}
	_, _ = fmt.Fprintf(a.out, "Agent Firewall %s\ncommit: %s\nbuilt: %s\ngo: %s\nplatform: %s\n", Version, Commit, Built, runtime.Version(), runtime.GOOS+"/"+runtime.GOARCH)
}

func (a *app) run(args []string) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(a.err)
	mode := flags.String("mode", "", "operating mode: auto, monitor, or enforce")
	nonInteractive := flags.Bool("non-interactive", false, "deny ASK decisions unless --ask-policy allow is set")
	askPolicy := flags.String("ask-policy", "deny", "non-interactive ASK behavior: deny or allow")
	dryRun := flags.Bool("dry-run", false, "show the plan without launching the command")
	noColor := flags.Bool("no-color", false, "disable ANSI colors")
	jsonOutput := flags.Bool("json", false, "emit machine-readable output where supported")
	if err := flags.Parse(args); err != nil {
		return ExitFailure
	}
	if *noColor {
		a.color = false
		a.printer = ui.New(a.out, a.err, false)
	}
	if *jsonOutput {
		a.json = true
	}
	command := flags.Args()
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if len(command) == 0 {
		_, _ = fmt.Fprintln(a.err, "afw run: expected a command after --")
		return ExitFailure
	}
	loaded, err := config.Load(a.workdir)
	if err != nil {
		a.errorf("cannot load policy: %v", err)
		return ExitInvalidConfig
	}
	effectiveMode := loaded.Policy.Mode
	if *mode != "" {
		effectiveMode = *mode
	}
	if effectiveMode != "auto" && effectiveMode != "monitor" && effectiveMode != "enforce" {
		a.errorf("mode: expected auto, monitor, or enforce; got %q", effectiveMode)
		return ExitInvalidConfig
	}
	if *askPolicy != "deny" && *askPolicy != "allow" {
		a.errorf("ask-policy: expected deny or allow; got %q", *askPolicy)
		return ExitInvalidConfig
	}
	policyValue, selection, err := selectForMode(context.Background(), loaded.Policy, effectiveMode)
	if err != nil {
		a.errorf("cannot select backend: %v", err)
		return ExitUnavailable
	}
	engine := policy.New(policyValue, loaded.RepoRoot)
	filteredEnv, removedEnv := engine.FilterEnvironment(os.Environ())
	commandText := displayCommand(command)
	riskAnalysis := risk.Analyze(commandText)
	policyResult := engine.EvaluateShell(commandText)
	record, err := session.New(command, selection.Backend.Name(), selection.Mode, policyValue)
	if err != nil {
		a.errorf("cannot create session: %v", err)
		return ExitFailure
	}
	writer := audit.New(config.AuditPath(loaded.Policy.Audit.Path), loaded.Policy.Audit.Enabled)
	startEvent := audit.Event{
		SessionID: record.ID,
		Event:     "session_start",
		Details: map[string]any{
			"command":             redact.Text(commandText),
			"agent":               adapter.Detect(command[0]),
			"backend":             selection.Backend.Name(),
			"mode":                selection.Mode,
			"policy_hash":         record.PolicyHash,
			"started_at":          record.StartedAt,
			"capabilities":        selection.Capabilities,
			"environment_removed": removedEnv,
		},
	}
	if err := writer.Write(startEvent); err != nil {
		a.errorf("cannot write audit start event: %v", err)
		return ExitFailure
	}
	if policyResult.Decision == publicpolicy.DecisionDeny {
		a.printDecision(policyResult, riskAnalysis, "blocked")
		if err := writer.Write(audit.Event{SessionID: record.ID, Event: "policy_decision", ResourceType: string(policyResult.ResourceType), Resource: policyResult.Resource, Decision: string(policyResult.Decision), Risk: string(riskAnalysis.Level), Rule: policyResult.Rule, Reason: policyResult.Reason, Details: map[string]any{"outcome": "deny"}}); err != nil {
			a.errorf("cannot write audit decision: %v", err)
		}
		record.Finish(ExitPolicyDenied)
		_ = writer.Write(sessionEndEvent(record, ExitPolicyDenied, nil))
		return ExitPolicyDenied
	}
	if policyResult.Decision == publicpolicy.DecisionAllow {
		if err := writer.Write(audit.Event{SessionID: record.ID, Event: "policy_decision", ResourceType: string(policyResult.ResourceType), Resource: policyResult.Resource, Decision: string(policyResult.Decision), Risk: string(riskAnalysis.Level), Rule: policyResult.Rule, Reason: policyResult.Reason, Details: map[string]any{"outcome": "allow"}}); err != nil {
			a.errorf("cannot write audit decision: %v", err)
			return ExitFailure
		}
	}
	if policyResult.Decision == publicpolicy.DecisionAsk {
		allowed := false
		if *nonInteractive || !isTerminal(a.in) {
			allowed = *askPolicy == "allow"
		} else {
			allowed, err = a.printer.AskApproval(a.in, policyResult, riskAnalysis, adapter.Detect(command[0]))
			if err != nil {
				a.errorf("approval input failed: %v", err)
				_ = writer.Write(audit.Event{SessionID: record.ID, Event: "policy_decision", ResourceType: string(policyResult.ResourceType), Resource: policyResult.Resource, Decision: string(policyResult.Decision), Risk: string(riskAnalysis.Level), Rule: policyResult.Rule, Reason: policyResult.Reason, Details: map[string]any{"approval_error": true}})
				record.Finish(ExitPolicyDenied)
				_ = writer.Write(sessionEndEvent(record, ExitPolicyDenied, nil))
				return ExitPolicyDenied
			}
		}
		if !allowed {
			a.printDecision(policyResult, riskAnalysis, "denied")
			_ = writer.Write(audit.Event{SessionID: record.ID, Event: "policy_decision", ResourceType: string(policyResult.ResourceType), Resource: policyResult.Resource, Decision: string(policyResult.Decision), Risk: string(riskAnalysis.Level), Rule: policyResult.Rule, Reason: policyResult.Reason, Details: map[string]any{"ask_policy": *askPolicy, "outcome": "deny"}})
			record.Finish(ExitPolicyDenied)
			_ = writer.Write(sessionEndEvent(record, ExitPolicyDenied, nil))
			return ExitPolicyDenied
		}
		_ = writer.Write(audit.Event{SessionID: record.ID, Event: "policy_decision", ResourceType: string(policyResult.ResourceType), Resource: policyResult.Resource, Decision: string(policyResult.Decision), Risk: string(riskAnalysis.Level), Rule: policyResult.Rule, Reason: policyResult.Reason, Details: map[string]any{"approved": true, "outcome": "allow"}})
	}
	if *dryRun {
		a.printDryRun(record, selection, command, loaded, removedEnv)
		record.Finish(ExitSuccess)
		_ = writer.Write(sessionEndEvent(record, ExitSuccess, map[string]any{"dry_run": true}))
		return ExitSuccess
	}
	a.printLaunch(record, selection, command, loaded)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	request := sandbox.Request{
		Command: command,
		Dir:     loaded.RepoRoot,
		Env:     filteredEnv,
		Mode:    selection.Mode,
		Policy:  policyValue,
		TTY:     isTerminal(a.in) && isTerminal(a.out),
		Stdin:   a.in,
		Stdout:  a.out,
		Stderr:  a.err,
	}
	runErr := selection.Backend.Run(ctx, request)
	exitCode := sandbox.Code(runErr)
	if runErr != nil {
		var childExit *sandbox.ExitError
		if errors.As(runErr, &childExit) {
			exitCode = childExit.Code
		} else {
			a.errorf("sandbox failure: %v", runErr)
			exitCode = ExitSandbox
		}
	}
	record.Finish(exitCode)
	_ = writer.Write(sessionEndEvent(record, exitCode, nil))
	return exitCode
}

func sessionEndEvent(record session.Record, exitCode int, details map[string]any) audit.Event {
	if details == nil {
		details = map[string]any{}
	}
	details["exit_status"] = exitCode
	details["ended_at"] = record.EndedAt
	details["policy_hash"] = record.PolicyHash
	return audit.Event{SessionID: record.ID, Event: "session_end", Details: details}
}

func selectForMode(ctx context.Context, value publicpolicy.Policy, mode string) (publicpolicy.Policy, sandbox.Selection, error) {
	switch mode {
	case "monitor":
		value.Sandbox.Backend = "local"
	case "enforce":
		if value.Sandbox.Backend == "local" {
			return value, sandbox.Selection{}, fmt.Errorf("cannot start enforce mode with sandbox.backend=local; configure a Docker-compatible runtime")
		}
		value.Sandbox.Backend = "container"
	}
	selection, err := sandboxdetect.Detect(ctx, value)
	if err != nil {
		return value, sandbox.Selection{}, err
	}
	if mode == "enforce" {
		selection.Mode = "enforce"
		if selection.Capabilities.Filesystem != publicpolicy.CapabilityEnforce || selection.Capabilities.Network != publicpolicy.CapabilityEnforce || selection.Capabilities.Environment != publicpolicy.CapabilityEnforce {
			return value, sandbox.Selection{}, fmt.Errorf("cannot start enforce mode: backend capabilities are filesystem=%s network=%s environment=%s", selection.Capabilities.Filesystem, selection.Capabilities.Network, selection.Capabilities.Environment)
		}
	}
	return value, selection, nil
}

func (a *app) printLaunch(record session.Record, selection sandbox.Selection, command []string, loaded config.Loaded) {
	if a.json {
		a.writeJSON(map[string]any{"session_id": record.ID, "backend": selection.Backend.Name(), "mode": selection.Mode, "command": command, "policy": loaded.PolicyPath})
		return
	}
	a.printer.Header("Agent Firewall")
	a.printer.Label("Session", record.ShortID())
	a.printer.Label("Backend", selection.Backend.Name())
	a.printer.Label("Mode", selection.Mode)
	a.printer.Success("repository access evaluated")
	a.printer.Success("environment filtering enabled")
	if selection.Capabilities.Filesystem == publicpolicy.CapabilityEnforce {
		a.printer.Success("filesystem boundary enforced")
	} else {
		a.printer.Warning("filesystem boundary is monitor-only")
	}
	if selection.Capabilities.Network == publicpolicy.CapabilityEnforce {
		a.printer.Success("network boundary enforced")
	} else {
		a.printer.Warning("network boundary is monitor-only")
	}
	_, _ = fmt.Fprintf(a.out, "\nLaunching: %s\n\n", displayCommand(command))
}

func (a *app) printDryRun(record session.Record, selection sandbox.Selection, command []string, loaded config.Loaded, removed []string) {
	if a.json {
		a.writeJSON(map[string]any{"session_id": record.ID, "command": command, "backend": selection.Backend.Name(), "mode": selection.Mode, "capabilities": selection.Capabilities, "policy": loaded.Policy, "environment_removed": removed})
		return
	}
	a.printer.Header("Agent Firewall Dry Run")
	a.printer.Label("Session", record.ShortID())
	a.printer.Label("Command", displayCommand(command))
	a.printer.Label("Backend", selection.Backend.Name())
	a.printer.Label("Mode", selection.Mode)
	a.printer.Section("Capabilities")
	a.printer.Label("Filesystem", a.printer.Capability(selection.Capabilities.Filesystem))
	a.printer.Label("Network", a.printer.Capability(selection.Capabilities.Network))
	a.printer.Label("Environment", a.printer.Capability(selection.Capabilities.Environment))
	a.printer.Label("Process", a.printer.Capability(selection.Capabilities.Process))
	a.printer.Section("Policy")
	a.printer.Label("Repository", loaded.RepoRoot)
	a.printer.Label("Configuration", loaded.PolicyPath)
	a.printer.Label("Audit log", auditPath(loaded))
	if len(removed) == 0 {
		a.printer.Success("No inherited environment variables removed")
	} else {
		a.printer.Warning(fmt.Sprintf("Environment removed: %s", strings.Join(removed, ", ")))
	}
	if selection.Note != "" {
		a.printer.Warning(selection.Note)
	}
}

func (a *app) printDecision(result publicpolicy.Result, analysis risk.Analysis, status string) {
	if a.json {
		a.writeJSON(map[string]any{"decision": result, "risk": analysis, "status": status})
		return
	}
	a.printer.Box("Agent Firewall", []string{
		strings.ToUpper(status),
		result.Resource,
		"Risk: " + strings.ToUpper(string(analysis.Level)),
		"Reason: " + result.Reason,
		"Policy: " + result.Rule,
	})
	if status == "denied" || status == "blocked" {
		_, _ = fmt.Fprintln(a.out, "Inspect the effective rule with: afw explain")
	}
}

func auditPath(loaded config.Loaded) string { return config.AuditPath(loaded.Policy.Audit.Path) }

func (a *app) init(args []string) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(a.err)
	force := flags.Bool("force", false, "replace an existing policy after explicit request")
	if err := flags.Parse(args); err != nil {
		return ExitFailure
	}
	root, err := config.FindRepoRoot(a.workdir)
	if err != nil {
		a.errorf("cannot inspect repository: %v", err)
		return ExitFailure
	}
	path := filepath.Join(root, ".agent-firewall.yaml")
	if _, err := os.Stat(path); err == nil && !*force {
		if !isTerminal(a.in) {
			a.errorf("%s already exists; use --force to replace it", path)
			return ExitFailure
		}
		_, _ = fmt.Fprintf(a.out, "%s already exists. Replace it? [y/N] ", path)
		answer, _ := bufio.NewReader(a.in).ReadString('\n')
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			_, _ = fmt.Fprintln(a.out, "Keeping existing policy.")
			return ExitSuccess
		}
	}
	if err := os.WriteFile(path, []byte(defaults.ExampleYAML()), 0o644); err != nil {
		a.errorf("cannot write %s: %v", path, err)
		return ExitFailure
	}
	if a.json {
		a.writeJSON(map[string]any{"created": path, "signals": config.ProjectSignals(root)})
		return ExitSuccess
	}
	a.printer.Header("Agent Firewall Init")
	a.printer.Label("Repository", root)
	a.printer.Label("Detected", strings.Join(config.ProjectSignals(root), ", "))
	a.printer.Success("Created " + path)
	_, _ = fmt.Fprintln(a.out, "\nProtected by default: ~/.ssh, ~/.gnupg, ~/.aws, ~/.kube")
	_, _ = fmt.Fprintln(a.out, "\nNext steps:\n  afw validate\n  afw status\n  afw run -- codex")
	return ExitSuccess
}

func (a *app) validate(args []string) int {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(a.err)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return ExitFailure
	}
	if *jsonOutput {
		a.json = true
	}
	loaded, err := config.Load(a.workdir)
	if err != nil {
		a.errorf("%v", err)
		return ExitInvalidConfig
	}
	counts := map[string]int{
		"filesystem": len(loaded.Policy.Filesystem.Allow) + len(loaded.Policy.Filesystem.ReadOnly) + len(loaded.Policy.Filesystem.Ask) + len(loaded.Policy.Filesystem.Deny),
		"network":    len(loaded.Policy.Network.Allow) + len(loaded.Policy.Network.Ask) + len(loaded.Policy.Network.Deny),
		"shell":      len(loaded.Policy.Shell.Allow) + len(loaded.Policy.Shell.Ask) + len(loaded.Policy.Shell.Deny),
	}
	if a.json {
		a.writeJSON(map[string]any{"valid": true, "policy": loaded.PolicyPath, "rule_counts": counts, "sources": loaded.Sources})
		return ExitSuccess
	}
	a.printer.Header("Agent Firewall Validation")
	a.printer.Success(loaded.PolicyPath + " is valid")
	for _, key := range []string{"filesystem", "network", "shell"} {
		a.printer.Label(key+" rules", fmt.Sprint(counts[key]))
	}
	_, _ = fmt.Fprintln(a.out, "No conflicting schema values found.")
	return ExitSuccess
}

func (a *app) status(args []string) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(a.err)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return ExitFailure
	}
	if *jsonOutput {
		a.json = true
	}
	loaded, err := config.Load(a.workdir)
	if err != nil {
		a.errorf("%v", err)
		return ExitInvalidConfig
	}
	_, selection, detectErr := selectForMode(context.Background(), loaded.Policy, loaded.Policy.Mode)
	status := map[string]any{
		"version":      Version,
		"platform":     config.PlatformLabel(),
		"policy":       loaded.PolicyPath,
		"mode":         loaded.Policy.Mode,
		"sources":      loaded.Sources,
		"audit_log":    auditPath(loaded),
		"backend":      nil,
		"capabilities": nil,
	}
	if detectErr != nil {
		status["error"] = detectErr.Error()
	} else {
		status["backend"] = selection.Backend.Name()
		status["backend_mode"] = selection.Mode
		status["capabilities"] = selection.Capabilities
		status["note"] = selection.Note
	}
	if a.json {
		a.writeJSON(status)
		if detectErr != nil {
			return ExitUnavailable
		}
		return ExitSuccess
	}
	a.printer.Header("Agent Firewall")
	a.printer.Label("Version", Version)
	a.printer.Label("Platform", config.PlatformLabel())
	a.printer.Label("Policy", loaded.PolicyPath)
	a.printer.Label("Mode", loaded.Policy.Mode)
	a.printer.Section("Available backends")
	localBackend := local.New()
	a.printer.Label("local", "✓ "+string(localBackend.Capabilities(loaded.Policy).Filesystem)+" filesystem / "+string(localBackend.Capabilities(loaded.Policy).Network)+" network")
	containerBackend := container.New(loaded.Policy.Sandbox.Container.Runtime)
	if err := containerBackend.Available(context.Background()); err == nil {
		a.printer.Label("container", "✓ available")
	} else {
		a.printer.Label("container", "× unavailable")
	}
	a.printer.Section("Effective backend")
	if detectErr != nil {
		a.printer.Failure(detectErr.Error())
		return ExitUnavailable
	}
	a.printer.Label("Backend", selection.Backend.Name())
	a.printer.Label("Run mode", selection.Mode)
	a.printer.Section("Protections")
	a.printer.Label("Filesystem", a.printer.Capability(selection.Capabilities.Filesystem))
	a.printer.Label("Network", a.printer.Capability(selection.Capabilities.Network))
	a.printer.Label("Environment", a.printer.Capability(selection.Capabilities.Environment))
	a.printer.Label("Process", a.printer.Capability(selection.Capabilities.Process))
	a.printer.Label("Audit log", "enabled: "+fmt.Sprint(loaded.Policy.Audit.Enabled))
	if selection.Note != "" {
		a.printer.Warning(selection.Note)
	}
	return ExitSuccess
}

func (a *app) doctor(args []string) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(a.err)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return ExitFailure
	}
	if *jsonOutput {
		a.json = true
	}
	root, rootErr := config.FindRepoRoot(a.workdir)
	loaded, configErr := config.Load(a.workdir)
	if rootErr != nil {
		root = a.workdir
	}
	policyValue := defaults.New()
	if configErr == nil {
		policyValue = loaded.Policy
	}
	containerBackend := container.New(policyValue.Sandbox.Container.Runtime)
	containerErr := containerBackend.Available(context.Background())
	_, selection, selectionErr := selectForMode(context.Background(), policyValue, policyValue.Mode)
	filtered, removed := policy.New(policyValue, root).FilterEnvironment(os.Environ())
	_ = filtered
	auditLocation := config.AuditPath(policyValue.Audit.Path)
	writable := checkWritable(filepath.Dir(auditLocation))
	checks := []map[string]any{
		{"name": "Git repository detected", "ok": rootErr == nil && hasGit(root)},
		{"name": "Policy file valid", "ok": configErr == nil},
		{"name": "Container runtime available", "ok": containerErr == nil},
		{"name": "Network isolation available", "ok": selectionErr == nil && selection.Capabilities.Network == publicpolicy.CapabilityEnforce},
		{"name": "Audit directory writable", "ok": writable},
	}
	ready := configErr == nil && writable && selectionErr == nil
	if a.json {
		a.writeJSON(map[string]any{"ready": ready, "checks": checks, "secret_like_environment_removed": len(removed), "container_error": errorString(containerErr), "selection_error": errorString(selectionErr)})
		if configErr != nil {
			return ExitInvalidConfig
		}
		if !ready {
			return ExitUnavailable
		}
		return ExitSuccess
	}
	a.printer.Header("Agent Firewall Doctor")
	for _, check := range checks {
		if check["ok"] == true {
			a.printer.Success(check["name"].(string))
		} else {
			a.printer.Warning(check["name"].(string))
		}
	}
	if configErr != nil {
		a.printer.Failure("Policy error: " + configErr.Error())
	}
	if len(removed) > 0 {
		a.printer.Warning(fmt.Sprintf("%d secret-like environment variables will be filtered", len(removed)))
	}
	if containerErr != nil {
		a.printer.Warning("Container backend: " + containerErr.Error())
	}
	if selectionErr == nil && selection.Note != "" {
		a.printer.Warning(selection.Note)
	} else if selectionErr != nil {
		a.printer.Failure("Backend selection: " + selectionErr.Error())
	}
	if ready {
		_, _ = fmt.Fprintln(a.out, "\nOverall\n\nReady for monitor mode. Enforce mode requires an available container with compatible policy capabilities.")
		return ExitSuccess
	}
	_, _ = fmt.Fprintln(a.out, "\nOverall\n\nNeeds attention")
	return ExitFailure
}

func (a *app) explain(args []string) int {
	loaded, err := config.Load(a.workdir)
	if err != nil {
		a.errorf("%v", err)
		return ExitInvalidConfig
	}
	engine := policy.New(loaded.Policy, loaded.RepoRoot)
	if len(args) == 0 {
		if a.json {
			a.writeJSON(map[string]any{"policy": loaded.Policy, "sources": loaded.Sources})
			return ExitSuccess
		}
		a.printer.Header("Agent Firewall Policy")
		a.printer.Label("Source", strings.Join(loaded.Sources, ", "))
		a.printer.Label("Filesystem default", string(loaded.Policy.Filesystem.Default))
		a.printer.Label("Network default", string(loaded.Policy.Network.Default))
		a.printer.Label("Shell default", string(loaded.Policy.Shell.Default))
		_, _ = fmt.Fprintln(a.out, "\nUse: afw explain path <path> or afw explain command -- <command>")
		return ExitSuccess
	}
	kind := args[0]
	values := args[1:]
	if len(values) > 0 && values[0] == "--" {
		values = values[1:]
	}
	if len(values) == 0 {
		a.errorf("explain %s: expected a resource", kind)
		return ExitFailure
	}
	var result publicpolicy.Result
	switch kind {
	case "path":
		result = engine.EvaluatePath(strings.Join(values, " "))
	case "command":
		result = engine.EvaluateShell(displayCommand(values))
	case "network":
		result = engine.EvaluateNetwork(values[0])
	default:
		a.errorf("explain: expected path, command, or network; got %q", kind)
		return ExitFailure
	}
	if a.json {
		a.writeJSON(result)
		return ExitSuccess
	}
	a.printer.Header("Agent Firewall Explanation")
	a.printer.Label("Decision", strings.ToUpper(string(result.Decision)))
	a.printer.Label("Resource", result.Resource)
	a.printer.Label("Matched", result.Rule)
	a.printer.Label("Reason", result.Reason)
	return ExitSuccess
}

func (a *app) logs(args []string) int {
	flags := flag.NewFlagSet("logs", flag.ContinueOnError)
	flags.SetOutput(a.err)
	last := flags.Int("last", 20, "number of newest records")
	sessionID := flags.String("session", "", "filter by session ID")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return ExitFailure
	}
	if *jsonOutput {
		a.json = true
	}
	loaded, err := config.Load(a.workdir)
	if err != nil {
		a.errorf("%v", err)
		return ExitInvalidConfig
	}
	if *last < 0 {
		a.errorf("last: must be zero or greater")
		return ExitFailure
	}
	events, err := audit.Read(auditPath(loaded), *sessionID, *last)
	if err != nil {
		a.errorf("cannot read audit log: %v", err)
		return ExitFailure
	}
	if a.json {
		a.writeJSON(events)
		return ExitSuccess
	}
	a.printer.Header("Agent Firewall Audit Log")
	a.printer.Label("Path", auditPath(loaded))
	if len(events) == 0 {
		_, _ = fmt.Fprintln(a.out, "No matching events.")
		return ExitSuccess
	}
	for _, event := range events {
		_, _ = fmt.Fprintf(a.out, "%s  %-18s %-8s %s\n", event.Timestamp.Format(time.RFC3339), event.Event, event.Decision, event.Resource)
	}
	return ExitSuccess
}

func (a *app) configCommand(args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(a.err, "Usage: afw config show | afw config path")
		return ExitFailure
	}
	loaded, err := config.Load(a.workdir)
	if err != nil {
		a.errorf("%v", err)
		return ExitInvalidConfig
	}
	switch args[0] {
	case "path":
		if a.json {
			a.writeJSON(map[string]string{"repository": loaded.PolicyPath, "global": loaded.GlobalPath, "audit": auditPath(loaded)})
		} else {
			_, _ = fmt.Fprintf(a.out, "repository: %s\nglobal: %s\naudit: %s\n", loaded.PolicyPath, loaded.GlobalPath, auditPath(loaded))
		}
		return ExitSuccess
	case "show":
		a.writeJSON(policyMap(loaded.Policy))
		return ExitSuccess
	default:
		_, _ = fmt.Fprintf(a.err, "afw config: unknown subcommand %q\n", args[0])
		return ExitFailure
	}
}

func (a *app) completion(args []string) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(a.err, "Usage: afw completion <bash|zsh|fish|powershell>")
		return ExitFailure
	}
	command := "afw"
	switch args[0] {
	case "bash":
		_, _ = fmt.Fprintln(a.out, `_afw_complete() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  COMPREPLY=( $(compgen -W "run init validate status doctor explain logs config version completion codex claude" -- "$cur") )
}
complete -F _afw_complete afw`)
	case "zsh":
		_, _ = fmt.Fprintln(a.out, `#compdef afw
_arguments '1:command:(run init validate status doctor explain logs config version completion codex claude)'`)
	case "fish":
		_, _ = fmt.Fprintf(a.out, `complete -c %s -f -a "run init validate status doctor explain logs config version completion codex claude"`, command)
		_, _ = fmt.Fprintln(a.out)
	case "powershell":
		_, _ = fmt.Fprintln(a.out, `Register-ArgumentCompleter -CommandName afw -ScriptBlock {
  param($wordToComplete)
  "run","init","validate","status","doctor","explain","logs","config","version","completion","codex","claude" | Where-Object { $_ -like "$wordToComplete*" }
}`)
	default:
		_, _ = fmt.Fprintf(a.err, "unsupported shell %q\n", args[0])
		return ExitFailure
	}
	return ExitSuccess
}

func (a *app) writeJSON(value any) {
	encoder := json.NewEncoder(a.out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_, _ = fmt.Fprintf(a.err, "afw: encode JSON: %v\n", err)
	}
}

func (a *app) errorf(format string, values ...any) {
	_, _ = fmt.Fprintf(a.err, "afw: "+format+"\n", values...)
}

func colorEnabled(in io.Reader, out io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return isTerminal(in) && isTerminal(out)
}

func isTerminal(value any) bool {
	if file, ok := value.(*os.File); ok {
		info, err := file.Stat()
		return err == nil && info.Mode()&os.ModeCharDevice != 0
	}
	return false
}

func displayCommand(command []string) string {
	parts := make([]string, 0, len(command))
	for _, value := range command {
		parts = append(parts, shellQuote(value))
	}
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	if value != "" && strings.IndexFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\'' || r == '"' || r == '$' || r == '`' || r == '|' || r == '&' || r == ';'
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func hasGit(root string) bool {
	_, err := os.Stat(filepath.Join(root, ".git"))
	return err == nil
}

func checkWritable(directory string) bool {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return false
	}
	file, err := os.CreateTemp(directory, ".afw-doctor-*")
	if err != nil {
		return false
	}
	name := file.Name()
	_ = file.Close()
	_ = os.Remove(name)
	return true
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func policyMap(value publicpolicy.Policy) map[string]any {
	return map[string]any{
		"version":     value.Version,
		"mode":        value.Mode,
		"filesystem":  map[string]any{"default": value.Filesystem.Default, "allow": value.Filesystem.Allow, "read_only": value.Filesystem.ReadOnly, "ask": value.Filesystem.Ask, "deny": value.Filesystem.Deny},
		"network":     map[string]any{"default": value.Network.Default, "allow": value.Network.Allow, "ask": value.Network.Ask, "deny": value.Network.Deny},
		"shell":       map[string]any{"default": value.Shell.Default, "allow": value.Shell.Allow, "ask": value.Shell.Ask, "deny": value.Shell.Deny},
		"environment": map[string]any{"inherit": value.Environment.Inherit, "deny": value.Environment.Deny},
		"audit":       map[string]any{"enabled": value.Audit.Enabled, "format": value.Audit.Format, "path": value.Audit.Path},
		"sandbox":     map[string]any{"backend": value.Sandbox.Backend, "container": map[string]any{"runtime": value.Sandbox.Container.Runtime, "image": value.Sandbox.Container.Image, "network": value.Sandbox.Container.Network}},
	}
}
