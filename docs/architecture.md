# Architecture

Agent Firewall is intentionally split into policy, execution, and presentation layers.

## Runtime flow

1. The CLI finds the repository root and loads built-in, global, and repository policy.
2. The policy package validates the effective configuration.
3. The shell analyzer classifies the command passed to `afw run`.
4. `allow`, `ask`, or `deny` is recorded before execution.
5. The environment filter creates an explicit child environment.
6. Backend detection selects local monitoring or a Docker/Podman boundary.
7. A session ID and redacted JSONL events are written locally.
8. The child exit status is propagated where practical.

## Package boundaries

- `pkg/policy`: stable value types and capability vocabulary.
- `internal/config`: dependency-free policy loading, validation, and precedence.
- `internal/policy`: deterministic path, network, shell, and environment evaluation.
- `internal/risk`: explainable command-risk heuristics.
- `internal/sandbox`: backend interface and exit-status contract.
- `internal/sandbox/local`: host process runner with monitor capabilities.
- `internal/sandbox/container`: Docker/Podman runner with explicit repository mount.
- `internal/audit`: local JSON Lines writer and reader.
- `internal/session`: session identity and policy hash.
- `internal/ui`: human terminal presentation and approval input.

The policy engine does not import MCP, a vendor SDK, a database, or an AI API. A future MCP proxy can consume the same structured policy results without changing the CLI core.

## Trust boundaries

The local process boundary is not a security boundary. It exists to provide environment filtering, auditability, and a consistent command UX.

The container boundary is meaningful only when the runtime is trusted, the daemon/socket is not exposed to the child, the repository mount is configured as expected, and the host/container platform behaves normally. Agent Firewall does not mount the host root, the host home directory, or `/var/run/docker.sock` by default.

## Extensibility

Backends implement:

```go
type Backend interface {
    Name() string
    Available(context.Context) error
    Capabilities(policy.Policy) Capabilities
    Run(context.Context, Request) error
}
```

Capabilities are per resource rather than one global “sandboxed” flag. This prevents a backend from reporting network enforcement merely because it can isolate the filesystem.
