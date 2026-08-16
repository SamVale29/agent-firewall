# Backends

## Local

The local backend launches the child on the host. It provides:

- explicit environment inheritance;
- secret-like environment filtering;
- shell pre-flight decisions;
- signal-aware process execution;
- audit events.

It reports filesystem and network as `monitor`, not `enforce`. A local process can still access any host path and network destination that the operating system user can access.

Use it for:

```bash
afw run --mode monitor -- codex
```

## Container

The container backend detects Docker or Podman, verifies that the runtime is available, and launches:

- a user-selected image, defaulting to `ubuntu:24.04`;
- only the repository directory mounted at `/workspace`;
- a read-only container root filesystem;
- a writable, no-exec temporary filesystem;
- dropped Linux capabilities where the runtime supports the flags;
- `no-new-privileges`;
- a bounded PID count where supported;
- a filtered environment;
- the current host user ID on Unix hosts when possible.

With `sandbox.container.network: policy`, a policy whose network default is `deny` and has no `allow` or `ask` exceptions is translated to `--network none`. `sandbox.container.network: none` always disables container networking, while `default` leaves the runtime's default network enabled. Domain allowlists are modeled in policy but are reported as monitor-only because Docker/Podman alone does not provide the required hostname-level enforcement.

The command must exist in the selected image. For example, a host-installed `codex` binary is not automatically available inside `ubuntu:24.04`. Build or select an image that contains the agent and its dependencies.

```bash
afw run --mode enforce -- codex
```

If the runtime is missing, enforce mode exits instead of silently falling back to local execution.

## Capability levels

| Level | Meaning |
| --- | --- |
| `unsupported` | The backend does not provide the capability. |
| `monitor` | The backend can observe or configure related behavior but cannot reliably prevent it. |
| `enforce` | The backend implementation actively applies the boundary described by the policy. |

Capability values are reported by `afw status` and `afw run --dry-run`.
