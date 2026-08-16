# Security Model

Agent Firewall is a local policy and containment layer for coding-agent workflows. It is not an endpoint detection product, antivirus, or a guarantee that arbitrary hostile code is safe.

## Protection goals

The MVP is designed to reduce:

- accidental destructive commands;
- accidental access to common credential paths;
- accidental leakage of secret-like environment variables;
- repository escape when using the container backend;
- unexpected broad network access when the policy disables container networking;
- lack of traceability around policy decisions.

## Enforcement claims

The product distinguishes capability levels:

- `enforce`: implemented by the selected backend;
- `monitor`: visible or evaluated, but not reliably prevented;
- `unsupported`: not provided.

The local backend always reports filesystem and network as `monitor`. It launches a process on the host and cannot intercept arbitrary syscalls. The command analyzer does not turn string matching into a firewall.

The container backend enforces its repository mount and, for an all-network-deny policy, passes `--network none` to Docker or Podman. It does not claim hostname-level enforcement. It cannot protect against a compromised container runtime, a privileged host administrator, a runtime escape, or a host kernel vulnerability.

## Trust assumptions

- The user trusts the Agent Firewall binary and its configuration.
- The user trusts the Docker/Podman runtime and its host integration.
- The host operating system correctly enforces process and container boundaries.
- The repository policy is not modified by an untrusted process before execution.
- The user understands what image is being executed and what tools are installed in it.

## Configuration and policy

A policy file is executable security input. Review it like code. A repository can contain a policy that is more permissive than a global policy; users should inspect `afw config show` and `afw status` before running untrusted repositories.

Policy decisions are deterministic. The core does not call an LLM, make network requests, or rely on telemetry.

## Secrets and privacy

The child environment is constructed from an allowlist and deny patterns. Audit records redact obvious assignments, PEM blocks, and secret-like keys. This is a defense against accidental logging, not a perfect secret detector. Do not put secrets in command-line arguments.

No telemetry is sent by default.

## Security-sensitive behavior

Enforce mode fails when no enforcing backend is available or when the backend cannot enforce the requested network capability. The wrapper does not silently turn an enforce request into monitor mode.
