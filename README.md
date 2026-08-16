English | [Português do Brasil](README.pt-BR.md)

# Agent Firewall

**A security layer between AI coding agents and your machine.**

Run coding agents with explicit rules for filesystem access, network access, environment secrets, and dangerous commands.

[![CI](https://github.com/SamVale29/agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/SamVale29/agent-firewall/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/SamVale29/agent-firewall.svg)](https://pkg.go.dev/github.com/SamVale29/agent-firewall)

> Agent Firewall is experimental security tooling. Read the [security model](docs/security-model.md) and [limitations](docs/limitations.md) before relying on it for sensitive work.

## Why?

Coding agents can execute commands, edit files, access environment variables, install dependencies, and communicate with external services. Agent Firewall adds a local policy and containment layer around those operations.

The design goal is trust through accurate capability reporting:

- the Docker/Podman backend mounts the repository explicitly and can disable container networking;
- the local backend filters the child environment and provides visibility, but does not claim to isolate host filesystem or network access;
- policy evaluation is deterministic, local, and independent of any AI API;
- audit records are local JSON Lines with secret redaction and no telemetry.

## Quick start

### Install from source

Requires Go 1.25 or newer:

```bash
go install github.com/SamVale29/agent-firewall/cmd/afw@latest
```

### Install a versioned release

Prebuilt archives for Linux, macOS, and Windows are published on the [GitHub Releases page](https://github.com/SamVale29/agent-firewall/releases). Replace `0.1.0` below with the version you want to install.

New releases also include CycloneDX SBOM files and GitHub build provenance alongside the archives and checksums.

For example, on Linux amd64:

```bash
VERSION=0.1.0
curl --fail --location --remote-name "https://github.com/SamVale29/agent-firewall/releases/download/v${VERSION}/agent-firewall_${VERSION}_linux_amd64.tar.gz"
curl --fail --location --remote-name "https://github.com/SamVale29/agent-firewall/releases/download/v${VERSION}/checksums.txt"
grep "agent-firewall_${VERSION}_linux_amd64.tar.gz" checksums.txt | sha256sum -c -
tar -xzf "agent-firewall_${VERSION}_linux_amd64.tar.gz"
sudo install -m 0755 afw /usr/local/bin/afw
```

On Windows, download the `windows_amd64.zip` archive and `checksums.txt`, then compare the archive's SHA-256 value with the matching line from `checksums.txt`:

```powershell
Get-FileHash .\agent-firewall_0.1.0_windows_amd64.zip -Algorithm SHA256
Select-String windows_amd64 checksums.txt
Expand-Archive .\agent-firewall_0.1.0_windows_amd64.zip -DestinationPath .\afw
```

### Initialize and inspect a policy

```bash
afw init
afw validate
afw status
```

### Run an agent

```bash
afw run -- codex
afw run -- claude
```

Use `--mode monitor` when you want to run the host-installed agent with visibility and filtered environment variables. Use `--mode enforce` only after configuring a Docker-compatible runtime and a container image that contains the command you intend to run.

```bash
afw run --mode monitor -- codex
afw run --dry-run -- codex
afw run --non-interactive --ask-policy deny -- npm test
```

## What it protects

| Layer | Local backend | Container backend |
| --- | --- | --- |
| Repository mount | Observed only | Explicit bind mount at `/workspace` |
| Host filesystem | Not enforced | Host paths outside the repository are not mounted by default |
| Network | Not enforced | Enforced when policy is `network.default: deny` with no domain exceptions |
| Environment | Explicit allowlist and secret patterns | Explicit allowlist and secret patterns |
| Dangerous command policy | Pre-flight analysis | Pre-flight analysis |
| Audit log | Local JSONL | Local JSONL |

Command analysis is a visibility and approval layer. It is not a syscall firewall.

## Demo

The deterministic demo uses a disposable temporary directory and never touches real credentials:

```bash
bash scripts/demo.sh
```

On Windows PowerShell:

```powershell
pwsh -File .\scripts\demo.ps1
```

Example output:

```console
$ afw run --dry-run -- git status
Agent Firewall Dry Run
Session          01J...
Backend          local
Mode             monitor
Filesystem       monitor
Network          monitor
Environment      enforced
```

## How it works

```text
Developer
    │
    ▼
afw run
    │
    ├── configuration precedence
    ├── deterministic policy engine
    ├── shell risk analysis and approval
    ├── environment filtering and redaction
    ├── backend capability selection
    └── local JSONL audit session
    │
    ▼
Local process or Docker/Podman container
```

See [architecture.md](docs/architecture.md) and [backends.md](docs/backends.md) for implementation details.

## Configuration

Repository configuration lives in `.agent-firewall.yaml`. A global policy can be placed at the platform-appropriate user configuration path shown by `afw config path`.

Precedence is:

```text
built-in defaults → global policy → repository policy → CLI flags
```

Useful commands:

```bash
afw config show
afw config path
afw explain path ~/.ssh/id_ed25519
afw explain command -- git clean -fdx
afw logs --last 20
afw logs --session <session-id>
```

## Security model

Agent Firewall mitigates accidental destructive actions, accidental credential exposure, and repository blast radius when the container backend is configured correctly. It does not make hostile code safe, and it cannot create a filesystem or network boundary in local monitor mode.

Review:

- [Security model](docs/security-model.md)
- [Threat model](docs/threat-model.md)
- [Limitations](docs/limitations.md)
- [Security reporting](SECURITY.md)

## Platform support

The Go CLI builds on Linux, macOS, and Windows. The local backend is intended for development and monitoring on all three. Enforced isolation currently relies on a Docker-compatible runtime and should be tested on the target operating system; native Linux, macOS, and Windows backends are roadmap items.

## Privacy

There is no telemetry. Agent Firewall does not send command history, repository contents, environment values, or audit logs to a service. Future telemetry, if ever added, must be explicit opt-in.

## Roadmap

- [x] Policy engine with deterministic `allow`, `ask`, and `deny` decisions
- [x] Environment filtering and secret redaction
- [x] Local JSONL audit logging and session IDs
- [x] Docker/Podman repository boundary
- [x] Dry run, explain, status, doctor, and completions
- [ ] Native Linux sandbox using namespaces/Landlock
- [ ] Native macOS sandbox backend
- [ ] Native Windows isolation backend
- [ ] MCP command/filesystem proxy
- [ ] Agent-specific adapters
- [ ] Domain-level network enforcement

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Security-sensitive changes must include policy tests and an update to the security documentation when guarantees or limitations change.

## License

Apache License 2.0. See [LICENSE](LICENSE).
