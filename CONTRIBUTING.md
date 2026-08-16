# Contributing

Thanks for helping improve Agent Firewall.

## Development setup

- Go 1.22 or newer
- Git
- Docker or Podman for container-backend integration work
- Make (optional)

Clone the repository, then run:

```bash
go test ./...
go vet ./...
go build ./cmd/afw
```

Useful targets:

```bash
make test
make vet
make build
make fmt
make demo
```

## Code style

Use idiomatic Go, small cohesive packages, contextual errors, and table-driven tests. Run `gofmt` on changed Go files. Avoid new dependencies unless the security or maintenance benefit is clear.

## Security-sensitive changes

A change that affects policy decisions, path canonicalization, environment filtering, redaction, backend capabilities, container flags, signal handling, or audit records must include:

1. a focused test;
2. an explanation of the platform assumptions;
3. an update to `docs/security-model.md`, `docs/threat-model.md`, or `docs/limitations.md) when a guarantee changes;
4. a review for secret leakage in errors and logs.

Never make a monitor-only behavior report as enforced.

## Pull requests

Pull requests should:

- explain the user impact;
- describe the security tradeoff;
- include commands used for validation;
- keep unrelated formatting changes out;
- update documentation and examples when CLI behavior changes.

Please use the issue templates for bugs and feature requests. Use `SECURITY.md` for vulnerabilities.
