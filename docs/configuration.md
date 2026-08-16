# Configuration

The primary repository file is `.agent-firewall.yaml`. Global configuration is loaded first from the path shown by:

```bash
afw config path
```

## Precedence

```text
built-in defaults
    ↓
global policy
    ↓
repository policy
    ↓
CLI flags
```

Repository policy values replace the corresponding global rule lists. This keeps overrides predictable and avoids accidentally concatenating a broad global allowlist with a stricter repository policy.

## Decisions

Each resource rule uses:

- `allow`: proceed without prompting;
- `ask`: require interactive approval or apply the documented non-interactive policy;
- `deny`: block before the wrapper launches the child.

The order within a resource is deny, ask, specialized allow, then default. Deny therefore wins over a broad allow rule.

## Path patterns

Path rules accept relative paths from the repository root, absolute paths, home-relative paths beginning with `~`, and `*`/ `**` wildcards. Existing symlink targets and the nearest existing parent are canonicalized before matching. This protects against a repository-local symlink pointing at a protected location.

The local backend evaluates paths for explanations but cannot intercept later child-process path operations. The container backend reduces the reachable host filesystem by mounting only the repository.

## Environment

Environment inheritance is an allowlist. Deny patterns are checked first. Secret-like names such as `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_API_KEY`, and private-key patterns are removed even if a broad inherit pattern would otherwise match them.

Values are never printed by `status`, `doctor`, dry runs, or audit events.

## Network

Hostname rules are part of the policy model. The current container backend can enforce an all-network-off policy; it cannot enforce a list of permitted domains without a separate network proxy. When a policy asks for domain-level behavior, capabilities show `monitor` and explicit enforce mode fails closed.

## Validation

```bash
afw validate
afw config show
afw explain path ~/.ssh/id_ed25519
```

Invalid keys and decisions return a field-specific error and exit code 2.
