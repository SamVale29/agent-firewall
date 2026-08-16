# Threat Model

## In scope

| Threat | Mitigation |
| --- | --- |
| Accidental destructive shell command | Deterministic risk analyzer, `ask`/ `deny` policy, interactive approval |
| Malicious dependency install script | Run inside a configured enforcing container; review image and network policy |
| Credential path access | Default deny patterns and repository-only container mount |
| Environment secret leakage | Explicit inheritance allowlist and secret-name deny patterns |
| Unexpected network exfiltration | Container `--network none` for all-deny policies; honest capability reporting |
| Repository escape | Container mount is scoped to the repository by default |
| Unclear security behavior | Status, dry run, explain, capability model, and audit log |

## Out of scope

The MVP does not provide:

- perfect shell parsing;
- kernel-level EDR or malware detection;
- protection from a malicious or privileged host administrator;
- perfect defense against prompt injection;
- domain-level packet filtering;
- guaranteed protection from every runtime or kernel vulnerability;
- organization-wide policy distribution or signed policy bundles;
- a secure boundary in local monitor mode.

## Abuse cases

A repository can instruct an agent to change `.agent-firewall.yaml`, use an allowed command to spawn another program, or exploit a dependency/runtime vulnerability. The policy file and selected backend are part of the trust boundary; users should review changes and prefer enforce mode for untrusted code.

An attacker who can run arbitrary code in the local backend can generally access anything the host user can access. This is why local mode is labeled monitor-only.

## Security posture

The project prioritizes correctness and honest limitations over a larger list of simulated controls. New guarantees require an implementation, a test, and documentation of the platform assumptions.
