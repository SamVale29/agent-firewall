# Security Policy

Agent Firewall is security-sensitive software. Please do not disclose an exploitable vulnerability in a public GitHub issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository when it is available. Include:

- a concise description and impact;
- affected version or commit;
- reproduction steps or a minimal proof of concept;
- operating system and backend;
- whether Docker or Podman is involved;
- any suggested mitigation.

If private reporting is not available, contact the repository maintainers through a private channel listed on the GitHub profile and ask for a security contact. Do not attach real credentials or sensitive repository data.

## Response expectations

Maintainers will acknowledge a report when practical, validate the impact, coordinate a fix, and publish a security advisory or release note when appropriate. Timelines depend on severity and reproduction quality.

## Scope

Reports about false security claims, capability misreporting, environment secret leakage, audit-log disclosure, container mount escapes, and unsafe default policies are especially important.

Agent Firewall v0.1.0 is experimental. Users should still apply OS updates, least privilege, container hardening, dependency review, and normal incident-response controls.
