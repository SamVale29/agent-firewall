# Changelog

All notable changes to Agent Firewall are documented here.

## [Unreleased]

### Added

- Race detection and pull-request vulnerability scanning in CI.
- CycloneDX SBOMs and GitHub build provenance for future releases.
- Versioned binary installation guidance and a PowerShell demo.
- CodeQL analysis and dependency review on protected changes.

### Changed

- Pin GitHub Actions used by CI, security, and release workflows to immutable commits.
- Run grouped Go module and GitHub Actions dependency updates weekly through Dependabot.

## [0.1.0] - 2026-08-16

### Added

- Deterministic `allow`, `ask`, and `deny` policy model.
- Local monitor backend with explicit capability reporting.
- Docker/Podman backend with repository-only mounts, filtered environment, and optional network isolation.
- Shell risk analysis, interactive approvals, dry runs, explanations, audit logs, and session IDs.
- English and Brazilian Portuguese documentation.

### Fixed

- Cross-platform CI formatting, lint, and symlink-policy regressions.
- Enforce-mode backend selection now fails closed instead of silently downgrading.
- Container network capability reporting and explicit `policy`, `none`, and `default` modes.
- Recursive audit redaction, policy hashes, decision outcomes, and session completion records.
