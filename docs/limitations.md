# Limitations

Agent Firewall v0.1.0 is intentionally narrow.

## Local mode is not a sandbox

The local backend runs on the host. Filesystem and network policies are evaluated for explanations and approvals, but the child process can still make host syscalls. Use it for visibility, environment filtering, and development workflows.

## Container image responsibility

The container backend does not install or copy host tools into an image. The selected image must contain the command, dependencies, certificates, and package manager workflow required by the agent. A container runtime itself is a privileged host component and must be trusted.

## Network rules

The MVP can disable all container network access. It cannot enforce hostname allowlists or inspect encrypted traffic. Domain rules are therefore reported as monitor-only.

## Command analysis

The risk analyzer is intentionally deterministic and incomplete. It recognizes common patterns such as recursive deletion, hard Git resets, raw device operations, and download-to-shell pipelines. It does not parse every shell language, command alias, script, binary, or indirect execution path.

## Filesystem rules

The policy engine canonicalizes known symlinks and supports path explanations. The local backend cannot intercept filesystem operations. Container mounts reduce the host surface but do not implement arbitrary read-only submounts for every pattern in the policy file.

## Secret redaction

Redaction covers obvious variable names, assignments, and PEM blocks. It is not a complete secret scanner. Avoid passing secrets on command lines and avoid writing them to files that the child can read.

## Platform maturity

The CLI builds on Linux, macOS, and Windows. Native platform sandbox backends are not included in this release. Docker/Podman behavior, TTY support, user mapping, and capability flags should be tested on the target platform.

## No production claim

v0.1.0 is experimental. Do not describe it as enterprise-ready, production-safe, or a replacement for OS security controls.
