#!/usr/bin/env bash
set -euo pipefail

# The demo is deliberately disposable: it creates and removes only a temp directory.
PROJECT_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$PROJECT_DIR"
}
trap cleanup EXIT

export GOCACHE="${GOCACHE:-/tmp/afw-demo-go-cache}"
export XDG_CONFIG_HOME="$PROJECT_DIR/config"
export XDG_CACHE_HOME="$PROJECT_DIR/cache"
AFW_BIN="${AFW_BIN:-afw}"

cd "$PROJECT_DIR"
mkdir -p demo-repo
mkdir -p demo-repo/.git
cd demo-repo

cat > .agent-firewall.yaml <<'POLICY'
version: 1
mode: monitor
filesystem:
  default: ask
  allow:
    - "./**"
  deny:
    - "~/.ssh/**"
network:
  default: ask
shell:
  default: allow
  ask:
    - "rm"
  deny:
    - "sudo"
environment:
  inherit:
    - "PATH"
    - "LANG"
  deny:
    - "*_TOKEN"
audit:
  enabled: true
  format: jsonl
sandbox:
  backend: local
  container:
    image: "ubuntu:24.04"
    network: policy
POLICY

printf 'demo\n' > README.demo.md
printf '%s\n' '== initialize =='
"$AFW_BIN" init --force
printf '%s\n' '== validate =='
"$AFW_BIN" validate
printf '%s\n' '== status =='
"$AFW_BIN" status
printf '%s\n' '== dry run =='
"$AFW_BIN" run --dry-run -- git status
printf '%s\n' '== explain protected path =='
"$AFW_BIN" explain path ~/.ssh/id_ed25519
printf '%s\n' '== blocked command =='
if "$AFW_BIN" run --non-interactive -- sudo reboot; then
  echo "unexpected allow"
  exit 1
else
  echo "blocked as expected"
fi
printf '%s\n' '== logs =='
"$AFW_BIN" logs --last 20
