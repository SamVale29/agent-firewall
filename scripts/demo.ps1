$ErrorActionPreference = "Stop"

$projectDir = Join-Path ([System.IO.Path]::GetTempPath()) ("afw-demo-" + [Guid]::NewGuid().ToString("N"))
$afw = if ($env:AFW_BIN) { $env:AFW_BIN } else { "afw" }

try {
    $demoRepo = Join-Path $projectDir "demo-repo"
    New-Item -ItemType Directory -Force -Path (Join-Path $demoRepo ".git") | Out-Null

    $env:GOCACHE = if ($env:GOCACHE) { $env:GOCACHE } else { Join-Path $projectDir "go-cache" }
    $env:XDG_CONFIG_HOME = Join-Path $projectDir "config"
    $env:XDG_CACHE_HOME = Join-Path $projectDir "cache"

    @'
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
'@ | Set-Content -LiteralPath (Join-Path $demoRepo ".agent-firewall.yaml") -Encoding utf8

    "demo" | Set-Content -LiteralPath (Join-Path $demoRepo "README.demo.md") -Encoding utf8

    Push-Location $demoRepo
    try {
        Write-Output "== initialize =="
        & $afw init --force
        Write-Output "== validate =="
        & $afw validate
        Write-Output "== status =="
        & $afw status
        Write-Output "== dry run =="
        & $afw run --dry-run -- git status
        Write-Output "== explain protected path =="
        & $afw explain path (Join-Path $HOME ".ssh\id_ed25519")
        Write-Output "== blocked command =="
        & $afw run --non-interactive -- sudo reboot
        if ($LASTEXITCODE -eq 0) {
            throw "unexpected allow"
        }
        Write-Output "blocked as expected"
        Write-Output "== logs =="
        & $afw logs --last 20
    }
    finally {
        Pop-Location
    }
}
finally {
    if (Test-Path -LiteralPath $projectDir) {
        Remove-Item -LiteralPath $projectDir -Recurse -Force
    }
}
