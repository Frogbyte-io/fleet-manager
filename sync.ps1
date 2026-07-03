#!/usr/bin/env pwsh
# Windows equivalent of sync.sh - pulls the latest agents-registry changes and
# re-runs setup.ps1 if anything moved. Invoked periodically by the
# agents-registry-sync scheduled task (see setup.ps1).
$ErrorActionPreference = "Stop"

$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoDir

$before = (git rev-parse HEAD).Trim()
git fetch --quiet origin
git pull --ff-only --quiet
$after = (git rev-parse HEAD).Trim()

if ($before -ne $after) {
    Write-Host "agents-registry: updated $before -> $after, re-running setup.ps1"
    & (Join-Path $RepoDir "setup.ps1")
} else {
    Write-Host "agents-registry: no changes ($after)"
}
