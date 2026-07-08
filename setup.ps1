#!/usr/bin/env pwsh
# Windows equivalent of setup.sh - wires this repo's AGENTS.md into both Claude Code
# and Codex CLI on the current machine. Safe to re-run (idempotent).
$ErrorActionPreference = "Stop"

$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentsFile = Join-Path $RepoDir "AGENTS.md"

if (-not (Test-Path $AgentsFile)) {
    Write-Error "AGENTS.md not found at $AgentsFile"
    exit 1
}

# --- Codex CLI: link ~/.codex/AGENTS.md -> this repo's AGENTS.md ---
$codexDir = Join-Path $HOME ".codex"
New-Item -ItemType Directory -Force -Path $codexDir | Out-Null
$codexAgents = Join-Path $codexDir "AGENTS.md"

if (Test-Path $codexAgents) {
    $existing = Get-Item $codexAgents -Force
    if ($existing.LinkType) {
        Remove-Item $codexAgents -Force
    } else {
        Write-Host "$codexAgents already exists and isn't a link -- backing it up to AGENTS.md.bak"
        Move-Item $codexAgents "$codexAgents.bak" -Force
    }
}

try {
    New-Item -ItemType SymbolicLink -Path $codexAgents -Target $AgentsFile -ErrorAction Stop | Out-Null
} catch {
    # Creating symlinks needs admin rights or Developer Mode - fall back to a
    # hard link, which works unprivileged as long as both paths share a volume.
    New-Item -ItemType HardLink -Path $codexAgents -Target $AgentsFile | Out-Null
}
Write-Host "Linked $codexAgents -> $AgentsFile"

# --- Claude Code: append an @import line to ~/.claude/CLAUDE.md ---
$claudeDir = Join-Path $HOME ".claude"
New-Item -ItemType Directory -Force -Path $claudeDir | Out-Null
$claudeMd = Join-Path $claudeDir "CLAUDE.md"
if (-not (Test-Path $claudeMd)) {
    New-Item -ItemType File -Path $claudeMd | Out-Null
}

$importLine = "@$AgentsFile"
$existingContent = Get-Content $claudeMd -Raw -ErrorAction SilentlyContinue
if (-not $existingContent -or -not $existingContent.Contains($importLine)) {
    Add-Content -Path $claudeMd -Value "`n## Machine registry`n$importLine"
    Write-Host "Added import line to $claudeMd"
} else {
    Write-Host "$claudeMd already imports this registry -- nothing to do"
}

# --- Periodic sync: Scheduled Task that pulls latest changes and re-runs
# setup.ps1 whenever the pull brings new commits. Runs every 30 min. ---
# Launched via wscript + sync-hidden.vbs so it runs with no console window
# flash, instead of calling powershell.exe directly (which -WindowStyle
# Hidden alone does not reliably suppress).
$taskName = "agents-registry-sync"
$syncScript = Join-Path $RepoDir "sync.ps1"
$hiddenWrapper = Join-Path $RepoDir "sync-hidden.vbs"
$innerCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$syncScript`""
$action = New-ScheduledTaskAction -Execute "wscript.exe" `
    -Argument "`"$hiddenWrapper`" `"$innerCommand`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 30) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
    -Description "Pulls agents-registry and re-runs setup.ps1 if changed" -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "Registered scheduled task '$taskName' -- syncs every 30 min."

Write-Host "Done. Don't forget to add matching Host entries to your SSH config (see ssh-config.example)."
