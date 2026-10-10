# Runs once, as the new local administrator, at first logon (FirstLogonCommands in
# autounattend.xml). Reads from the config ISO (this script's drive) and the virtio-win ISO.
# Writes C:\ProgramData\fleet\setup-complete when everything below worked.
$ErrorActionPreference = 'Stop'
$cfg = Split-Path -Parent $MyInvocation.MyCommand.Path
$state = 'C:\ProgramData\fleet'
New-Item -ItemType Directory -Force -Path $state | Out-Null
Start-Transcript -Path "$state\setup-guest.log" -Force | Out-Null

function Step($name, [scriptblock]$body) { Write-Host "== $name"; & $body }

try {

Step 'virtio-win guest tools (drivers + qemu-ga)' {
  $virtio = (Get-Volume | Where-Object { $_.FileSystemLabel -like 'virtio-win*' } | Select-Object -First 1).DriveLetter
  if (-not $virtio) { throw 'virtio-win ISO not found' }
  $p = Start-Process -FilePath "${virtio}:\virtio-win-guest-tools.exe" -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru
  Write-Host "guest tools exit code $($p.ExitCode)"   # 3010 = reboot pending, fine
  if ($p.ExitCode -notin 0, 3010) { throw "virtio-win-guest-tools failed: $($p.ExitCode)" }
  Set-Service QEMU-GA -StartupType Automatic
  Start-Service QEMU-GA
}

Step 'OpenSSH Server' {
  $installed = $false
  try {
    for ($i = 1; $i -le 3 -and -not $installed; $i++) {
      $r = Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
      $installed = [bool](Get-Service sshd -ErrorAction SilentlyContinue)
    }
  } catch { Write-Host "Add-WindowsCapability failed: $($_.Exception.Message)" }
  if (-not $installed) {
    # Offline fallback: Microsoft's Win32-OpenSSH MSI carried on the config ISO. The
    # builder verified its pinned SHA-256 before putting it there; verify again here.
    $msi = Join-Path $cfg 'OpenSSH-Win64.msi'
    $want = (Get-Content (Join-Path $cfg 'OpenSSH-Win64.msi.sha256') -Raw).Trim().ToLowerInvariant()
    if ((Get-FileHash -Algorithm SHA256 $msi).Hash.ToLowerInvariant() -ne $want) { throw 'OpenSSH MSI hash mismatch' }
    $p = Start-Process msiexec.exe -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart' -Wait -PassThru
    if ($p.ExitCode -notin 0, 3010) { throw "OpenSSH MSI failed: $($p.ExitCode)" }
  }
  Set-Service sshd -StartupType Automatic
  Set-Service ssh-agent -StartupType Disabled -ErrorAction SilentlyContinue
  if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' `
      -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -Profile Any | Out-Null
  } else {
    Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -Enabled True -Profile Any
  }
  New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -PropertyType String -Force `
    -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | Out-Null

  # Key auth for members of Administrators reads administrators_authorized_keys, whose ACL
  # must be exactly SYSTEM and Administrators.
  $ssh = Join-Path $env:ProgramData 'ssh'
  New-Item -ItemType Directory -Force -Path $ssh | Out-Null
  $keys = Join-Path $ssh 'administrators_authorized_keys'
  [IO.File]::WriteAllText($keys, ((Get-Content (Join-Path $cfg 'authorized_keys.pub') -Raw).Trim() + "`n"),
    (New-Object Text.UTF8Encoding $false))
  icacls.exe $keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null

  # Key-only login. The first start below generates the host keys.
  $conf = Join-Path $ssh 'sshd_config'
  Start-Service sshd
  $lines = Get-Content $conf | Where-Object { $_ -notmatch '^\s*#?\s*PasswordAuthentication\s' }
  Set-Content -Path $conf -Value (@('PasswordAuthentication no') + $lines) -Encoding ascii
  Restart-Service sshd
}

Step 'keep generalize working' {
  # With a TPM, Windows 11 turns on automatic device encryption, and sysprep /generalize
  # refuses to run while BitLocker is on (0x80310039). PreventDeviceEncryption asks Windows
  # not to start it; manage-bde -off decrypts it if it already did (harmless otherwise).
  # generalize.ps1 checks again before sysprep.
  # (New-Item -Force on an existing key with subkeys fails, so create only when missing.)
  if (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker')) { New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker' | Out-Null }
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker' -Name PreventDeviceEncryption -Type DWord -Value 1
  manage-bde.exe -off C: | Out-Null
  # A Store app updated by a user makes sysprep /generalize fail (ADR 0015).
  if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' | Out-Null }
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name AutoDownload -Type DWord -Value 2
  powercfg.exe /h off
  powercfg.exe /change standby-timeout-ac 0
  powercfg.exe /change monitor-timeout-ac 0
}



(Get-Date).ToUniversalTime().ToString('o') | Set-Content "$state\setup-complete"
} finally {
  # Always: no autologon secret stays in the registry, and the transcript is closed.
  $w = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  foreach ($n in 'DefaultPassword', 'AutoAdminLogon', 'AutoLogonCount') {
    Remove-ItemProperty -Path $w -Name $n -ErrorAction SilentlyContinue
  }
  Stop-Transcript | Out-Null
}
