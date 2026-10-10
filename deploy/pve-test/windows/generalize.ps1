# Run over SSH as the fixture administrator, from `windows-template generalize`. It only
# registers and starts a one-shot SYSTEM task and returns, because the task stops sshd (which
# ends this SSH session). The task removes the SSH host keys and the cached install answer
# files (which hold the install-time password), then runs sysprep; the guest powers off.
$ErrorActionPreference = 'Stop'
$answer = 'C:\Windows\System32\Sysprep\sysprep-unattend.xml'
if (-not (Test-Path $answer)) { throw "$answer missing (the builder copies it before running this)" }
$worker = 'C:\Windows\Temp\fleet\generalize-worker.ps1'
@'
$ErrorActionPreference = 'Stop'
$log = 'C:\Windows\Temp\fleet\generalize.log'
function Log($m) { "$(Get-Date -Format o) $m" | Add-Content -Path $log }
try {
  Start-Sleep -Seconds 5
  # sysprep /generalize refuses to run while BitLocker is on. VolumeStatus is an enum, so
  # the check does not depend on the display language. Wait at most 8 minutes (the host
  # side waits 20) and fail loudly instead of running sysprep anyway. sshd is still up
  # here, so the log can be read over SSH.
  $v = Get-BitLockerVolume -MountPoint 'C:'
  Log "BitLocker volume status: $($v.VolumeStatus)"
  if ($v.VolumeStatus -ne 'FullyDecrypted') { Disable-BitLocker -MountPoint 'C:' | Out-Null }
  for ($i = 0; $i -lt 48; $i++) {
    $v = Get-BitLockerVolume -MountPoint 'C:'
    if ($v.VolumeStatus -eq 'FullyDecrypted') { break }
    Start-Sleep -Seconds 10
  }
  if ($v.VolumeStatus -ne 'FullyDecrypted') { throw "BitLocker still $($v.VolumeStatus) ($($v.EncryptionPercentage)%) after 8 minutes" }
  Log 'BitLocker is off; removing SSH host keys and cached answer files, then sysprep'
  Stop-Service sshd -Force
  Get-ChildItem 'C:\ProgramData\ssh' -Filter 'ssh_host_*' -Force | Remove-Item -Force
  foreach ($f in 'C:\Windows\Panther\unattend.xml', 'C:\Windows\Panther\autounattend.xml',
                 'C:\Windows\Panther\Unattend\unattend.xml', 'C:\Windows\System32\Sysprep\unattend.xml',
                 'C:\unattend.xml', 'C:\autounattend.xml') {
    Remove-Item $f -Force -ErrorAction SilentlyContinue
  }
  Remove-Item 'C:\ProgramData\fleet\setup-guest.log', 'C:\ProgramData\fleet\setup-complete' -Force -ErrorAction SilentlyContinue
  & 'C:\Windows\System32\Sysprep\sysprep.exe' /generalize /oobe /shutdown '/unattend:C:\Windows\System32\Sysprep\sysprep-unattend.xml'
  Log "sysprep exited with $LASTEXITCODE"
} catch {
  Log "FAILED: $($_.Exception.Message)"
  exit 1
}
'@ | Set-Content -Path $worker -Encoding ascii
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File $worker"
Register-ScheduledTask -TaskName 'FleetGeneralize' -Action $action -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'FleetGeneralize'
'sysprep task started'
