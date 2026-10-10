# Run over SSH as the fixture administrator, from `windows-template generalize`. It only
# registers and starts a one-shot SYSTEM task and returns, because the task stops sshd (which
# ends this SSH session). The task removes the SSH host keys and the cached install answer
# files (which hold the install-time password), then runs sysprep; the guest powers off.
$ErrorActionPreference = 'Stop'
$answer = 'C:\Windows\System32\Sysprep\sysprep-unattend.xml'
if (-not (Test-Path $answer)) { throw "$answer missing (the builder copies it before running this)" }
$worker = 'C:\Windows\Temp\fleet\generalize-worker.ps1'
@'
Start-Sleep -Seconds 5
# sysprep /generalize refuses to run while BitLocker is on: wait for any decryption to end.
manage-bde.exe -off C: | Out-Null
for ($i = 0; $i -lt 360; $i++) {
  if ((manage-bde.exe -status C: | Out-String) -match 'Fully Decrypted') { break }
  Start-Sleep -Seconds 10
}
Stop-Service sshd -Force
Get-ChildItem 'C:\ProgramData\ssh' -Filter 'ssh_host_*' -Force | Remove-Item -Force
foreach ($f in 'C:\Windows\Panther\unattend.xml', 'C:\Windows\Panther\autounattend.xml',
               'C:\Windows\Panther\Unattend\unattend.xml', 'C:\Windows\System32\Sysprep\unattend.xml',
               'C:\unattend.xml', 'C:\autounattend.xml') {
  Remove-Item $f -Force -ErrorAction SilentlyContinue
}
Remove-Item 'C:\ProgramData\fleet\setup-guest.log', 'C:\ProgramData\fleet\setup-complete' -Force -ErrorAction SilentlyContinue
& 'C:\Windows\System32\Sysprep\sysprep.exe' /generalize /oobe /shutdown '/unattend:C:\Windows\System32\Sysprep\sysprep-unattend.xml'
'@ | Set-Content -Path $worker -Encoding ascii
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File $worker"
Register-ScheduledTask -TaskName 'FleetGeneralize' -Action $action -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'FleetGeneralize'
'sysprep task started'
