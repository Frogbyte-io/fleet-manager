#ps1
# Cloudbase-Init LocalScripts plugin script, run at every boot after
# SetUserSSHPublicKeysPlugin. That plugin writes the injected key to the user's own
# C:\Users\<user>\.ssh\authorized_keys, but OpenSSH for Windows reads
# C:\ProgramData\ssh\administrators_authorized_keys for members of Administrators, and
# only when its ACL is exactly SYSTEM and Administrators. This copies the keys over.
# Idempotent; without an injected key it leaves the current file alone. The ACL uses SIDs
# (S-1-5-18 SYSTEM, S-1-5-32-544 Administrators), so it does not depend on the language.
$ErrorActionPreference = 'Stop'
$dst = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
$admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { ($_.Name -split '\\')[-1] })
$keys = @()
foreach ($dir in Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue) {
  if ($admins -notcontains $dir.Name) { continue }
  $f = Join-Path $dir.FullName '.ssh\authorized_keys'
  if (Test-Path $f) {
    $keys += Get-Content $f | Where-Object { $_ -match '^\s*(ssh-|ecdsa-|sk-)' } | ForEach-Object { $_.Trim() }
  }
}
if ($keys.Count -eq 0) { Write-Host 'no injected SSH key for an administrator; leaving administrators_authorized_keys alone'; exit 0 }
New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
[IO.File]::WriteAllText($dst, (($keys | Select-Object -Unique) -join "`n") + "`n", (New-Object Text.UTF8Encoding $false))
icacls.exe $dst /inheritance:r /grant '*S-1-5-18:F' /grant '*S-1-5-32-544:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed: $LASTEXITCODE" }
Write-Host "wrote $($keys.Count) key(s) to administrators_authorized_keys"
