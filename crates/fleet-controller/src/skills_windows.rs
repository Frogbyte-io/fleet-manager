//! The Windows twins of the Skills Manager scripts (#609, ADR 0021).
//!
//! Each script here is fixed Windows PowerShell 5.1 text run through the
//! SSH provider's PowerShell bootstrap: caller values arrive as `$args` and
//! environment variables from the metadata blob, never as PowerShell text.
//! Every script answers in the same protocol as its Bash twin in
//! [`crate::skills`] (the same JSON lines, the same exit codes), so the
//! version gate, the probe normalization and every public reason are shared
//! between Linux and Windows.
//!
//! Windows rules (ADR 0021 decisions 3, 8 and 9):
//!
//! - **Fleet-owned per-user paths.** The managed CLI is
//!   `%LOCALAPPDATA%\fleet\bin\skills-manager-cli.exe`; catalog rollouts
//!   stage under `%LOCALAPPDATA%\fleet\skills\<name>`. Each Fleet directory
//!   is created with a protected ACL (the user, SYSTEM, Administrators) and
//!   checked on every use: a real directory, not a reparse point, owned by
//!   one of the three, with no other write grant. A managed CLI in a
//!   directory that fails the check is never run.
//! - **The CLI** is the managed copy, then `skills-manager-cli.exe` on
//!   `PATH` (an `.exe` only: a `.cmd` or `.bat` is never run). Fleet does
//!   not change `PATH`.
//! - **Install** downloads with the in-box `curl.exe` (bounded at 120
//!   seconds), stages beside the destination, checks the pinned SHA-256
//!   with `Get-FileHash`, runs `--version` before placing (a binary that is
//!   blocked or does not run is `binary_unusable`, never left in place), and
//!   moves it with no replace.
//! - **Native arguments.** Windows PowerShell 5.1 builds a native command
//!   line itself and does not escape embedded quotes, so every caller value
//!   passed to a native program matches a strict grammar, checked by the
//!   executor ([`refusal`]) and again by the script: a value with `"`,
//!   `\`, whitespace or a control character is refused, never escaped.
//! - **Never** reads or writes `%USERPROFILE%\.skills-manager` or
//!   `%APPDATA%\skills-manager`; only the CLI does.
//!
//! On a non-Windows PowerShell (the fixture tests run under `pwsh` on
//! Linux) the ACL part of the directory check is skipped; the reparse-point
//! check still applies.

/// The shared prologue: preferences, helpers, the Fleet paths, the
/// directory check and the CLI resolution. `$fleetCli` is the CLI to run
/// (or `$null`), and `$fleetUntrusted` says a managed copy exists in a
/// directory that failed the check. `PATH` is searched only when there is
/// no rejected managed copy: a `PATH` entry naming the rejected directory
/// would otherwise run the very file the check refused.
const PRELUDE: &str = r##"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$fleetWindows = [Environment]::OSVersion.Platform -eq 'Win32NT'
function fleetB64([string]$text) { return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text)) }
function fleetOut([string]$line) { [Console]::Out.Write($line + "`n") }
# `ssh` keeps only the low 8 bits of the exit status, so a failure whose low
# byte is 0 exits 1 instead of reading as success (as the bootstrap does).
function fleetExit([int]$code) { if ($code -ne 0 -and ($code -band 255) -eq 0) { $code = 1 }; exit $code }
function fleetFail([int]$code, [string]$message) { [Console]::Error.WriteLine($message); fleetExit $code }
# Runs a native program ($args[0]) with the remaining arguments as an array.
# Its stdout and stderr land in $global:fleetStdout and $global:fleetStderr
# (stderr is collected, not raised: Windows PowerShell 5.1 turns a native
# stderr line into an error record), and its exit code is returned; a program
# that cannot be started answers 255.
function fleetNative {
  $fleetExe = $args[0]
  $fleetRest = @()
  if ($args.Count -gt 1) { $fleetRest = @($args[1..($args.Count - 1)]) }
  $global:fleetStdout = ''
  $global:fleetStderr = ''
  $ErrorActionPreference = 'Continue'
  $global:LASTEXITCODE = 255
  try { $fleetAll = @(& $fleetExe @fleetRest 2>&1) } catch { $global:fleetStderr = 'the program could not be started'; return 255 }
  $fleetO = New-Object Text.StringBuilder
  $fleetE = New-Object Text.StringBuilder
  foreach ($fleetItem in $fleetAll) {
    if ($fleetItem -is [Management.Automation.ErrorRecord]) { [void]$fleetE.Append([string]$fleetItem.Exception.Message + "`n") }
    else { [void]$fleetO.Append([string]$fleetItem + "`n") }
  }
  $global:fleetStdout = $fleetO.ToString().TrimEnd()
  $global:fleetStderr = $fleetE.ToString().TrimEnd()
  if ($null -eq $global:LASTEXITCODE) { return 255 }
  return [int]$global:LASTEXITCODE
}
$fleetTrusted = @()
if ($fleetWindows) {
  $fleetTrusted = @(
    (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'),
    (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'),
    [Security.Principal.WindowsIdentity]::GetCurrent().User
  )
}
function fleetIn($sid, $list) { foreach ($t in $list) { if ($t.Equals($sid)) { return $true } }; return $false }
# A Fleet directory is usable only when it is a real directory (not a
# reparse point), owned by the user, SYSTEM or Administrators, and grants
# write-class access (including GENERIC_ALL and GENERIC_WRITE) to nobody else.
function fleetSecureDir([string]$path) {
  try {
    $info = New-Object IO.DirectoryInfo $path
    if (-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    if (-not $fleetWindows) { return $true }
    $acl = $info.GetAccessControl()
    if (-not (fleetIn ($acl.GetOwner([Security.Principal.SecurityIdentifier])) $fleetTrusted)) { return $false }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -eq 'Allow' -and ((([int64]$rule.FileSystemRights) -band [int64]0x500D0156) -ne 0) -and -not (fleetIn $rule.IdentityReference $fleetTrusted)) { return $false }
    }
    return $true
  } catch { return $false }
}
# Creates a Fleet directory with a protected ACL when it is absent, then
# checks it: one someone else created first fails the check.
function fleetMakeDir([string]$path) {
  if (-not [IO.Directory]::Exists($path) -and -not [IO.File]::Exists($path)) {
    try {
      if ($fleetWindows) {
        $sec = New-Object Security.AccessControl.DirectorySecurity
        $sec.SetAccessRuleProtection($true, $false)
        foreach ($sid in $fleetTrusted) {
          $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        [void][IO.Directory]::CreateDirectory($path, $sec)
      } else {
        [void][IO.Directory]::CreateDirectory($path)
      }
    } catch { }
  }
  return (fleetSecureDir $path)
}
function fleetRegularFile([string]$path) {
  try { $i = New-Object IO.FileInfo $path; return ($i.Exists -and -not ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)) } catch { return $false }
}
$fleetRoot = $null
$fleetBin = $null
$fleetManaged = $null
if ($env:LOCALAPPDATA) {
  $fleetRoot = [IO.Path]::Combine($env:LOCALAPPDATA, 'fleet')
  $fleetBin = [IO.Path]::Combine($fleetRoot, 'bin')
  $fleetManaged = [IO.Path]::Combine($fleetBin, 'skills-manager-cli.exe')
}
$fleetCli = $null
$fleetUntrusted = $false
if ($fleetManaged -and ([IO.File]::Exists($fleetManaged) -or [IO.Directory]::Exists($fleetManaged))) {
  if ((fleetSecureDir $fleetRoot) -and (fleetSecureDir $fleetBin) -and (fleetRegularFile $fleetManaged)) { $fleetCli = $fleetManaged }
  else { $fleetUntrusted = $true }
}
if (-not $fleetCli -and -not $fleetUntrusted) {
  $fleetFound = @(Get-Command -Name 'skills-manager-cli' -CommandType Application -ErrorAction SilentlyContinue | Where-Object { -not $fleetWindows -or [IO.Path]::GetExtension($_.Path) -eq '.exe' })
  if ($fleetFound.Count -gt 0) { $fleetCli = $fleetFound[0].Path }
}
$fleetAgentGrammar = '^[a-z0-9][a-z0-9_-]{0,63}\z'
$fleetNameGrammar = '^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?\z'
$fleetRefGrammar = '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}\z'
$fleetTokenGrammar = '^[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{0,2047}\z'
"##;

/// The version gate: `{"present":false}` or `{"version64":"…"}`, as the
/// Bash gate answers.
const GATE_BODY: &str = r##"if (-not $fleetCli) { fleetOut '{"present":false}'; exit 0 }
[void](fleetNative $fleetCli '--version')
$fleetVersion = ''
if ($global:fleetStdout) { $fleetVersion = $global:fleetStdout.Split("`n")[0].Trim() }
fleetOut ('{"version64":"' + (fleetB64 $fleetVersion) + '"}')
"##;

/// The probe and pinned install. `FLEET_PIN_URL` and `FLEET_PIN_SHA256`
/// carry the pin; an external skills root (`$args[0]`) is refused because
/// the executor never sends one to Windows.
const PROBE_BODY: &str = r##"function fleetEmitFailure([string]$why) { fleetOut ('{"installFailed":"' + $why + '"}'); exit 0 }
if ($args.Count -gt 0) { fleetFail 2 'an external skills root is not supported on Windows endpoints' }
if (-not $fleetCli -and $env:FLEET_PIN_URL -and $env:FLEET_PIN_SHA256) {
  $fleetUrl = $env:FLEET_PIN_URL
  $fleetSha = $env:FLEET_PIN_SHA256
  if ($fleetUrl -cnotmatch $fleetTokenGrammar -or $fleetSha -cnotmatch '^[0-9A-Fa-f]{64}\z' -or -not $fleetRoot) { fleetEmitFailure 'install_failed' }
  if (-not (fleetMakeDir $fleetRoot) -or -not (fleetMakeDir $fleetBin)) { fleetEmitFailure 'directory_untrusted' }
  # Staged beside the destination, with an .exe name so Windows runs it for
  # the check below; every path out of here removes it.
  $fleetTmp = [IO.Path]::Combine($fleetBin, '.skills-manager-cli.fleet-tmp.' + $PID + '.exe')
  $fleetFailure = $null
  try {
    if ([IO.File]::Exists($fleetTmp)) { [IO.File]::Delete($fleetTmp) }
    $fleetCurl = 'curl'
    if ($fleetWindows) { $fleetCurl = [IO.Path]::Combine([Environment]::GetFolderPath('System'), 'curl.exe') }
    $fleetCode = fleetNative $fleetCurl '-fsL' '--max-time' '120' '-o' $fleetTmp $fleetUrl
    if ($fleetCode -ne 0 -or -not (fleetRegularFile $fleetTmp)) { $fleetFailure = 'download_failed' }
    if (-not $fleetFailure) {
      $fleetDigest = (Get-FileHash -LiteralPath $fleetTmp -Algorithm SHA256).Hash.ToLowerInvariant()
      if ($fleetDigest -cne $fleetSha.ToLowerInvariant()) { $fleetFailure = 'checksum_mismatch' }
    }
    if (-not $fleetFailure -and -not $fleetWindows) {
      if ((fleetNative 'chmod' '700' $fleetTmp) -ne 0) { $fleetFailure = 'install_failed' }
    }
    # A verified binary that does not run here (Smart App Control, an
    # antivirus quarantine) is never placed.
    if (-not $fleetFailure -and (fleetNative $fleetTmp '--version') -ne 0) { $fleetFailure = 'binary_unusable' }
    if (-not $fleetFailure) {
      if ([IO.File]::Exists($fleetManaged) -or [IO.Directory]::Exists($fleetManaged)) { $fleetFailure = 'install_failed' }
      else { [IO.File]::Move($fleetTmp, $fleetManaged) }
    }
  } catch { if (-not $fleetFailure) { $fleetFailure = 'install_failed' } }
  try { if ([IO.File]::Exists($fleetTmp)) { [IO.File]::Delete($fleetTmp) } } catch { }
  if ($fleetFailure) { fleetEmitFailure $fleetFailure }
  $fleetCli = $fleetManaged
}
if (-not $fleetCli) { fleetOut '{"present":false}'; exit 0 }
[void](fleetNative $fleetCli '--version')
$fleetVersionOutput = ''
if ($global:fleetStdout) { $fleetVersionOutput = $global:fleetStdout.Split("`n")[0].Trim() }
if (-not $fleetVersionOutput) { fleetOut '{"present":true,"unidentified":true}'; exit 0 }
$fleetVersion = $fleetVersionOutput
if ($fleetVersionOutput.StartsWith('{')) {
  $fleetVersion = ''
  if ($fleetVersionOutput -match '"version"\s*:\s*"([^"]*)"') { $fleetVersion = $Matches[1] }
}
if (-not $fleetVersion) { fleetOut '{"present":true,"unidentified":true}'; exit 0 }
if ($fleetVersion -ceq 'skills-manager-cli __TESTED__' -or $fleetVersion -ceq '__TESTED__') { $fleetVersion = '__TESTED__' }
else { fleetOut ('{"present":true,"version64":"' + (fleetB64 $fleetVersion) + '","unsupportedVersion":true}'); exit 0 }
$fleetVersion64 = fleetB64 $fleetVersion
# One bounded upstream document: 0 with the text, 1 when the command
# failed, 2 when the document is over its bound.
function fleetCollect {
  $fleetMax = [int]$args[0]
  $fleetCmd = @('--json') + @($args[1..($args.Count - 1)])
  if ((fleetNative $fleetCli @fleetCmd) -ne 0) { return @(1, '') }
  if ([Text.Encoding]::UTF8.GetByteCount($global:fleetStdout) -gt $fleetMax) { return @(2, '') }
  return @(0, $global:fleetStdout)
}
$fleetAgents = fleetCollect 65536 'agents' 'list'
$fleetSkills = fleetCollect 393216 'skills' 'list'
$fleetPresets = fleetCollect 65536 'presets' 'list'
$fleetChecks = fleetCollect 196608 'skills' 'check' '--all'
if ($fleetAgents[0] -eq 2 -or $fleetSkills[0] -eq 2 -or $fleetPresets[0] -eq 2 -or $fleetChecks[0] -eq 2) {
  fleetOut ('{"present":true,"version64":"' + $fleetVersion64 + '","inventoryTooLarge":true}')
  exit 0
}
function fleetDoc($pair) { if ($pair[1]) { return (fleetB64 $pair[1]) }; return (fleetB64 '[]') }
function fleetFailed($pair) { if ($pair[0] -eq 0) { return 'false' }; return 'true' }
fleetOut ('{"present":true,"version64":"' + $fleetVersion64 + '","agents64":"' + (fleetDoc $fleetAgents) + '","skills64":"' + (fleetDoc $fleetSkills) + '","presets64":"' + (fleetDoc $fleetPresets) + '","checks64":"' + (fleetDoc $fleetChecks) + '","agentsFailed":' + (fleetFailed $fleetAgents) + ',"skillsFailed":' + (fleetFailed $fleetSkills) + ',"presetsFailed":' + (fleetFailed $fleetPresets) + ',"updateCheckFailed":' + (fleetFailed $fleetChecks) + '}')
"##;

/// Deploy or undeploy: `$args[0]` is the skill reference, the rest are
/// agent ids; the CLI's stdout and stderr are passed through.
const MUTATION_BODY: &str = r##"if (-not $fleetCli) { fleetFail 3 'skills-manager-cli is not installed' }
if ($env:FLEET_SKILLS_ROOT) { fleetFail 2 'an external skills root is not supported on Windows endpoints' }
if ($args.Count -lt 1 -or [string]$args[0] -cnotmatch $fleetRefGrammar) { fleetFail 2 'invalid skill reference' }
$fleetCmd = @('--json', 'skills', '__VERB__', [string]$args[0])
for ($i = 1; $i -lt $args.Count; $i++) {
  if ([string]$args[$i] -cnotmatch $fleetAgentGrammar) { fleetFail 2 'invalid agent id' }
  $fleetCmd += @('--agent', [string]$args[$i])
}
__DRY__$fleetCode = fleetNative $fleetCli @fleetCmd
if ($global:fleetStdout) { fleetOut $global:fleetStdout }
if ($global:fleetStderr) { [Console]::Error.WriteLine($global:fleetStderr) }
fleetExit $fleetCode
"##;

/// The inline catalog rollout: `$args` are the name, the content digest,
/// the file count, then (path, base64, sha256) per file, then the agent
/// count and the agents. Stages under `%LOCALAPPDATA%\fleet\skills\<name>`,
/// keeps a backup of the previous staging until the CLI has installed,
/// deployed and verified the new one, and restores it on any failure.
const CATALOG_ROLLOUT_BODY: &str = r##"$fleetName = [string]$args[0]
$fleetDigest = [string]$args[1]
$fleetCount = [string]$args[2]
if ($fleetName -cnotmatch $fleetNameGrammar) { fleetFail 2 'invalid skill name' }
if ($fleetDigest -cnotmatch '^[A-Za-z0-9:_.-]{1,160}\z') { fleetFail 2 'invalid version digest' }
if ($fleetCount -cnotmatch '^[0-9]{1,4}\z') { fleetFail 2 'invalid staged file list' }
$fleetCount = [int]$fleetCount
# A staged path is relative, `/`-separated, and every component is a name
# Windows can hold as written: no `..` or `.`, no drive or stream colon, no
# backslash, no reserved device name, no trailing dot or space.
function fleetSafeRelative([string]$rel) {
  if (-not $rel -or $rel.Length -gt 400) { return $false }
  foreach ($part in $rel.Split('/')) {
    if ($part -eq '' -or $part -eq '.' -or $part -eq '..') { return $false }
    if ($part -match '[\x00-\x1f<>:"|?*\\]') { return $false }
    if ($part.EndsWith('.') -or $part.EndsWith(' ')) { return $false }
    if ($part -match '^(?i:con|prn|aux|nul|conin\$|conout\$|com[0-9¹²³]|lpt[0-9¹²³])(?:\..*)?\z') { return $false }
  }
  return $true
}
$fleetFiles = @()
$i = 3
for ($n = 0; $n -lt $fleetCount; $n++) {
  if ($i + 2 -ge $args.Count) { fleetFail 2 'invalid staged file list' }
  $fleetRel = [string]$args[$i]
  if (-not (fleetSafeRelative $fleetRel)) { fleetFail 2 'invalid staged path' }
  if ([string]$args[$i + 2] -cnotmatch '^[0-9a-f]{64}\z') { fleetFail 2 'invalid staged file digest' }
  $fleetFiles += ,@($fleetRel, [string]$args[$i + 1], [string]$args[$i + 2])
  $i += 3
}
if ($i -ge $args.Count -or [string]$args[$i] -cnotmatch '^[0-9]{1,2}\z') { fleetFail 2 'invalid explicit agent list' }
$fleetAgentCount = [int][string]$args[$i]
$i++
if ($args.Count - $i -ne $fleetAgentCount -or $fleetAgentCount -lt 1) { fleetFail 2 'invalid explicit agent list' }
$fleetAgentArgs = @()
for (; $i -lt $args.Count; $i++) {
  if ([string]$args[$i] -cnotmatch $fleetAgentGrammar) { fleetFail 2 'invalid agent id' }
  $fleetAgentArgs += @('--agent', [string]$args[$i])
}
if (-not $fleetRoot) { fleetFail 2 'LOCALAPPDATA is not set for the SSH login' }
$fleetParent = [IO.Path]::Combine($fleetRoot, 'skills')
if (-not (fleetMakeDir $fleetRoot) -or -not (fleetMakeDir $fleetParent)) { fleetFail 2 'Fleet staging path must be a private Fleet directory and must not be a reparse point' }
$fleetTarget = [IO.Path]::Combine($fleetParent, $fleetName)
if ([IO.File]::Exists($fleetTarget) -or ([IO.Directory]::Exists($fleetTarget) -and -not (fleetSecureDir $fleetTarget))) { fleetFail 2 'Fleet staging target must be a private directory and must not be a reparse point' }
$fleetTmp = [IO.Path]::Combine($fleetParent, '.' + $fleetName + '.staging.' + $PID)
$fleetBackup = [IO.Path]::Combine($fleetParent, '.' + $fleetName + '.backup.' + $PID)
foreach ($fleetPath in @($fleetTmp, $fleetBackup)) {
  if ([IO.File]::Exists($fleetPath) -or [IO.Directory]::Exists($fleetPath)) { fleetFail 2 'Fleet staging temporary path already exists' }
}
$fleetCommitted = $false
$fleetStaged = $false
try {
  # Inherits the parent's protected ACL.
  [void][IO.Directory]::CreateDirectory($fleetTmp)
  $fleetTmpFull = [IO.Path]::GetFullPath($fleetTmp) + [IO.Path]::DirectorySeparatorChar
  foreach ($fleetEntry in $fleetFiles) {
    $fleetFile = $fleetTmp
    foreach ($fleetPart in $fleetEntry[0].Split('/')) { $fleetFile = [IO.Path]::Combine($fleetFile, $fleetPart) }
    if (-not [IO.Path]::GetFullPath($fleetFile).StartsWith($fleetTmpFull, [StringComparison]::OrdinalIgnoreCase)) { fleetFail 2 'invalid staged path' }
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($fleetFile))
    try { $fleetBytes = [Convert]::FromBase64String($fleetEntry[1]) } catch { fleetFail 2 'invalid staged file content' }
    [IO.File]::WriteAllBytes($fleetFile, $fleetBytes)
    $fleetActual = (Get-FileHash -LiteralPath $fleetFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($fleetActual -cne $fleetEntry[2]) { fleetFail 2 'staged file digest mismatch' }
  }
  if (-not $fleetCli) { fleetFail 3 'skills-manager-cli is not installed' }
  if ([IO.Directory]::Exists($fleetTarget)) { [IO.Directory]::Move($fleetTarget, $fleetBackup) }
  [IO.Directory]::Move($fleetTmp, $fleetTarget)
  $fleetStaged = $true
  if ((fleetNative $fleetCli '--json' 'skills' 'show' $fleetName) -eq 0) {
    $fleetCode = fleetNative $fleetCli '--json' 'skills' 'update' $fleetName
    if ($global:fleetStdout.Contains('held_back_removals')) { fleetOut $global:fleetStdout; fleetFail 4 'update held back removals; inspect the Skills Manager result' }
    if ($fleetCode -ne 0) { if ($global:fleetStdout) { fleetOut $global:fleetStdout }; fleetFail $fleetCode $global:fleetStderr }
  } else {
    $fleetCode = fleetNative $fleetCli '--json' 'skills' 'install' $fleetTarget '--local'
    if ($fleetCode -ne 0) { if ($global:fleetStdout) { fleetOut $global:fleetStdout }; fleetFail $fleetCode $global:fleetStderr }
  }
  $fleetCmd = @('--json', 'skills', 'deploy', $fleetName) + $fleetAgentArgs
  $fleetCode = fleetNative $fleetCli @fleetCmd
  if ($fleetCode -ne 0) { if ($global:fleetStdout) { fleetOut $global:fleetStdout }; fleetFail $fleetCode $global:fleetStderr }
  $fleetCode = fleetNative $fleetCli '--json' 'skills' 'show' $fleetName
  if ($fleetCode -ne 0) { fleetFail $fleetCode $global:fleetStderr }
  $fleetCode = fleetNative $fleetCli '--json' 'skills' 'status' $fleetName
  if ($fleetCode -ne 0) { fleetFail $fleetCode $global:fleetStderr }
  $fleetCommitted = $true
} finally {
  # A failure restores the previous staging, or removes the one this run
  # created when there was none (the CLI keeps its own copy of an
  # installed skill; the next rollout stages this path again).
  if (-not $fleetCommitted) {
    try {
      if ([IO.Directory]::Exists($fleetBackup)) {
        if ([IO.Directory]::Exists($fleetTarget)) { [IO.Directory]::Delete($fleetTarget, $true) }
        [IO.Directory]::Move($fleetBackup, $fleetTarget)
      } elseif ($fleetStaged -and [IO.Directory]::Exists($fleetTarget)) {
        [IO.Directory]::Delete($fleetTarget, $true)
      }
    } catch { }
  }
  try { if ([IO.Directory]::Exists($fleetTmp)) { [IO.Directory]::Delete($fleetTmp, $true) } } catch { }
}
try { if ([IO.Directory]::Exists($fleetBackup)) { [IO.Directory]::Delete($fleetBackup, $true) } } catch { }
fleetOut ('{"versionDigest":"' + $fleetDigest + '","verified":true}')
"##;

/// The referenced catalog rollout: `$args` are the name, the install
/// reference, `true`/`false` for a Git source, the agent count and the
/// agents. Prints the CLI's `skills show` record last, which the executor
/// verifies against the pinned revision.
const REFERENCED_ROLLOUT_BODY: &str = r##"$fleetName = [string]$args[0]
$fleetReference = [string]$args[1]
$fleetGit = [string]$args[2]
$fleetAgentCount = [string]$args[3]
if ($fleetName -cnotmatch $fleetNameGrammar) { fleetFail 2 'invalid skill name' }
if ($fleetReference -cnotmatch $fleetTokenGrammar) { fleetFail 2 'invalid skill source reference' }
if ($fleetGit -cne 'true' -and $fleetGit -cne 'false') { fleetFail 2 'invalid source kind' }
if ($fleetAgentCount -cnotmatch '^[0-9]{1,2}\z' -or $args.Count - 4 -ne [int]$fleetAgentCount -or [int]$fleetAgentCount -lt 1) { fleetFail 2 'invalid explicit agent list' }
$fleetAgentArgs = @()
for ($i = 4; $i -lt $args.Count; $i++) {
  if ([string]$args[$i] -cnotmatch $fleetAgentGrammar) { fleetFail 2 'invalid agent id' }
  $fleetAgentArgs += @('--agent', [string]$args[$i])
}
if (-not $fleetCli) { fleetFail 3 'skills-manager-cli is not installed' }
# Runs one CLI command; on failure prints its stdout and stderr and exits
# with its code, on success prints nothing.
function fleetSilent {
  $fleetCmd = @('--json') + @($args)
  $fleetCode = fleetNative $fleetCli @fleetCmd
  if ($fleetCode -ne 0) {
    if ($global:fleetStdout) { fleetOut $global:fleetStdout }
    fleetFail $fleetCode $global:fleetStderr
  }
}
if ((fleetNative $fleetCli '--json' 'skills' 'show' $fleetName) -ne 0) {
  $fleetInstall = @('skills', 'install', $fleetReference, '--name', $fleetName)
  if ($fleetGit -ceq 'true') { $fleetInstall += '--git' }
  fleetSilent @fleetInstall
} elseif ($fleetGit -ceq 'true') {
  fleetSilent 'skills' 'set-source' $fleetName '--git-url' $fleetReference '--force'
} else {
  $fleetExisting = $null
  try { $fleetExisting = ConvertFrom-Json -InputObject $global:fleetStdout } catch { }
  if ($null -ne $fleetExisting -and [string]$fleetExisting.source_ref -ceq $fleetReference) {
    fleetSilent 'skills' 'update' $fleetName
  } else {
    fleetFail 4 'the existing skill uses a different non-Git source; refusing to remove and reinstall it'
  }
}
$fleetDeploy = @('skills', 'deploy', $fleetName) + $fleetAgentArgs
fleetSilent @fleetDeploy
$fleetCode = fleetNative $fleetCli '--json' 'skills' 'show' $fleetName
if ($fleetCode -ne 0) { fleetFail $fleetCode $global:fleetStderr }
$fleetShow = $global:fleetStdout
fleetSilent 'skills' 'status' $fleetName
fleetOut $fleetShow
"##;

fn script(body: &str) -> String {
    format!("{PRELUDE}{body}")
}

/// The Windows version gate.
#[must_use]
pub(crate) fn gate_script() -> String {
    script(GATE_BODY)
}

/// The Windows probe and pinned install.
#[must_use]
pub(crate) fn probe_script() -> String {
    script(&PROBE_BODY.replace("__TESTED__", crate::skills::TESTED_CLI_VERSION))
}

/// The Windows deploy (`verb` = `deploy`) or undeploy (`undeploy`). The
/// v1.40.0 CLI takes each agent as `--agent <id>` and has no `--yes` on
/// either verb.
#[must_use]
pub(crate) fn mutation_script(verb: &str, dry_run: bool) -> String {
    let verb = if verb == "undeploy" {
        "undeploy"
    } else {
        "deploy"
    };
    let dry = if dry_run {
        "$fleetCmd += '--dry-run'\n"
    } else {
        ""
    };
    script(
        &MUTATION_BODY
            .replace("__VERB__", verb)
            .replace("__DRY__", dry),
    )
}

/// The Windows inline catalog rollout.
#[must_use]
pub(crate) fn catalog_rollout_script() -> String {
    script(CATALOG_ROLLOUT_BODY)
}

/// The Windows referenced catalog rollout.
#[must_use]
pub(crate) fn referenced_rollout_script() -> String {
    script(REFERENCED_ROLLOUT_BODY)
}

/// An agent id the scripts pass to the CLI: `[a-z0-9][a-z0-9_-]{0,63}`
/// (Skills Manager's agent keys are lowercase snake case).
#[must_use]
pub fn is_agent_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// A catalog skill name: `[a-z0-9-]`, no leading or trailing dash, at most
/// 128 characters.
#[must_use]
pub fn is_skill_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

/// A skill reference for deploy and undeploy (an id, name or directory
/// name): `[A-Za-z0-9][A-Za-z0-9._-]{0,254}`.
#[must_use]
pub fn is_skill_reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=255).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A URL or source reference passed to a native program: URL characters
/// only (no quote, backslash, backtick, whitespace or control character),
/// starting with a letter or digit, at most 2048 characters.
#[must_use]
pub fn is_native_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=2048).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'_'
                        | b'~'
                        | b':'
                        | b'/'
                        | b'?'
                        | b'#'
                        | b'['
                        | b']'
                        | b'@'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b'%'
                        | b'-'
                )
        })
}

/// Why a value cannot be passed to a native program on a Windows endpoint,
/// or `None` when it can. `what` names the value in the reason.
#[must_use]
pub fn refusal(what: &str, value: &str, accepts: fn(&str) -> bool) -> Option<String> {
    (!accepts(value)).then(|| {
        format!(
            "{what} cannot be passed to a native program on a Windows endpoint: it must match Fleet's strict grammar (ADR 0021 decision 3)"
        )
    })
}

#[cfg(test)]
mod tests {
    //! Fixture tests: each script runs through the real PowerShell bootstrap
    //! (the command string and stdin framing a Windows login receives) under
    //! `pwsh`, against a fake `skills-manager-cli.exe`. CI sets
    //! `FLEET_PWSH` and `FLEET_REQUIRE_PWSH`, so a missing PowerShell fails
    //! there instead of skipping.

    use std::io::Write as _;
    use std::path::{Path, PathBuf};

    use base64::Engine as _;
    use fleet_provider_ssh::ScriptMetadata;

    use super::*;

    fn pwsh() -> Option<String> {
        let candidate = std::env::var("FLEET_PWSH").unwrap_or_else(|_| "pwsh".to_owned());
        let found = fleet_provider_ssh::pwsh_starts(&candidate)
            .map_err(|why| eprintln!("no working PowerShell: {why}"))
            .ok()
            .map(|()| candidate);
        assert!(
            found.is_some() || std::env::var_os("FLEET_REQUIRE_PWSH").is_none(),
            "FLEET_REQUIRE_PWSH is set but no PowerShell was found"
        );
        if found.is_none() {
            eprintln!("SKIPPED: no working PowerShell (pwsh on PATH, or FLEET_PWSH)");
        }
        found
    }

    fn b64(text: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(text)
    }

    fn unb64(text: &str) -> String {
        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .unwrap(),
        )
        .unwrap()
    }

    fn sha256(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// A fake CLI answering the documented v1.40.0 shapes, logging each
    /// argv (one argument per line, then `--`) for assertions.
    const FAKE_CLI: &str = r#"#!/bin/bash
for a in "$@"; do printf '%s\n' "$a" >> "$FAKE_LOG"; done
printf -- '--\n' >> "$FAKE_LOG"
[ "$1" = "--json" ] && shift
case "$1" in
  --version) [ -n "${FAKE_UNUSABLE:-}" ] && exit 1; printf '%s\n' "${FAKE_VERSION:-skills-manager-cli 1.40.0}"; exit 0 ;;
  agents) echo '[{"id":"claude_code","name":"Claude Code","installed":true,"enabled":true}]'; exit 0 ;;
  presets) echo '[{"id":"default","name":"Default","skill_count":1,"active":true}]'; exit 0 ;;
esac
case "$2" in
  list)
    if [ -n "${FAKE_HUGE:-}" ]; then head -c 400000 /dev/zero | tr '\0' 'x'; echo; exit 0; fi
    echo '[{"id":"hello","name":"Hello","enabled":true,"preset_ids":["default"],"deployed_to":["claude_code"]}]' ;;
  check) echo '[{"skill_id":"hello","update_status":"update_available"}]' ;;
  show) [ -f "$FAKE_STATE/installed" ] || { echo 'skill not found' >&2; exit 1; }; cat "$FAKE_STATE/show.json" 2>/dev/null || echo '{}' ;;
  install) touch "$FAKE_STATE/installed"; echo '{}' ;;
  update) printf '%s\n' "${FAKE_UPDATE:-{\}}" ;;
  set-source) echo '{}' ;;
  deploy)
    [ -n "${FAKE_FAIL_DEPLOY:-}" ] && { echo '{"ok":false,"code":"DEPLOY_FAILED","message":"deploy refused"}'; echo 'deploy refused' >&2; exit 5; }
    echo "{\"skillId\":\"$3\",\"deployedTo\":[\"claude_code\"]}" ;;
  undeploy) echo "{\"skillId\":\"$3\",\"deployedTo\":[]}" ;;
  status) echo '{}' ;;
  *) exit 8 ;;
esac
"#;

    /// A private Windows-like profile: `%LOCALAPPDATA%`, a home, the fake
    /// CLI's state and its argv log.
    struct Guest {
        dir: tempfile::TempDir,
    }

    impl Guest {
        fn new() -> Self {
            let guest = Self {
                dir: tempfile::tempdir().unwrap(),
            };
            for sub in ["local", "home", "state"] {
                std::fs::create_dir_all(guest.dir.path().join(sub)).unwrap();
            }
            guest
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.dir.path().join(relative)
        }

        fn managed(&self) -> PathBuf {
            self.path("local/fleet/bin/skills-manager-cli.exe")
        }

        fn write_executable(path: &Path, text: &str) {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        /// Places the fake as the managed copy.
        fn install_fake(&self) {
            Self::write_executable(&self.managed(), FAKE_CLI);
        }

        /// The argv log, one invocation per entry.
        fn calls(&self) -> Vec<Vec<String>> {
            let log = std::fs::read_to_string(self.path("calls.log")).unwrap_or_default();
            log.split("--\n")
                .filter(|call| !call.is_empty())
                .map(|call| call.lines().map(str::to_owned).collect())
                .collect()
        }

        /// Runs `script` through the real bootstrap with `arguments` and the
        /// metadata `environment`; `process_env` is the login's own
        /// environment (the fake CLI's switches, an extra `PATH` entry).
        fn run(
            &self,
            pwsh: &str,
            script: &str,
            arguments: &[&str],
            environment: &[(&str, &str)],
            process_env: &[(&str, &str)],
        ) -> std::process::Output {
            let metadata = ScriptMetadata {
                working_directory: String::new(),
                environment: environment
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect(),
                arguments: arguments.iter().map(|value| (*value).to_owned()).collect(),
            };
            let input = format!(
                "{}\n{}\n",
                fleet_provider_ssh::encode_metadata(&metadata),
                b64(script)
            );
            let mut command = std::process::Command::new(pwsh);
            command
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    fleet_provider_ssh::shell::POWERSHELL_BOOTSTRAP,
                ])
                .env_clear()
                .env("HOME", self.path("home"))
                .env("LOCALAPPDATA", self.path("local"))
                .env("PATH", "/usr/bin:/bin")
                .env("POWERSHELL_TELEMETRY_OPTOUT", "1")
                .env("POWERSHELL_UPDATECHECK", "Off")
                .env("FAKE_LOG", self.path("calls.log"))
                .env("FAKE_STATE", self.path("state"))
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            for (key, value) in process_env {
                command.env(key, value);
            }
            let mut child = command.spawn().unwrap();
            let mut stdin = child.stdin.take().unwrap();
            let writer = std::thread::spawn(move || {
                let _ = stdin.write_all(input.as_bytes());
            });
            let output = child.wait_with_output().unwrap();
            writer.join().unwrap();
            output
        }
    }

    fn stdout_line(output: &std::process::Output) -> serde_json::Value {
        let text = String::from_utf8_lossy(&output.stdout);
        let line = text
            .lines()
            .find(|line| line.starts_with('{'))
            .unwrap_or_else(|| {
                panic!(
                    "no JSON line: {text}\nstderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        serde_json::from_str(line).unwrap()
    }

    fn stderr(output: &std::process::Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    #[test]
    fn the_gate_reports_absence_and_the_version() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        let output = guest.run(&pwsh, &gate_script(), &[], &[], &[]);
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout_line(&output), serde_json::json!({"present": false}));

        guest.install_fake();
        let output = guest.run(
            &pwsh,
            &gate_script(),
            &[],
            &[],
            &[("FAKE_VERSION", r#"{"version":"1.40.0"}"#)],
        );
        assert!(output.status.success(), "{}", stderr(&output));
        let line = stdout_line(&output);
        assert_eq!(
            unb64(line["version64"].as_str().unwrap()),
            r#"{"version":"1.40.0"}"#
        );
    }

    #[test]
    fn the_probe_answers_the_bash_protocol_and_normalizes() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        guest.install_fake();
        let output = guest.run(&pwsh, &probe_script(), &[], &[], &[]);
        assert!(output.status.success(), "{}", stderr(&output));
        let line = stdout_line(&output);
        assert_eq!(line["present"], true);
        assert_eq!(unb64(line["version64"].as_str().unwrap()), "1.40.0");
        for flag in [
            "agentsFailed",
            "skillsFailed",
            "presetsFailed",
            "updateCheckFailed",
        ] {
            assert_eq!(line[flag], false, "{flag}");
        }
        // The same normalization as Linux.
        let snapshot = crate::skills::normalize_probe("m-1", &line).unwrap();
        assert!(matches!(
            snapshot.availability,
            fleet_application::skills::SkillsAvailability::Available
        ));
        assert_eq!(snapshot.cli_version.as_deref(), Some("1.40.0"));
        assert_eq!(snapshot.data["skills"][0]["id"], "hello");
        assert_eq!(snapshot.data["skills"][0]["deployedTo"][0], "claude_code");
        assert_eq!(
            snapshot.data["skills"][0]["updateStatus"],
            "update_available"
        );
        assert_eq!(snapshot.data["agents"][0]["id"], "claude_code");
        // The probe only ever calls the CLI; every call is `--json` or
        // `--version`.
        let calls = guest.calls();
        assert_eq!(calls[0], ["--version"]);
        assert!(
            calls[1..].iter().all(|call| call[0] == "--json"),
            "{calls:?}"
        );
        assert!(calls.contains(&vec![
            "--json".to_owned(),
            "skills".to_owned(),
            "check".to_owned(),
            "--all".to_owned()
        ]));
    }

    #[test]
    fn the_probe_degrades_absent_unidentified_unsupported_and_too_large() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        let output = guest.run(&pwsh, &probe_script(), &[], &[], &[]);
        assert_eq!(stdout_line(&output), serde_json::json!({"present": false}));

        guest.install_fake();
        let output = guest.run(
            &pwsh,
            &probe_script(),
            &[],
            &[],
            &[("FAKE_VERSION", "skills-manager-cli 2.0.0")],
        );
        let line = stdout_line(&output);
        assert_eq!(line["unsupportedVersion"], true);
        assert_eq!(
            unb64(line["version64"].as_str().unwrap()),
            "skills-manager-cli 2.0.0"
        );

        let output = guest.run(
            &pwsh,
            &probe_script(),
            &[],
            &[],
            &[("FAKE_VERSION", r#"{"name":"x"}"#)],
        );
        assert_eq!(
            stdout_line(&output),
            serde_json::json!({"present": true, "unidentified": true})
        );

        let output = guest.run(&pwsh, &probe_script(), &[], &[], &[("FAKE_HUGE", "1")]);
        assert_eq!(stdout_line(&output)["inventoryTooLarge"], true);

        // An external root never reaches Windows.
        let output = guest.run(&pwsh, &probe_script(), &["/srv/skills"], &[], &[]);
        assert_eq!(output.status.code(), Some(2));
    }

    /// A pinned artifact served from a `file://` URL (curl reads it like
    /// the release download), and its digest.
    fn artifact(guest: &Guest, text: &str) -> (String, String) {
        let path = guest.path("artifact/skills-manager-cli-Windows-x64.exe");
        Guest::write_executable(&path, text);
        (
            format!("file://{}", path.display()),
            sha256(text.as_bytes()),
        )
    }

    fn no_staging_left(guest: &Guest) -> bool {
        std::fs::read_dir(guest.path("local/fleet/bin"))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .all(|entry| !entry.file_name().to_string_lossy().contains("fleet-tmp"))
            })
            .unwrap_or(true)
    }

    #[test]
    fn a_pinned_install_verifies_runs_and_places_the_binary() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        let (url, digest) = artifact(&guest, FAKE_CLI);
        let pin = [
            ("FLEET_PIN_URL", url.as_str()),
            ("FLEET_PIN_SHA256", digest.as_str()),
        ];
        let output = guest.run(&pwsh, &probe_script(), &[], &pin, &[]);
        assert!(output.status.success(), "{}", stderr(&output));
        let line = stdout_line(&output);
        assert_eq!(line["present"], true, "{line}");
        assert_eq!(
            std::fs::read_to_string(guest.managed()).unwrap(),
            FAKE_CLI,
            "the verified artifact is the managed CLI"
        );
        assert!(no_staging_left(&guest));

        // An installed CLI is never replaced: a second pinned probe with a
        // different artifact leaves it alone.
        let (other_url, other_digest) = artifact(&guest, "#!/bin/bash\nexit 1\n");
        let output = guest.run(
            &pwsh,
            &probe_script(),
            &[],
            &[
                ("FLEET_PIN_URL", other_url.as_str()),
                ("FLEET_PIN_SHA256", other_digest.as_str()),
            ],
            &[],
        );
        assert_eq!(stdout_line(&output)["present"], true);
        assert_eq!(std::fs::read_to_string(guest.managed()).unwrap(), FAKE_CLI);
    }

    #[test]
    fn a_failed_install_names_why_and_places_nothing() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        let (url, digest) = artifact(&guest, FAKE_CLI);
        let missing = format!("file://{}", guest.path("artifact/missing.exe").display());
        let wrong = "0".repeat(64);
        for (url, digest, process_env, reason) in [
            (url.as_str(), wrong.as_str(), &[][..], "checksum_mismatch"),
            (
                missing.as_str(),
                digest.as_str(),
                &[][..],
                "download_failed",
            ),
            (
                url.as_str(),
                digest.as_str(),
                &[("FAKE_UNUSABLE", "1")][..],
                "binary_unusable",
            ),
            // A value outside the native-argument grammar never reaches curl.
            (
                "https://example.invalid/a b",
                digest.as_str(),
                &[][..],
                "install_failed",
            ),
            (
                "https://example.invalid/a\"b",
                digest.as_str(),
                &[][..],
                "install_failed",
            ),
        ] {
            let output = guest.run(
                &pwsh,
                &probe_script(),
                &[],
                &[("FLEET_PIN_URL", url), ("FLEET_PIN_SHA256", digest)],
                process_env,
            );
            assert!(output.status.success(), "{reason}: {}", stderr(&output));
            assert_eq!(
                stdout_line(&output),
                serde_json::json!({"installFailed": reason}),
                "{url}"
            );
            assert!(!guest.managed().exists(), "{reason}: nothing is placed");
            assert!(
                no_staging_left(&guest),
                "{reason}: the staged file is removed"
            );
        }
    }

    #[test]
    fn a_managed_copy_behind_a_reparse_point_is_never_run() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        // `fleet\bin` is a link to a directory someone else controls.
        let elsewhere = guest.path("elsewhere");
        Guest::write_executable(&elsewhere.join("skills-manager-cli.exe"), FAKE_CLI);
        // The name `Get-Command` resolves on Linux, so a PATH lookup could
        // reach the planted copy too.
        Guest::write_executable(&elsewhere.join("skills-manager-cli"), FAKE_CLI);
        std::fs::create_dir_all(guest.path("local/fleet")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, guest.path("local/fleet/bin")).unwrap();

        let output = guest.run(&pwsh, &gate_script(), &[], &[], &[]);
        assert_eq!(stdout_line(&output), serde_json::json!({"present": false}));
        // A PATH entry naming the rejected directory does not bring the
        // managed copy back.
        let path = format!("{}:/usr/bin:/bin", guest.path("local/fleet/bin").display());
        let output = guest.run(&pwsh, &gate_script(), &[], &[], &[("PATH", &path)]);
        assert_eq!(stdout_line(&output), serde_json::json!({"present": false}));
        let output = guest.run(&pwsh, &probe_script(), &[], &[], &[]);
        assert_eq!(stdout_line(&output), serde_json::json!({"present": false}));
        let (url, digest) = artifact(&guest, FAKE_CLI);
        let output = guest.run(
            &pwsh,
            &probe_script(),
            &[],
            &[
                ("FLEET_PIN_URL", url.as_str()),
                ("FLEET_PIN_SHA256", digest.as_str()),
            ],
            &[],
        );
        assert_eq!(
            stdout_line(&output),
            serde_json::json!({"installFailed": "directory_untrusted"})
        );
        assert!(guest.calls().is_empty(), "the planted CLI never ran");
    }

    #[test]
    fn a_cli_on_path_is_used_when_there_is_no_managed_copy() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        Guest::write_executable(&guest.path("tools/skills-manager-cli"), FAKE_CLI);
        let path = format!("{}:/usr/bin:/bin", guest.path("tools").display());
        let output = guest.run(&pwsh, &gate_script(), &[], &[], &[("PATH", &path)]);
        assert_eq!(
            unb64(stdout_line(&output)["version64"].as_str().unwrap()),
            "skills-manager-cli 1.40.0"
        );
    }

    #[test]
    fn deploy_and_undeploy_pass_agents_as_documented_pairs() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        guest.install_fake();
        let output = guest.run(
            &pwsh,
            &mutation_script("deploy", false),
            &["db", "claude_code", "codex"],
            &[],
            &[],
        );
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout_line(&output)["skillId"], "db");
        let output = guest.run(
            &pwsh,
            &mutation_script("undeploy", true),
            &["db", "claude_code"],
            &[],
            &[],
        );
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(
            guest.calls(),
            [
                vec![
                    "--json",
                    "skills",
                    "deploy",
                    "db",
                    "--agent",
                    "claude_code",
                    "--agent",
                    "codex"
                ],
                // v1.40.0's undeploy has no `--yes`.
                vec![
                    "--json",
                    "skills",
                    "undeploy",
                    "db",
                    "--agent",
                    "claude_code",
                    "--dry-run"
                ],
            ]
            .map(|call| call.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
        );
    }

    #[test]
    fn a_failed_deploy_passes_the_cli_answer_and_exit_code_through() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        guest.install_fake();
        let output = guest.run(
            &pwsh,
            &mutation_script("deploy", false),
            &["db", "claude_code"],
            &[],
            &[("FAKE_FAIL_DEPLOY", "1")],
        );
        assert_eq!(output.status.code(), Some(5));
        assert_eq!(stdout_line(&output)["code"], "DEPLOY_FAILED");
        assert!(stderr(&output).contains("deploy refused"));
    }

    #[test]
    fn mutation_values_outside_the_grammar_are_refused_in_the_script() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        guest.install_fake();
        for arguments in [
            &["db\"x", "claude_code"][..],
            &["db", "claude code"][..],
            &["db", "Claude"][..],
            &["-db", "claude_code"][..],
            &["db\\", "claude_code"][..],
        ] {
            let output = guest.run(
                &pwsh,
                &mutation_script("deploy", false),
                arguments,
                &[],
                &[],
            );
            assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        }
        assert!(guest.calls().is_empty(), "the CLI never ran");
        let output = guest.run(
            &pwsh,
            &mutation_script("deploy", false),
            &["db", "codex"],
            &[],
            &[],
        );
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

        // No CLI: the same exit 3 as the Bash script.
        let bare = Guest::new();
        let output = bare.run(
            &pwsh,
            &mutation_script("deploy", false),
            &["db", "codex"],
            &[],
            &[],
        );
        assert_eq!(output.status.code(), Some(3));
    }

    fn rollout_args<'a>(
        name: &'a str,
        files: &'a [(String, String, String)],
        agents: &'a [&'a str],
        count: &'a str,
        agent_count: &'a str,
    ) -> Vec<&'a str> {
        let mut args = vec![name, "digest-1", count];
        for (path, content, digest) in files {
            args.extend([path.as_str(), content.as_str(), digest.as_str()]);
        }
        args.push(agent_count);
        args.extend(agents);
        args
    }

    fn file(path: &str, content: &str) -> (String, String, String) {
        (path.to_owned(), b64(content), sha256(content.as_bytes()))
    }

    #[test]
    fn a_catalog_rollout_stages_installs_and_reruns_as_update() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        guest.install_fake();
        let skill = "---\nname: hello-world\ndescription: Do useful work\n---\n# Hello\n";
        let files = [
            file("SKILL.md", skill),
            file("references/notes.md", "notes\n"),
        ];
        let args = rollout_args("hello-world", &files, &["claude_code"], "2", "1");
        for _ in 0..2 {
            let output = guest.run(&pwsh, &catalog_rollout_script(), &args, &[], &[]);
            assert!(output.status.success(), "{}", stderr(&output));
            assert_eq!(
                stdout_line(&output),
                serde_json::json!({"versionDigest": "digest-1", "verified": true})
            );
        }
        let target = guest.path("local/fleet/skills/hello-world");
        assert_eq!(
            std::fs::read_to_string(target.join("SKILL.md")).unwrap(),
            skill
        );
        assert!(target.join("references/notes.md").exists());
        // Only the staged skill is left in the Fleet directory.
        let entries: Vec<String> = std::fs::read_dir(guest.path("local/fleet/skills"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, ["hello-world"]);

        let calls = guest.calls();
        let target_text = target.display().to_string();
        let expect = |call: &[&str]| {
            let call: Vec<String> = call.iter().map(|arg| (*arg).to_owned()).collect();
            assert!(calls.contains(&call), "{call:?} not in {calls:?}");
        };
        expect(&["--json", "skills", "install", &target_text, "--local"]);
        expect(&["--json", "skills", "update", "hello-world"]);
        expect(&[
            "--json",
            "skills",
            "deploy",
            "hello-world",
            "--agent",
            "claude_code",
        ]);
        expect(&["--json", "skills", "status", "hello-world"]);
    }

    #[test]
    fn a_failed_rollout_restores_the_previous_staging() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        guest.install_fake();
        let old = [file("SKILL.md", "old\n")];
        // A failed first rollout leaves no staging behind.
        let output = guest.run(
            &pwsh,
            &catalog_rollout_script(),
            &rollout_args("hello-world", &old, &["claude_code"], "1", "1"),
            &[],
            &[("FAKE_FAIL_DEPLOY", "1")],
        );
        assert_eq!(output.status.code(), Some(5), "{}", stderr(&output));
        assert_eq!(
            std::fs::read_dir(guest.path("local/fleet/skills"))
                .unwrap()
                .count(),
            0
        );
        let output = guest.run(
            &pwsh,
            &catalog_rollout_script(),
            &rollout_args("hello-world", &old, &["claude_code"], "1", "1"),
            &[],
            &[],
        );
        assert!(output.status.success(), "{}", stderr(&output));

        let new = [file("SKILL.md", "new\n")];
        let output = guest.run(
            &pwsh,
            &catalog_rollout_script(),
            &rollout_args("hello-world", &new, &["claude_code"], "1", "1"),
            &[],
            &[("FAKE_FAIL_DEPLOY", "1")],
        );
        assert_eq!(output.status.code(), Some(5), "{}", stderr(&output));
        let skills = guest.path("local/fleet/skills");
        assert_eq!(
            std::fs::read_to_string(skills.join("hello-world/SKILL.md")).unwrap(),
            "old\n"
        );

        // A digest mismatch stops before anything is moved.
        let mut tampered = file("SKILL.md", "new\n");
        tampered.2 = sha256(b"other");
        let output = guest.run(
            &pwsh,
            &catalog_rollout_script(),
            &rollout_args("hello-world", &[tampered], &["claude_code"], "1", "1"),
            &[],
            &[],
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(stderr(&output).contains("digest mismatch"));
        assert_eq!(
            std::fs::read_to_string(skills.join("hello-world/SKILL.md")).unwrap(),
            "old\n"
        );
        let entries: Vec<String> = std::fs::read_dir(&skills)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, ["hello-world"], "no staging or backup is left");
    }

    #[test]
    fn staged_paths_windows_cannot_hold_are_refused() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        guest.install_fake();
        for path in [
            "../escape.md",
            "a/../../escape.md",
            "/abs.md",
            "C:x.md",
            "a\\b.md",
            "SKILL.md:stream",
            "aux.md",
            "scripts/COM1",
            "trailing.",
            "space ",
            "a//b.md",
            "./SKILL.md",
        ] {
            let files = [file(path, "x\n")];
            let output = guest.run(
                &pwsh,
                &catalog_rollout_script(),
                &rollout_args("hello-world", &files, &["claude_code"], "1", "1"),
                &[],
                &[],
            );
            assert_eq!(output.status.code(), Some(2), "{path}: {}", stderr(&output));
            assert!(stderr(&output).contains("invalid staged path"), "{path}");
        }
        assert!(!guest.path("escape.md").exists());
        assert!(!guest.path("local/escape.md").exists());
        assert!(guest.calls().is_empty(), "the CLI never ran");
    }

    #[test]
    fn rollout_names_and_agents_outside_the_grammar_are_refused() {
        let Some(pwsh) = pwsh() else { return };
        let guest = Guest::new();
        guest.install_fake();
        let files = [file("SKILL.md", "x\n")];
        for (name, agent) in [
            ("Hello", "claude_code"),
            ("-hello", "claude_code"),
            ("hello..x", "claude_code"),
            ("hello", "claude\"code"),
        ] {
            let output = guest.run(
                &pwsh,
                &catalog_rollout_script(),
                &rollout_args(name, &files, &[agent], "1", "1"),
                &[],
                &[],
            );
            assert_eq!(output.status.code(), Some(2), "{name} {agent}");
        }
        // The agent count must match.
        let output = guest.run(
            &pwsh,
            &catalog_rollout_script(),
            &rollout_args("hello", &files, &["claude_code"], "1", "2"),
            &[],
            &[],
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(!guest.path("local/fleet/skills/hello").exists());
    }

    #[test]
    fn a_referenced_rollout_installs_rebinds_or_refuses_and_prints_the_record() {
        let Some(pwsh) = pwsh() else { return };
        let reference = "https://github.com/example/skills/tree/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/release-notes";
        let record = format!(
            r#"{{"source_ref":"{reference}","source_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_subpath":"release-notes"}}"#
        );

        // A new Git skill installs with its name.
        let guest = Guest::new();
        guest.install_fake();
        std::fs::write(guest.path("state/show.json"), &record).unwrap();
        let args = ["release-notes", reference, "true", "1", "codex"];
        let output = guest.run(&pwsh, &referenced_rollout_script(), &args, &[], &[]);
        assert!(output.status.success(), "{}", stderr(&output));
        let printed = String::from_utf8_lossy(&output.stdout);
        assert_eq!(printed.trim(), record);
        let calls = guest.calls();
        let has = |call: &[&str]| {
            calls.contains(&call.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
        };
        assert!(has(&[
            "--json",
            "skills",
            "install",
            reference,
            "--name",
            "release-notes",
            "--git"
        ]));
        assert!(has(&[
            "--json",
            "skills",
            "deploy",
            "release-notes",
            "--agent",
            "codex"
        ]));
        assert!(has(&["--json", "skills", "status", "release-notes"]));

        // An existing Git skill is rebound to the pinned source.
        let output = guest.run(&pwsh, &referenced_rollout_script(), &args, &[], &[]);
        assert!(output.status.success(), "{}", stderr(&output));
        let calls = guest.calls();
        assert!(
            calls.contains(
                &[
                    "--json",
                    "skills",
                    "set-source",
                    "release-notes",
                    "--git-url",
                    reference,
                    "--force"
                ]
                .map(str::to_owned)
                .to_vec()
            )
        );

        // An existing non-Git skill updates only when its source matches.
        let local = "owner/repo/release-notes";
        std::fs::write(
            guest.path("state/show.json"),
            format!(r#"{{"source_ref":"{local}"}}"#),
        )
        .unwrap();
        let output = guest.run(
            &pwsh,
            &referenced_rollout_script(),
            &["release-notes", local, "false", "1", "codex"],
            &[],
            &[],
        );
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(
            guest.calls().contains(
                &["--json", "skills", "update", "release-notes"]
                    .map(str::to_owned)
                    .to_vec()
            )
        );
        let output = guest.run(
            &pwsh,
            &referenced_rollout_script(),
            &[
                "release-notes",
                "owner/other/release-notes",
                "false",
                "1",
                "codex",
            ],
            &[],
            &[],
        );
        assert_eq!(output.status.code(), Some(4));
        assert!(stderr(&output).contains("different non-Git source"));

        // A reference outside the grammar never reaches the CLI.
        let before = guest.calls().len();
        let output = guest.run(
            &pwsh,
            &referenced_rollout_script(),
            &[
                "release-notes",
                "https://example.invalid/a\"b",
                "true",
                "1",
                "codex",
            ],
            &[],
            &[],
        );
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(guest.calls().len(), before);
    }

    #[test]
    fn the_grammars_refuse_what_windows_powershell_cannot_pass_safely() {
        for good in ["claude_code", "codex", "gemini_cli", "trae_cn", "a", "0x"] {
            assert!(is_agent_id(good), "{good}");
        }
        for bad in [
            "",
            "Claude",
            "claude code",
            "-x",
            "_x",
            "a\"b",
            "a\\",
            &"a".repeat(65),
        ] {
            assert!(!is_agent_id(bad), "{bad}");
        }
        for good in ["hello-world", "a", "skill2"] {
            assert!(is_skill_name(good), "{good}");
        }
        for bad in ["", "-a", "a-", "Hello", "a_b", "a.b", &"a".repeat(129)] {
            assert!(!is_skill_name(bad), "{bad}");
        }
        for good in ["db", "Hello.World", "3f0c-uuid_like"] {
            assert!(is_skill_reference(good), "{good}");
        }
        for bad in ["", "-db", "db x", "db\"", "db\\", "db/x", "db\n"] {
            assert!(!is_skill_reference(bad), "{bad}");
        }
        for good in [
            "https://github.com/xingkongliang/skills-manager/releases/download/v1.40.0/skills-manager-cli-Windows-x64.exe",
            "owner/repo/skill",
            "ssh://git@github.com/org/repo.git",
            "https://example.invalid/a?b=c&d=%20",
        ] {
            assert!(is_native_token(good), "{good}");
        }
        for bad in [
            "",
            "-o/tmp/x",
            "https://example.invalid/a b",
            "https://example.invalid/a\"b",
            "https://example.invalid/a\\",
            "https://example.invalid/`a",
            "https://example.invalid/'a",
            "https://example.invalid/\n",
        ] {
            assert!(!is_native_token(bad), "{bad:?}");
        }
        assert!(refusal("an agent id", "claude_code", is_agent_id).is_none());
        let reason = refusal("an agent id", "a\"b", is_agent_id).unwrap();
        assert!(reason.contains("an agent id") && !reason.contains("a\"b"));
    }

    #[test]
    fn the_scripts_never_name_the_skills_manager_library() {
        // ADR 0021 decision 8: only the CLI touches its library, database
        // and settings.
        for text in [
            gate_script(),
            probe_script(),
            mutation_script("deploy", false),
            catalog_rollout_script(),
            referenced_rollout_script(),
        ] {
            for forbidden in [
                "'.skills-manager'",
                ".skills-manager\\",
                "'skills-manager'",
                "APPDATA\\skills-manager",
                "USERPROFILE",
                ".db",
            ] {
                assert!(!text.contains(forbidden), "{forbidden}");
            }
            // Never a `.cmd` or `.bat`, and no PowerShell file is written.
            assert!(!text.contains(".cmd") && !text.contains(".bat") && !text.contains(".ps1'"));
        }
    }
}
