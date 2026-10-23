//! The guest-side scripts of persistent VM creation (#489): installing and
//! replacing the SSH key a machine accepts, naming a Windows computer,
//! rotating the Windows administrator password, and activating Windows.
//!
//! Every script is fixed text with a few validated values interpolated
//! through the quoting helpers below, and every script rides the SSH
//! session's **stdin** like any other Fleet script, never a command line.
//! That matters most for the product key: it is part of the script text the
//! controller holds in memory only, it is not an operation payload, an
//! argument or an environment variable, and the guest command that echoes it
//! (`slmgr /ipk`) has its output discarded.
//!
//! The scripts print `FLEET_*=` result lines. The parsers here read those
//! lines only, so unrelated output (or a hostile guest's chatter) cannot
//! forge a result field the controller acts on beyond the documented ones.

/// Quotes a value for a POSIX shell as one single-quoted word.
#[must_use]
pub fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Quotes a value for PowerShell as one single-quoted string.
#[must_use]
pub fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// The Linux script that appends `public_key` to the target user's
/// `authorized_keys` (idempotent), creating the user first when it is not
/// the login user and does not exist (this needs root). `target_user` is
/// `None` for the login user itself.
#[must_use]
pub fn linux_install_key_script(target_user: Option<&str>, public_key: &str) -> String {
    format!(
        "set -eu\n\
         KEY={key}\n\
         TARGET={target}\n\
         if [ -n \"$TARGET\" ] && [ \"$TARGET\" != \"$(id -un)\" ]; then\n\
         \x20 if [ \"$(id -u)\" != 0 ]; then echo \"fleet: switching to or creating $TARGET needs root\" >&2; exit 78; fi\n\
         \x20 id -u \"$TARGET\" >/dev/null 2>&1 || useradd -m -s /bin/bash \"$TARGET\"\n\
         \x20 HOME_DIR=$(getent passwd \"$TARGET\" | cut -d: -f6)\n\
         \x20 OWNER=\"$TARGET\"\n\
         else\n\
         \x20 HOME_DIR=\"${{HOME:?}}\"\n\
         \x20 OWNER=\n\
         fi\n\
         DIR=\"$HOME_DIR/.ssh\"\n\
         FILE=\"$DIR/authorized_keys\"\n\
         mkdir -p \"$DIR\"\n\
         chmod 700 \"$DIR\"\n\
         touch \"$FILE\"\n\
         chmod 600 \"$FILE\"\n\
         grep -qxF -- \"$KEY\" \"$FILE\" || printf '%s\\n' \"$KEY\" >> \"$FILE\"\n\
         if [ -n \"$OWNER\" ]; then chown -R \"$OWNER:\" \"$DIR\"; fi\n\
         printf 'FLEET_AUTHORIZED_KEYS=%s\\n' \"$FILE\"\n",
        key = sh_quote(public_key.trim()),
        target = sh_quote(target_user.unwrap_or("")),
    )
}

/// The Linux script that makes `public_key` the only key the login user
/// accepts. It runs over the new key, so it cannot lock Fleet out.
#[must_use]
pub fn linux_replace_keys_script(public_key: &str) -> String {
    format!(
        "set -eu\n\
         KEY={key}\n\
         FILE=\"${{HOME:?}}/.ssh/authorized_keys\"\n\
         TMP=\"$FILE.fleet-new\"\n\
         umask 077\n\
         printf '%s\\n' \"$KEY\" > \"$TMP\"\n\
         chmod 600 \"$TMP\"\n\
         mv -f \"$TMP\" \"$FILE\"\n\
         printf 'FLEET_AUTHORIZED_KEYS=%s\\n' \"$FILE\"\n",
        key = sh_quote(public_key.trim()),
    )
}

/// The Windows script that appends `public_key` for the target user
/// (idempotent): `administrators_authorized_keys` with its required ACL
/// for an administrator, `~\.ssh\authorized_keys` otherwise. A target that
/// is not the login user is created as a local administrator with a random
/// password nobody keeps, so only the key logs in. `replace` makes the key
/// the only one accepted.
#[must_use]
pub fn windows_install_key_script(
    target_user: Option<&str>,
    public_key: &str,
    replace: bool,
) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $key = {key}\n\
         $target = {target}\n\
         $replace = {replace}\n\
         if ($target -and ($target -ine $env:USERNAME)) {{\n\
         \x20 if (-not (Get-LocalUser -Name $target -ErrorAction SilentlyContinue)) {{\n\
         \x20   $bytes = New-Object byte[] 24\n\
         \x20   [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)\n\
         \x20   $secret = ConvertTo-SecureString ([Convert]::ToBase64String($bytes) + 'aA1!') -AsPlainText -Force\n\
         \x20   New-LocalUser -Name $target -Password $secret -PasswordNeverExpires | Out-Null\n\
         \x20   Add-LocalGroupMember -Group 'Administrators' -Member $target\n\
         \x20 }}\n\
         \x20 $isAdmin = $true\n\
         }} else {{\n\
         \x20 $id = [Security.Principal.WindowsIdentity]::GetCurrent()\n\
         \x20 $isAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\n\
         }}\n\
         if ($isAdmin) {{\n\
         \x20 $file = Join-Path $env:ProgramData 'ssh\\administrators_authorized_keys'\n\
         }} else {{\n\
         \x20 $dir = Join-Path $env:USERPROFILE '.ssh'\n\
         \x20 New-Item -ItemType Directory -Force -Path $dir | Out-Null\n\
         \x20 $file = Join-Path $dir 'authorized_keys'\n\
         }}\n\
         if (-not (Test-Path $file)) {{ New-Item -ItemType File -Force -Path $file | Out-Null }}\n\
         $lines = @(Get-Content -Path $file -ErrorAction SilentlyContinue | Where-Object {{ $_ -ne '' }})\n\
         if ($replace) {{ $lines = @($key) }} elseif ($lines -notcontains $key) {{ $lines += $key }}\n\
         Set-Content -Path $file -Value $lines -Encoding Ascii\n\
         if ($isAdmin) {{\n\
         \x20 & icacls.exe $file /inheritance:r /grant '*S-1-5-18:F' /grant '*S-1-5-32-544:F' | Out-Null\n\
         \x20 if ($LASTEXITCODE -ne 0) {{ throw 'icacls failed' }}\n\
         }}\n\
         Write-Output \"FLEET_AUTHORIZED_KEYS=$file\"\n",
        key = ps_quote(public_key.trim()),
        target = ps_quote(target_user.unwrap_or("")),
        replace = if replace { "$true" } else { "$false" },
    )
}

/// The Windows script that renames the computer when its name differs.
/// The new name takes effect after a restart; the script prints
/// `FLEET_RENAMED=1` when it changed the name and `FLEET_RENAMED=0` when it
/// already matched.
#[must_use]
pub fn windows_rename_script(name: &str) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $name = {name}\n\
         if ($env:COMPUTERNAME -ieq $name) {{ Write-Output 'FLEET_RENAMED=0' }} else {{\n\
         \x20 Rename-Computer -NewName $name -Force | Out-Null\n\
         \x20 Write-Output 'FLEET_RENAMED=1'\n\
         }}\n",
        name = ps_quote(name),
    )
}

/// The Windows script that restarts the computer shortly after the session
/// ends, so the session returns before the connection drops.
#[must_use]
pub fn windows_restart_script() -> String {
    "& shutdown.exe /r /t 3 /c 'Fleet: computer name change'\n".to_owned()
}

/// The Windows script that rotates a local account's password to a random
/// value generated on the guest. With `print` the value is written once as
/// `FLEET_PASSWORD=<value>` for the controller to store as a secret;
/// without it the value exists nowhere afterwards.
#[must_use]
pub fn windows_rotate_password_script(account: &str, print: bool) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $account = {account}\n\
         $bytes = New-Object byte[] 24\n\
         [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)\n\
         $plain = [Convert]::ToBase64String($bytes) + 'aA1!'\n\
         Set-LocalUser -Name $account -Password (ConvertTo-SecureString $plain -AsPlainText -Force)\n\
         {emit}\
         Write-Output 'FLEET_ROTATED=1'\n",
        account = ps_quote(account),
        emit = if print {
            "Write-Output \"FLEET_PASSWORD=$plain\"\n"
        } else {
            ""
        },
    )
}

/// How a Windows guest is activated, as the script needs it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationMethod<'a> {
    /// Install this product key, then activate.
    ProductKey(&'a str),
    /// Point at a KMS host, then activate.
    Kms(&'a str),
}

/// The Windows script that activates the guest and reads the result back.
///
/// With a product key, the key goes to the licensing service's
/// `InstallProductKey` method through CIM, so no child process ever has it in
/// its argument list (`slmgr /ipk <key>` would, and echoes it besides); only
/// the HRESULT of a failure is printed. The key is still part of the script
/// text, which Windows PowerShell script-block logging, when enabled by
/// policy on the guest, records: see `docs/operations/persistent-machines.md`.
/// The script then runs `/ato`, reads
/// `SoftwareLicensingProduct.LicenseStatus` and the `/xpr` result, and always
/// exits 0: a failed activation is a result for the controller to report,
/// not a script failure.
#[must_use]
pub fn windows_activation_script(method: &ActivationMethod<'_>) -> String {
    let prepare = match method {
        ActivationMethod::ProductKey(key) => format!(
            "$k = {key}\n\
             try {{\n\
             \x20 $svc = Get-CimInstance -ClassName SoftwareLicensingService\n\
             \x20 Invoke-CimMethod -InputObject $svc -MethodName InstallProductKey -Arguments @{{ ProductKey = $k }} -ErrorAction Stop | Out-Null\n\
             }} catch {{ Write-Output ('FLEET_IPK_ERROR=0x{{0:X8}}' -f $_.Exception.HResult) }}\n\
             $k = $null\n",
            key = ps_quote(key.trim()),
        ),
        ActivationMethod::Kms(host) => format!(
            "& cscript.exe //nologo $slmgr /skms {host} *> $null\n",
            host = ps_quote(host),
        ),
    };
    format!(
        "$ErrorActionPreference = 'Continue'\n\
         $slmgr = Join-Path $env:SystemRoot 'System32\\slmgr.vbs'\n\
         {prepare}\
         $ato = (& cscript.exe //nologo $slmgr /ato 2>&1 | Out-String)\n\
         Write-Output ('FLEET_ATO=' + (($ato -replace '\\s+', ' ').Trim()))\n\
         $product = Get-CimInstance SoftwareLicensingProduct | Where-Object {{ $_.PartialProductKey -and $_.ApplicationId -eq '55c92734-d682-4d71-983e-d6ec3f16059f' }} | Select-Object -First 1\n\
         if ($product) {{ Write-Output ('FLEET_LICENSE_STATUS=' + [int]$product.LicenseStatus) }} else {{ Write-Output 'FLEET_LICENSE_STATUS=none' }}\n\
         $xpr = (& cscript.exe //nologo $slmgr /xpr 2>&1 | Out-String)\n\
         Write-Output ('FLEET_XPR=' + (($xpr -replace '\\s+', ' ').Trim()))\n\
         exit 0\n",
    )
}

/// The activation result a guest reported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationReport {
    /// `SoftwareLicensingProduct.LicenseStatus`, when a product with a key
    /// was found.
    pub license_status: Option<u32>,
    /// The `/xpr` line, bounded and scrubbed of anything but plain text.
    pub xpr: Option<String>,
    /// The Microsoft error code (`0xC004F074`) of a failed key install or
    /// activation.
    pub error_code: Option<String>,
}

impl ActivationReport {
    /// Whether Windows reports itself licensed.
    #[must_use]
    pub fn activated(&self) -> bool {
        self.license_status == Some(1)
    }

    /// The stable name of the license status.
    #[must_use]
    pub fn status_name(&self) -> &'static str {
        match self.license_status {
            Some(0) => "unlicensed",
            Some(1) => "licensed",
            Some(2) => "oob_grace",
            Some(3) => "oot_grace",
            Some(4) => "non_genuine_grace",
            Some(5) => "notification",
            Some(6) => "extended_grace",
            Some(_) => "unknown",
            None => "no_product",
        }
    }
}

fn result_line<'a>(output: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("{field}=");
    output
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
}

/// The first `0x` followed by eight hex digits in `text`: a Microsoft error
/// code. Nothing else from the guest's `/ato` text is kept.
fn find_error_code(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    (0..bytes.len().saturating_sub(9)).find_map(|start| {
        let window = text.get(start..start + 10)?;
        let digits = window.strip_prefix("0x")?;
        digits
            .chars()
            .all(|c| c.is_ascii_hexdigit())
            .then(|| window.to_ascii_uppercase().replacen("0X", "0x", 1))
    })
}

/// Reads the activation script's result lines.
#[must_use]
pub fn parse_activation(stdout: &str) -> ActivationReport {
    let license_status = result_line(stdout, "FLEET_LICENSE_STATUS")
        .and_then(|value| value.trim().parse::<u32>().ok());
    let xpr = result_line(stdout, "FLEET_XPR").map(|text| {
        text.chars()
            .filter(|c| !c.is_control())
            .take(160)
            .collect::<String>()
    });
    // A failed key install names its HRESULT; otherwise the `/ato` text may.
    let error_code = result_line(stdout, "FLEET_IPK_ERROR")
        .and_then(find_error_code)
        .or_else(|| result_line(stdout, "FLEET_ATO").and_then(find_error_code));
    ActivationReport {
        license_status,
        xpr,
        error_code,
    }
}

/// The rotated password a guest printed, when it printed one.
#[must_use]
pub fn parse_password(stdout: &str) -> Option<String> {
    result_line(stdout, "FLEET_PASSWORD")
        .map(str::trim)
        .filter(|password| (16..=128).contains(&password.len()))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_keeps_a_hostile_value_inside_one_word() {
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
        assert_eq!(ps_quote("a'b"), "'a''b'");
        let script = linux_install_key_script(None, "ssh-ed25519 AAAA c'; rm -rf / #");
        assert!(script.contains("KEY='ssh-ed25519 AAAA c'\\''; rm -rf / #'"));
    }

    #[test]
    fn the_activation_result_is_read_from_the_marked_lines_only() {
        let report = parse_activation(
            "noise\nFLEET_ATO=Error: 0xc004f074 The Software Licensing Service reported\nFLEET_LICENSE_STATUS=5\nFLEET_XPR=The machine is permanently activated.\n",
        );
        assert_eq!(report.license_status, Some(5));
        assert_eq!(report.status_name(), "notification");
        assert!(!report.activated());
        assert_eq!(report.error_code.as_deref(), Some("0xC004F074"));
        assert_eq!(
            report.xpr.as_deref(),
            Some("The machine is permanently activated.")
        );
        let licensed = parse_activation("FLEET_LICENSE_STATUS=1\n");
        assert!(licensed.activated());
        assert_eq!(
            parse_activation("FLEET_LICENSE_STATUS=none").license_status,
            None
        );
    }

    #[test]
    fn the_product_key_is_in_the_script_text_only_and_its_output_is_discarded() {
        let script = windows_activation_script(&ActivationMethod::ProductKey(
            "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE",
        ));
        assert!(script.contains("$k = 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'"));
        // The key is passed to the service's own method, never to a child
        // process.
        assert!(script.contains("InstallProductKey -Arguments @{ ProductKey = $k }"));
        assert!(!script.contains("/ipk"));
        // The key appears once, in the assignment, and is cleared at once.
        assert_eq!(script.matches("AAAAA-BBBBB").count(), 1);
        assert!(script.contains("$k = $null"));
        let kms = windows_activation_script(&ActivationMethod::Kms("kms.example.test:1688"));
        assert!(kms.contains("/skms 'kms.example.test:1688'"));
        assert!(!kms.contains("/ipk"));
    }

    #[test]
    fn a_password_is_read_only_when_one_was_printed() {
        assert_eq!(
            parse_password("FLEET_PASSWORD=abcdefghijklmnop1234\nFLEET_ROTATED=1"),
            Some("abcdefghijklmnop1234".to_owned())
        );
        assert_eq!(parse_password("FLEET_ROTATED=1"), None);
        assert_eq!(parse_password("FLEET_PASSWORD=short"), None);
        let discard = windows_rotate_password_script("fleetadmin", false);
        assert!(!discard.contains("FLEET_PASSWORD"));
        assert!(windows_rotate_password_script("fleetadmin", true).contains("FLEET_PASSWORD"));
    }

    #[test]
    fn the_windows_key_script_uses_the_administrators_file_with_its_acl() {
        let script = windows_install_key_script(None, "ssh-ed25519 AAAA c", false);
        assert!(script.contains("administrators_authorized_keys"));
        assert!(script.contains(
            "icacls.exe $file /inheritance:r /grant '*S-1-5-18:F' /grant '*S-1-5-32-544:F'"
        ));
        assert!(script.contains("$replace = $false"));
        assert!(
            windows_install_key_script(Some("ops"), "ssh-ed25519 AAAA c", true)
                .contains("$replace = $true")
        );
    }

    #[cfg(unix)]
    mod linux {
        use super::*;
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::{Command, Stdio};

        fn run(home: &std::path::Path, script: &str) -> (bool, String) {
            use std::io::Write as _;
            let mut child = Command::new("bash")
                .arg("-s")
                .env("HOME", home)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("bash");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(script.as_bytes())
                .expect("script");
            let output = child.wait_with_output().expect("output");
            (
                output.status.success(),
                String::from_utf8_lossy(&output.stdout).into_owned(),
            )
        }

        #[test]
        fn the_install_script_appends_once_with_private_modes_and_replace_keeps_one_key() {
            let home = tempfile::tempdir().expect("home");
            let old = "ssh-ed25519 AAAAOLD fixture";
            let new = "ssh-ed25519 AAAANEW fleet";
            let file = home.path().join(".ssh/authorized_keys");
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, format!("{old}\n")).unwrap();

            let (ok, out) = run(home.path(), &linux_install_key_script(None, new));
            assert!(ok, "{out}");
            assert!(out.contains("FLEET_AUTHORIZED_KEYS="));
            // Idempotent: a second install adds nothing, and the old key
            // still works until it is replaced.
            let (ok, _) = run(home.path(), &linux_install_key_script(None, new));
            assert!(ok);
            let text = std::fs::read_to_string(&file).unwrap();
            assert_eq!(text, format!("{old}\n{new}\n"));
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(file.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );

            let (ok, _) = run(home.path(), &linux_replace_keys_script(new));
            assert!(ok);
            assert_eq!(std::fs::read_to_string(&file).unwrap(), format!("{new}\n"));
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        #[test]
        fn switching_to_another_user_without_root_is_refused() {
            if Command::new("id")
                .arg("-u")
                .output()
                .is_ok_and(|o| o.stdout == b"0\n")
            {
                return;
            }
            let home = tempfile::tempdir().expect("home");
            let (ok, _) = run(
                home.path(),
                &linux_install_key_script(Some("someone-else"), "ssh-ed25519 AAAA c"),
            );
            assert!(!ok);
            assert!(!home.path().join(".ssh").exists());
        }
    }
}
