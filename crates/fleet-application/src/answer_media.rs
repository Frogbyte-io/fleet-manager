//! Fleet-generated answer media for unattended installs (#549).
//!
//! Two pieces, both pure and free of I/O so a reviewer reads exactly what
//! goes on the disc:
//!
//! - [`build_iso`]: a minimal ISO 9660 writer with a Joliet extension, for a
//!   flat set of small files. Joliet carries the long, lower-case names that
//!   cloud-init (`user-data`) and Windows Setup (`autounattend.xml`) look for;
//!   the primary tree carries the same files under 8.3 names for readers that
//!   ignore Joliet. There is no Rock Ridge, no El Torito and no directories.
//!   It is written here instead of shelling out to `xorriso` or pulling in a
//!   crate: the layout for a handful of tiny files is about two hundred lines,
//!   the result is deterministic, and no unpinned binary runs next to the
//!   controller's secrets.
//! - [`nocloud_seed`] and [`autounattend_iso`]: the reviewed templates. Every
//!   interpolated value is validated against a narrow alphabet first and then
//!   quoted or escaped for its format, so a hostile machine name or key cannot
//!   add a directive to a script that runs as root.
//!
//! Secrets: the Linux seed holds no secret at all (a public key and a locked
//! password). The Windows answer file holds a throwaway administrator password
//! the caller generates; the product key never enters it.

use std::fmt::Write as _;

const SECTOR: usize = 2048;
const SECTOR_U32: u32 = 2048;
const SECTOR_U16: u16 = 2048;
/// The most files one image holds; the root directory must fit one sector.
const MAX_FILES: usize = 8;

/// One file in the image.
#[derive(Clone, Copy, Debug)]
pub struct IsoFile<'a> {
    /// The Joliet name (any case, no `/`).
    pub name: &'a str,
    /// The contents.
    pub data: &'a [u8],
}

/// The 8.3 uppercase level-1 name of `name`, with the version suffix.
fn primary_name(name: &str) -> String {
    let clean = |text: &str, max: usize| -> String {
        text.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .take(max)
            .collect()
    };
    let (stem, extension) = name.rsplit_once('.').unwrap_or((name, ""));
    format!("{}.{};1", clean(stem, 8), clean(extension, 3))
}

fn both_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
    out.extend_from_slice(&value.to_be_bytes());
}

fn both_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
    out.extend_from_slice(&value.to_be_bytes());
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (year + i64::from(month <= 2), month, day)
}

/// The 7-byte directory-record date.
fn record_date(unix: i64) -> [u8; 7] {
    let (y, mo, d) = civil(unix.div_euclid(86_400));
    let secs = unix.rem_euclid(86_400);
    let byte = |value: i64| u8::try_from(value).unwrap_or(0);
    [
        byte(y - 1900),
        byte(mo),
        byte(d),
        byte(secs / 3_600),
        byte(secs % 3_600 / 60),
        byte(secs % 60),
        0,
    ]
}

/// The 17-byte volume date (`YYYYMMDDHHMMSSCC` and a zone byte).
fn volume_date(unix: i64) -> Vec<u8> {
    let (y, mo, d) = civil(unix.div_euclid(86_400));
    let secs = unix.rem_euclid(86_400);
    let mut text = String::new();
    let _ = write!(
        text,
        "{y:04}{mo:02}{d:02}{:02}{:02}{:02}00",
        secs / 3_600,
        secs % 3_600 / 60,
        secs % 60
    );
    let mut out = text.into_bytes();
    out.push(0);
    out
}

/// One directory record.
fn dir_record(extent: u32, size: u32, flags: u8, id: &[u8], date: [u8; 7]) -> Vec<u8> {
    let mut record = Vec::new();
    record.push(0); // length, patched below
    record.push(0);
    both_u32(&mut record, extent);
    both_u32(&mut record, size);
    record.extend_from_slice(&date);
    record.push(flags);
    record.push(0);
    record.push(0);
    both_u16(&mut record, 1);
    record.push(u8::try_from(id.len()).unwrap_or(0));
    record.extend_from_slice(id);
    if record.len() % 2 == 1 {
        record.push(0);
    }
    record[0] = u8::try_from(record.len()).unwrap_or(0);
    record
}

fn ucs2(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

/// A fixed-width text field: `text` then padding.
fn field(out: &mut Vec<u8>, text: &[u8], width: usize, pad: &[u8]) {
    let mut bytes = text.to_vec();
    bytes.truncate(width);
    while bytes.len() < width {
        bytes.extend_from_slice(pad);
    }
    bytes.truncate(width);
    out.extend_from_slice(&bytes);
}

struct Tree {
    /// The root directory's sector contents.
    directory: Vec<u8>,
    /// The path table, little-endian and big-endian.
    path_l: Vec<u8>,
    path_m: Vec<u8>,
}

/// A directory with `.`, `..` and the files in the given order, in one sector.
fn tree(root_extent: u32, files: &[(Vec<u8>, u32, u32)], created: i64) -> Result<Tree, String> {
    let date = record_date(created);
    let mut directory = Vec::new();
    directory.extend(dir_record(root_extent, SECTOR_U32, 2, &[0], date));
    directory.extend(dir_record(root_extent, SECTOR_U32, 2, &[1], date));
    for (id, extent, size) in files {
        let record = dir_record(*extent, *size, 0, id, date);
        // A record never straddles a sector.
        if directory.len() + record.len() > SECTOR {
            return Err("the answer media has too many files".to_owned());
        }
        directory.extend(record);
    }
    directory.resize(SECTOR, 0);
    let mut path_l = vec![1, 0];
    path_l.extend_from_slice(&root_extent.to_le_bytes());
    path_l.extend_from_slice(&1u16.to_le_bytes());
    path_l.extend_from_slice(&[0, 0]);
    let mut path_m = vec![1, 0];
    path_m.extend_from_slice(&root_extent.to_be_bytes());
    path_m.extend_from_slice(&1u16.to_be_bytes());
    path_m.extend_from_slice(&[0, 0]);
    Ok(Tree {
        directory,
        path_l,
        path_m,
    })
}

#[allow(clippy::too_many_arguments)]
fn volume_descriptor(
    kind: u8,
    joliet: bool,
    label: &str,
    total_sectors: u32,
    path_size: u32,
    path_l: u32,
    path_m: u32,
    root: &[u8],
    created: i64,
) -> Vec<u8> {
    let text = |out: &mut Vec<u8>, value: &str, width: usize| {
        if joliet {
            let mut encoded = ucs2(value);
            encoded.truncate(width);
            while encoded.len() < width {
                encoded.extend_from_slice(&[0, 0x20]);
            }
            encoded.truncate(width);
            out.extend(encoded);
        } else {
            field(out, value.as_bytes(), width, b" ");
        }
    };
    let mut vd = vec![kind];
    vd.extend_from_slice(b"CD001");
    vd.push(1);
    vd.push(0);
    text(&mut vd, "", 32); // system id
    text(&mut vd, label, 32); // volume id
    vd.extend_from_slice(&[0; 8]);
    both_u32(&mut vd, total_sectors);
    if joliet {
        field(&mut vd, b"%/E", 32, &[0]);
    } else {
        vd.extend_from_slice(&[0; 32]);
    }
    both_u16(&mut vd, 1);
    both_u16(&mut vd, 1);
    both_u16(&mut vd, SECTOR_U16);
    both_u32(&mut vd, path_size);
    vd.extend_from_slice(&path_l.to_le_bytes());
    vd.extend_from_slice(&0u32.to_le_bytes());
    vd.extend_from_slice(&path_m.to_be_bytes());
    vd.extend_from_slice(&0u32.to_be_bytes());
    vd.extend_from_slice(root);
    text(&mut vd, "", 128); // volume set
    text(&mut vd, "", 128); // publisher
    text(&mut vd, "FLEET", 128); // data preparer
    text(&mut vd, "FLEET", 128); // application
    text(&mut vd, "", 37);
    text(&mut vd, "", 37);
    text(&mut vd, "", 37);
    vd.extend(volume_date(created));
    vd.extend(volume_date(created));
    vd.extend_from_slice(b"0000000000000000\0"); // not expiring
    vd.extend(volume_date(created));
    vd.push(1);
    vd.resize(SECTOR, 0);
    vd
}

/// Builds the image.
///
/// `label` is the volume label: 1 to 16 letters, digits or `_`. The primary
/// descriptor carries it upper-cased (ISO 9660 d-characters; cloud-init
/// accepts `CIDATA`), the Joliet one as given (`cidata`). `created` is the
/// image timestamp in Unix seconds; the same inputs give the same bytes.
///
/// # Errors
///
/// Fails when the label or a file name is not allowed, names collide, or
/// there are too many files.
pub fn build_iso(label: &str, files: &[IsoFile<'_>], created: i64) -> Result<Vec<u8>, String> {
    if label.is_empty()
        || label.len() > 16
        || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("the volume label must be 1 to 16 letters, digits or `_`".to_owned());
    }
    if files.is_empty() || files.len() > MAX_FILES {
        return Err(format!("an image holds 1 to {MAX_FILES} files"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for file in files {
        let ok = !file.name.is_empty()
            && file.name.len() <= 64
            && file
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !ok {
            return Err(format!("the file name {:?} is not allowed", file.name));
        }
        if !seen.insert(primary_name(file.name)) {
            return Err(format!(
                "the file name {:?} collides with another once shortened",
                file.name
            ));
        }
    }
    // Sector map: 16 system, 16 PVD, 17 SVD, 18 terminator, 19..22 path
    // tables, 23 primary root, 24 Joliet root, 25.. file data.
    let mut next = 25u32;
    let mut placed = Vec::new();
    for file in files {
        let size =
            u32::try_from(file.data.len()).map_err(|_| "an answer file is too large".to_owned())?;
        placed.push((next, size));
        next += size.div_ceil(SECTOR_U32).max(1);
    }
    let total = next;
    let mut primary_files: Vec<(Vec<u8>, u32, u32)> = files
        .iter()
        .zip(&placed)
        .map(|(file, (extent, size))| (primary_name(file.name).into_bytes(), *extent, *size))
        .collect();
    primary_files.sort();
    let mut joliet_files: Vec<(Vec<u8>, u32, u32)> = files
        .iter()
        .zip(&placed)
        .map(|(file, (extent, size))| (ucs2(file.name), *extent, *size))
        .collect();
    joliet_files.sort();
    let primary = tree(23, &primary_files, created)?;
    let joliet = tree(24, &joliet_files, created)?;
    let root_record =
        |extent: u32| dir_record(extent, SECTOR_U32, 2, &[0], record_date(created))[..34].to_vec();
    let mut image = vec![0u8; 16 * SECTOR];
    image.extend(volume_descriptor(
        1,
        false,
        &label.to_ascii_uppercase(),
        total,
        10,
        19,
        20,
        &root_record(23),
        created,
    ));
    image.extend(volume_descriptor(
        2,
        true,
        label,
        total,
        10,
        21,
        22,
        &root_record(24),
        created,
    ));
    let mut terminator = vec![255];
    terminator.extend_from_slice(b"CD001");
    terminator.push(1);
    terminator.resize(SECTOR, 0);
    image.extend(terminator);
    for table in [
        &primary.path_l,
        &primary.path_m,
        &joliet.path_l,
        &joliet.path_m,
    ] {
        let mut sector = table.clone();
        sector.resize(SECTOR, 0);
        image.extend(sector);
    }
    image.extend(primary.directory);
    image.extend(joliet.directory);
    for file in files {
        image.extend_from_slice(file.data);
        let padded = file.data.len().div_ceil(SECTOR).max(1) * SECTOR;
        image.resize(image.len() + padded - file.data.len(), 0);
    }
    debug_assert_eq!(image.len(), total as usize * SECTOR);
    Ok(image)
}

// ---------------------------------------------------------------------
// Validation shared by the templates.
// ---------------------------------------------------------------------

/// A hostname or machine name: letters, digits and `-`, 1 to 63.
///
/// # Errors
///
/// Answers the rule the name broke.
pub fn check_hostname(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok {
        Ok(())
    } else {
        Err("the machine name must be 1 to 63 letters, digits or `-` to be a hostname".to_owned())
    }
}

/// A public key line: one line, a known type, base64 and a plain comment.
fn check_public_key(key: &str) -> Result<(), String> {
    let mut parts = key.split(' ');
    let kind = parts.next().unwrap_or_default();
    let blob = parts.next().unwrap_or_default();
    let comment_ok = parts.all(|part| {
        part.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+'))
    });
    let ok = matches!(
        kind,
        "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384"
    ) && !blob.is_empty()
        && blob
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        && comment_ok
        && key.len() <= 1024;
    if ok {
        Ok(())
    } else {
        Err("the public key must be a single-line OpenSSH public key".to_owned())
    }
}

/// An account name on the guest.
fn check_account(user: &str) -> Result<(), String> {
    let ok = !user.is_empty()
        && user.len() <= 20
        && user
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_uppercase())
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(
            "the account name must start with a letter and use letters, digits, `_` or `-`"
                .to_owned(),
        )
    }
}

/// A double-quoted YAML scalar. A JSON string is one.
fn yaml(value: &str) -> String {
    serde_json::Value::String(value.to_owned()).to_string()
}

fn xml(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------
// NoCloud seed (Ubuntu Server autoinstall).
// ---------------------------------------------------------------------

/// What the `NoCloud` seed installs.
#[derive(Clone, Debug)]
pub struct NoCloudSeed<'a> {
    /// The VMID, for the cloud-init instance id.
    pub vmid: u32,
    /// The hostname.
    pub hostname: &'a str,
    /// The account Fleet logs in as. Never `root`.
    pub user: &'a str,
    /// The OpenSSH public key to authorize (public by construction).
    pub public_key: &'a str,
}

/// The `user-data` and `meta-data` of a `NoCloud` seed for an Ubuntu Server
/// (Subiquity) autoinstall: key-only login, a locked password, the guest agent
/// and an SSH server, and a power-off at the end (Fleet's end-of-install
/// signal). It holds no secret.
///
/// # Errors
///
/// Fails when a value is not allowed.
pub fn nocloud_files(seed: &NoCloudSeed<'_>) -> Result<(String, String), String> {
    check_hostname(seed.hostname)?;
    check_account(seed.user)?;
    if seed.user == "root" {
        return Err("the seed creates a regular sudo user; `root` is not allowed".to_owned());
    }
    check_public_key(seed.public_key)?;
    let user_data = format!(
        "#cloud-config\n\
         autoinstall:\n  \
           version: 1\n  \
           locale: en_US.UTF-8\n  \
           keyboard:\n    layout: us\n  \
           storage:\n    layout:\n      name: direct\n  \
           ssh:\n    install-server: true\n    allow-pw: false\n  \
           packages:\n    - qemu-guest-agent\n  \
           late-commands:\n    - curtin in-target --target=/target -- systemctl enable qemu-guest-agent || true\n  \
           user-data:\n    \
             hostname: {hostname}\n    \
             disable_root: true\n    \
             users:\n      \
               - name: {user}\n        \
                 groups: [sudo]\n        \
                 shell: /bin/bash\n        \
                 sudo: ALL=(ALL) NOPASSWD:ALL\n        \
                 lock_passwd: true\n        \
                 ssh_authorized_keys:\n          - {key}\n  \
           shutdown: poweroff\n",
        hostname = yaml(seed.hostname),
        user = yaml(seed.user),
        key = yaml(seed.public_key),
    );
    let meta_data = format!(
        "instance-id: fleet-{}\nlocal-hostname: {}\n",
        seed.vmid,
        yaml(seed.hostname)
    );
    Ok((user_data, meta_data))
}

/// The seed image: volume label `cidata`, files `user-data` and `meta-data`.
///
/// # Errors
///
/// Fails when a value is not allowed.
pub fn nocloud_iso(seed: &NoCloudSeed<'_>, created: i64) -> Result<Vec<u8>, String> {
    let (user_data, meta_data) = nocloud_files(seed)?;
    build_iso(
        "cidata",
        &[
            IsoFile {
                name: "user-data",
                data: user_data.as_bytes(),
            },
            IsoFile {
                name: "meta-data",
                data: meta_data.as_bytes(),
            },
        ],
        created,
    )
}

// ---------------------------------------------------------------------
// Windows autounattend.
// ---------------------------------------------------------------------

/// What the Windows answer file installs.
#[derive(Clone, Debug)]
pub struct Autounattend<'a> {
    /// The local administrator account Fleet logs in as.
    pub user: &'a str,
    /// A throwaway password for it, generated by the caller. It exists only
    /// in this file; Fleet rotates it after the install.
    pub password: &'a str,
    /// The OpenSSH public key authorized for the account.
    pub public_key: &'a str,
    /// The edition's image name, e.g. `Windows 11 Pro`.
    pub image_name: &'a str,
}

fn check_password(password: &str) -> Result<(), String> {
    let ok = (16..=64).contains(&password.len())
        && password
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '!');
    if ok {
        Ok(())
    } else {
        Err("the throwaway password must be 16 to 64 letters, digits or `!`".to_owned())
    }
}

/// Windows image names, e.g. `Windows 11 Pro`.
///
/// # Errors
///
/// Answers the rule the name broke.
pub fn check_image_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '.'));
    if ok {
        Ok(())
    } else {
        Err("the Windows image name must be letters, digits, spaces, `-` or `.`".to_owned())
    }
}

/// The `autounattend.xml` for a Windows 11 install on UEFI with the virtio
/// drivers disc attached: GPT layout, drivers from the virtio-win disc, a
/// local administrator, no online account, and on first logon the guest agent,
/// OpenSSH with the Fleet key, then a power-off (Fleet's end-of-install
/// signal). No product key is set; activation is a separate post-install step.
///
/// # Errors
///
/// Fails when a value is not allowed.
#[allow(clippy::too_many_lines)]
pub fn autounattend_xml(answer: &Autounattend<'_>) -> Result<String, String> {
    check_account(answer.user)?;
    check_password(answer.password)?;
    check_public_key(answer.public_key)?;
    check_image_name(answer.image_name)?;
    let mut paths = String::new();
    let mut key = 1;
    for letter in ['D', 'E', 'F', 'G'] {
        for folder in [
            "vioscsi\\w11\\amd64",
            "NetKVM\\w11\\amd64",
            "Balloon\\w11\\amd64",
        ] {
            let _ = write!(
                paths,
                "<PathAndCredentials wcm:action=\"add\" wcm:keyValue=\"{key}\"><Path>{letter}:\\{folder}</Path></PathAndCredentials>"
            );
            key += 1;
        }
    }
    let drivers_pe = format!(
        "<component name=\"Microsoft-Windows-PnpCustomizationsWinPE\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\"><DriverPaths>{paths}</DriverPaths></component>"
    );
    let drivers_os = format!(
        "<component name=\"Microsoft-Windows-PnpCustomizationsNonWinPE\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\"><DriverPaths>{paths}</DriverPaths></component>"
    );
    let agent = "$d=(Get-Volume | Where-Object { $_.FileSystemLabel -like 'virtio-win*' } | Select-Object -First 1).DriveLetter; \
        if (-not $d) { exit 1 }; \
        Start-Process msiexec.exe -Wait -ArgumentList '/i',($d+':\\virtio-win-gt-x64.msi'),'/qn','/norestart'; \
        Start-Process msiexec.exe -Wait -ArgumentList '/i',($d+':\\guest-agent\\qemu-ga-x86_64.msi'),'/qn','/norestart'";
    let ssh = format!(
        "Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'; \
         Set-Service -Name sshd -StartupType Automatic; Start-Service sshd; \
         $f=Join-Path $env:ProgramData 'ssh\\administrators_authorized_keys'; \
         Set-Content -Path $f -Value '{key}' -Encoding ascii; \
         icacls $f /inheritance:r /grant 'SYSTEM:F' /grant 'Administrators:F'; \
         New-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -Value 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -PropertyType String -Force",
        key = answer.public_key
    );
    let commands = [
        (
            "Install the virtio drivers and the guest agent",
            agent.to_owned(),
        ),
        ("Install OpenSSH and authorize the Fleet key", ssh),
    ];
    let mut first_logon = String::new();
    for (index, (description, script)) in commands.iter().enumerate() {
        let _ = write!(
            first_logon,
            "<SynchronousCommand wcm:action=\"add\"><Order>{}</Order><CommandLine>{}</CommandLine><Description>{}</Description></SynchronousCommand>",
            index + 1,
            xml(&format!(
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"{script}\""
            )),
            xml(description)
        );
    }
    let _ = write!(
        first_logon,
        "<SynchronousCommand wcm:action=\"add\"><Order>{}</Order><CommandLine>shutdown.exe /s /t 15 /c \"Fleet install finished\"</CommandLine><Description>Power off: the end of the install</Description></SynchronousCommand>",
        commands.len() + 1
    );
    let user = xml(answer.user);
    let password = xml(answer.password);
    let image = xml(answer.image_name);
    let locale = "<InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>";
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
<unattend xmlns=\"urn:schemas-microsoft-com:unattend\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\">\n\
<settings pass=\"windowsPE\">\n\
<component name=\"Microsoft-Windows-International-Core-WinPE\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\">{locale}<SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage></component>\n\
{drivers_pe}\n\
<component name=\"Microsoft-Windows-Setup\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\">\n\
<DiskConfiguration><WillShowUI>OnError</WillShowUI><Disk wcm:action=\"add\"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk><CreatePartitions>\
<CreatePartition wcm:action=\"add\"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>\
<CreatePartition wcm:action=\"add\"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>\
<CreatePartition wcm:action=\"add\"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>\
</CreatePartitions><ModifyPartitions>\
<ModifyPartition wcm:action=\"add\"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>\
<ModifyPartition wcm:action=\"add\"><Order>2</Order><PartitionID>2</PartitionID></ModifyPartition>\
<ModifyPartition wcm:action=\"add\"><Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>\
</ModifyPartitions></Disk></DiskConfiguration>\n\
<ImageInstall><OSImage><InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo><InstallFrom><MetaData wcm:action=\"add\"><Key>/IMAGE/NAME</Key><Value>{image}</Value></MetaData></InstallFrom><WillShowUI>OnError</WillShowUI></OSImage></ImageInstall>\n\
<UserData><AcceptEula>true</AcceptEula><ProductKey><Key></Key><WillShowUI>OnError</WillShowUI></ProductKey></UserData>\n\
</component>\n\
</settings>\n\
<settings pass=\"specialize\">\n\
<component name=\"Microsoft-Windows-Shell-Setup\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\"><ComputerName>*</ComputerName></component>\n\
{drivers_os}\n\
<component name=\"Microsoft-Windows-Deployment\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\"><RunSynchronous><RunSynchronousCommand wcm:action=\"add\"><Order>1</Order><Path>reg.exe add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OOBE /v BypassNRO /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand></RunSynchronous></component>\n\
</settings>\n\
<settings pass=\"oobeSystem\">\n\
<component name=\"Microsoft-Windows-International-Core\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\">{locale}</component>\n\
<component name=\"Microsoft-Windows-Shell-Setup\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\">\n\
<OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>\n\
<UserAccounts><LocalAccounts><LocalAccount wcm:action=\"add\"><Name>{user}</Name><Group>Administrators</Group><Password><Value>{password}</Value><PlainText>true</PlainText></Password></LocalAccount></LocalAccounts></UserAccounts>\n\
<AutoLogon><Enabled>true</Enabled><LogonCount>1</LogonCount><Username>{user}</Username><Password><Value>{password}</Value><PlainText>true</PlainText></Password></AutoLogon>\n\
<FirstLogonCommands>{first_logon}</FirstLogonCommands>\n\
</component>\n\
</settings>\n\
</unattend>\n"
    ))
}

/// The answer image for Windows Setup: `autounattend.xml` in the root.
///
/// # Errors
///
/// Fails when a value is not allowed.
pub fn autounattend_iso(answer: &Autounattend<'_>, created: i64) -> Result<Vec<u8>, String> {
    let text = autounattend_xml(answer)?;
    build_iso(
        "FLEETANSWER",
        &[IsoFile {
            name: "autounattend.xml",
            data: text.as_bytes(),
        }],
        created,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl fleet-ci";

    /// Reads the files of one root directory out of an image, by its volume
    /// descriptor at `sector` (16 primary, 17 Joliet).
    fn read(image: &[u8], sector: usize, joliet: bool) -> (String, Vec<(String, Vec<u8>)>) {
        let vd = &image[sector * SECTOR..(sector + 1) * SECTOR];
        assert_eq!(&vd[1..6], b"CD001");
        let label = if joliet {
            String::from_utf16(
                &vd[40..72]
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        } else {
            String::from_utf8(vd[40..72].to_vec()).unwrap()
        }
        .trim_end()
        .to_owned();
        let total = u32::from_le_bytes(vd[80..84].try_into().unwrap()) as usize;
        assert_eq!(total * SECTOR, image.len());
        assert_eq!(
            u32::from_be_bytes(vd[84..88].try_into().unwrap()) as usize,
            total
        );
        let root = &vd[156..190];
        let extent = u32::from_le_bytes(root[2..6].try_into().unwrap()) as usize;
        let dir = &image[extent * SECTOR..(extent + 1) * SECTOR];
        let mut files = Vec::new();
        let mut offset = 0;
        while dir[offset] != 0 {
            let len = dir[offset] as usize;
            let record = &dir[offset..offset + len];
            offset += len;
            let id = &record[33..33 + record[32] as usize];
            if id == [0] || id == [1] {
                continue;
            }
            let name = if joliet {
                String::from_utf16(
                    &id.chunks(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            } else {
                String::from_utf8(id.to_vec()).unwrap()
            };
            let start = u32::from_le_bytes(record[2..6].try_into().unwrap()) as usize;
            let size = u32::from_le_bytes(record[10..14].try_into().unwrap()) as usize;
            assert_eq!(
                u32::from_be_bytes(record[6..10].try_into().unwrap()) as usize,
                start
            );
            files.push((name, image[start * SECTOR..start * SECTOR + size].to_vec()));
        }
        (label, files)
    }

    #[test]
    fn an_image_round_trips_through_both_trees() {
        let big = vec![7u8; 5_000];
        let image = build_iso(
            "cidata",
            &[
                IsoFile {
                    name: "user-data",
                    data: b"hello",
                },
                IsoFile {
                    name: "meta-data",
                    data: &big,
                },
            ],
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(image.len() % SECTOR, 0);
        let (label, joliet) = read(&image, 17, true);
        assert_eq!(label, "cidata");
        assert_eq!(
            joliet,
            vec![
                ("meta-data".to_owned(), big.clone()),
                ("user-data".to_owned(), b"hello".to_vec())
            ]
        );
        let (label, primary) = read(&image, 16, false);
        assert_eq!(label, "CIDATA");
        let names: Vec<_> = primary.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["META_DAT.;1", "USER_DAT.;1"]);
        assert_eq!(&image[18 * SECTOR..18 * SECTOR + 6], b"\xffCD001");
    }

    #[test]
    fn the_image_is_deterministic_and_rejects_bad_input() {
        let one = [IsoFile {
            name: "a.txt",
            data: b"x",
        }];
        assert_eq!(
            build_iso("L", &one, 5).unwrap(),
            build_iso("L", &one, 5).unwrap()
        );
        assert!(build_iso("bad label", &one, 0).is_err());
        assert!(build_iso("L", &[], 0).is_err());
        let clash = [
            IsoFile {
                name: "user-data",
                data: b"",
            },
            IsoFile {
                name: "user_data",
                data: b"",
            },
        ];
        assert!(build_iso("L", &clash, 0).is_err());
        assert!(
            build_iso(
                "L",
                &[IsoFile {
                    name: "a/b",
                    data: b""
                }],
                0
            )
            .is_err()
        );
        // An empty file still gets an extent.
        let empty = build_iso(
            "L",
            &[IsoFile {
                name: "e",
                data: b"",
            }],
            0,
        )
        .unwrap();
        assert_eq!(read(&empty, 17, true).1, vec![("e".to_owned(), Vec::new())]);
    }

    #[test]
    fn the_dates_are_civil() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(19_723), (2024, 1, 1));
        assert_eq!(&volume_date(86_400 + 3_661)[..16], b"1970010201010100");
    }

    #[test]
    fn the_seed_holds_the_key_and_no_password() {
        let seed = NoCloudSeed {
            vmid: 4242,
            hostname: "ci-linux",
            user: "fleetadmin",
            public_key: KEY,
        };
        let image = nocloud_iso(&seed, 0).unwrap();
        let (label, files) = read(&image, 17, true);
        assert_eq!(label, "cidata");
        let user_data = String::from_utf8(files[1].1.clone()).unwrap();
        assert!(user_data.starts_with("#cloud-config\nautoinstall:\n"));
        assert!(user_data.contains("shutdown: poweroff"));
        assert!(user_data.contains("lock_passwd: true"));
        assert!(user_data.contains(KEY));
        assert!(
            !user_data.to_ascii_lowercase().contains("passwd:")
                || user_data.contains("lock_passwd")
        );
        assert!(!user_data.contains("password"));
        let meta = String::from_utf8(files[0].1.clone()).unwrap();
        assert!(meta.contains("instance-id: fleet-4242"));
    }

    #[test]
    fn hostile_values_never_reach_the_templates() {
        let mut seed = NoCloudSeed {
            vmid: 1,
            hostname: "ok",
            user: "fleetadmin",
            public_key: KEY,
        };
        for bad in ["a\nb", "a b", "", "-a", "a_b", "x: y"] {
            seed.hostname = bad;
            assert!(nocloud_files(&seed).is_err(), "{bad:?}");
        }
        seed.hostname = "ok";
        for bad in ["root", "a\n- x", "", "1abc", "a b"] {
            seed.user = bad;
            assert!(nocloud_files(&seed).is_err(), "{bad:?}");
        }
        seed.user = "fleetadmin";
        for bad in [
            "ssh-ed25519 AAAA\nruncmd: [x]",
            "command=\"x\" ssh-ed25519 AAAA",
            "ssh-ed25519",
            "ssh-ed25519 AA'A c",
        ] {
            seed.public_key = bad;
            assert!(nocloud_files(&seed).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_answer_file_is_escaped_and_carries_no_product_key() {
        let answer = Autounattend {
            user: "fleetadmin",
            password: "Fa1b2c3d4e5f6a7b8c9d0e1f!9",
            public_key: KEY,
            image_name: "Windows 11 Pro",
        };
        let xml_text = autounattend_xml(&answer).unwrap();
        assert!(xml_text.contains("<Key></Key>"), "no product key");
        assert!(xml_text.contains("<Value>Windows 11 Pro</Value>"));
        assert!(xml_text.contains(KEY));
        assert!(xml_text.contains("shutdown.exe /s"));
        assert!(xml_text.contains("virtio-win*"));
        assert_eq!(xml_text.matches(answer.password).count(), 2);
        // Well-formed enough that every opened tag closes: crude balance check.
        assert_eq!(
            xml_text.matches("<component ").count(),
            xml_text.matches("</component>").count()
        );
        let image = autounattend_iso(&answer, 0).unwrap();
        let (_, files) = read(&image, 17, true);
        assert_eq!(files[0].0, "autounattend.xml");
        assert_eq!(files[0].1, xml_text.as_bytes());
        for bad in ["short", "has space 1234567890", "ok1234567890123456&x"] {
            let mut copy = answer.clone();
            copy.password = bad;
            assert!(autounattend_xml(&copy).is_err(), "{bad:?}");
        }
        let mut copy = answer.clone();
        copy.image_name = "Pro</Value><x>";
        assert!(autounattend_xml(&copy).is_err());
        assert_eq!(xml("<a&b>\"'"), "&lt;a&amp;b&gt;&quot;&apos;");
    }
}
