//! Host-side Linux job storage and user-namespace contract for the bootstrap
//! and the native step runner's per-command checks.
//!
//! Same contract as `scripts/architecture/linux_job_isolation.py` (which the
//! architecture step's confinement still imports): `prepare` provisions a fresh
//! bounded filesystem before staging; `dispose` unmounts it only after every
//! candidate container is gone. No lazy or forced unmount conceals busy mounts.
//! `prepare_writable` and the swap-bound proofs are the per-invocation half.
use crate::json::{self, Value, object};
use crate::proc::{self, Result, require};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const GIB: u64 = 1 << 30;

fn host_options(timeout: u64, interruptible: bool) -> proc::Options {
    proc::Options {
        interruptible,
        env: vec![
            ("PATH".into(), proc::HOST_PATH.into()),
            ("LC_ALL".into(), "C".into()),
        ],
        capture: true,
        timeout: Some(Duration::from_secs(timeout)),
        ..Default::default()
    }
}

fn host(argv: &[&str], timeout: u64) -> Result<String> {
    host_command(argv, timeout, false)
}

/// Long preparation steps stop on interruption so rollback can run.
fn preparing(argv: &[&str], timeout: u64) -> Result<String> {
    host_command(argv, timeout, true)
}

fn host_command(argv: &[&str], timeout: u64, interruptible: bool) -> Result<String> {
    let output = proc::run(&proc::strings(argv), &host_options(timeout, interruptible))?;
    require(
        output.status.success(),
        &format!(
            "host command {} failed: {}",
            argv[0],
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    )?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Absolute, normalized and free of symbolic links (`p == p.resolve()`).
pub fn exact_path(path: &Path) -> bool {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return false;
    }
    let mut existing = path.to_path_buf();
    let mut missing = Vec::new();
    while !existing.exists() && !existing.is_symlink() {
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                missing.push(name.to_owned());
                existing = parent.to_path_buf();
            }
            _ => return false,
        }
    }
    match fs::canonicalize(&existing) {
        Ok(mut resolved) => {
            resolved.extend(missing.iter().rev());
            resolved == path
                && path
                    .to_str()
                    .is_some_and(|text| !text.ends_with('/') || text == "/")
        }
        Err(_) => false,
    }
}

fn u64_field(config: &Value, key: &str) -> Result<u64> {
    config
        .at(key)
        .as_u64()
        .ok_or_else(|| format!("invalid {key}"))
}

pub fn validate_configuration(config: &Value) -> Result<PathBuf> {
    require(config.is_object(), "invalid Linux isolation configuration")?;
    let kind = config.at("storage_kind").as_str().unwrap_or("");
    require(
        matches!(kind, "tmpfs" | "loop-ext4"),
        "unknown job storage kind",
    )?;
    let mut keys = vec![
        "storage_kind",
        "storage_root",
        "storage_bytes",
        "storage_inodes",
        "storage_reserve_bytes",
        "uid_map",
        "gid_map",
    ];
    if kind == "loop-ext4" {
        keys.push("storage_image");
    }
    require(
        config.has_keys(&keys),
        "invalid Linux isolation configuration",
    )?;
    // Operator-only: protected root configuration names the job storage root. It is
    // still held to an exact, absolute, link-free path (`exact_path`: no `.`, `..` or
    // link anywhere) below the filesystem root before anything mounts on it.
    let configured = config
        .at("storage_root")
        .as_str()
        .ok_or("unsafe job storage root")?;
    require(!configured.contains('\0'), "unsafe job storage root")?;
    let root = crate::confined::Trusted::internal(Path::new(configured))
        .as_path()
        .to_path_buf();
    require(
        exact_path(&root)
            && root.components().count() > 2
            && !root.is_symlink()
            && !root.to_string_lossy().contains(','),
        "unsafe job storage root",
    )?;
    let bytes = config.at("storage_bytes").as_u64();
    require(
        bytes.is_some_and(|b| (4096..=256 * GIB).contains(&b) && b % 4096 == 0),
        "invalid job storage byte cap",
    )?;
    let inodes = config.at("storage_inodes").as_u64();
    require(
        inodes.is_some_and(|n| (16..=16 << 20).contains(&n)),
        "invalid job storage inode cap",
    )?;
    let reserve = config.at("storage_reserve_bytes").as_u64();
    require(
        reserve.is_some_and(|r| r <= 256 * GIB),
        "invalid host storage reserve",
    )?;
    if kind == "loop-ext4" {
        let image = PathBuf::from(config.at("storage_image").as_str().unwrap_or(""));
        require(
            exact_path(&image)
                && !image.is_symlink()
                && image.parent() == root.parent()
                && image != root,
            "job image must be a direct protected sibling",
        )?;
        require(
            bytes.unwrap() >= 64 << 20 && inodes.unwrap() >= 128 && reserve.unwrap() > 0,
            "invalid ext4 job storage budget",
        )?;
    }
    for key in ["uid_map", "gid_map"] {
        let row = config.at(key).as_array();
        let numbers: Option<Vec<u64>> = row
            .map(|r| r.iter().map(Value::as_u64).collect())
            .unwrap_or(None);
        require(
            numbers.is_some_and(|n| {
                n.len() == 3
                    && n[0] == 0
                    && n[1] >= 65536
                    && (1..=1 << 31).contains(&n[2])
                    && n[1] + n[2] < 1 << 32
            }),
            "invalid subordinate identity map",
        )?;
    }
    Ok(root)
}

#[derive(Debug, PartialEq)]
pub struct MountRow {
    pub root: String,
    pub path: PathBuf,
    pub options: Vec<String>,
    pub kind: String,
    pub source: String,
}

fn unescape(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            out.push(
                (bytes[i + 1] - b'0') * 64 + (bytes[i + 2] - b'0') * 8 + (bytes[i + 3] - b'0'),
            );
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_mounts(text: &str) -> Result<Vec<MountRow>> {
    text.lines()
        .map(|line| {
            let (before, after) = line.split_once(" - ").ok_or("invalid mountinfo")?;
            let fields: Vec<_> = before.split_whitespace().collect();
            let filesystem: Vec<_> = after.split_whitespace().collect();
            require(
                fields.len() >= 6 && filesystem.len() >= 2,
                "invalid mountinfo",
            )?;
            Ok(MountRow {
                root: unescape(fields[3]),
                path: PathBuf::from(unescape(fields[4])),
                options: fields[5].split(',').map(str::to_owned).collect(),
                kind: filesystem[0].to_owned(),
                source: unescape(filesystem[1]),
            })
        })
        .collect()
}

fn mounts() -> Result<Vec<MountRow>> {
    parse_mounts(&fs::read_to_string("/proc/self/mountinfo").map_err(|e| e.to_string())?)
}

fn is_mount(root: &Path) -> Result<bool> {
    Ok(mounts()?.iter().any(|row| row.path == root))
}

fn protected_image_parent(config: &Value) -> Result<PathBuf> {
    let image = PathBuf::from(config.at("storage_image").as_str().unwrap_or(""));
    let parent = image
        .parent()
        .ok_or("job image parent is not protected")?
        .to_path_buf();
    let metadata = fs::metadata(&parent).map_err(|e| e.to_string())?;
    require(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "job image parent is not protected",
    )?;
    Ok(parent)
}

fn available_bytes(path: &Path) -> Result<u64> {
    Ok(proc::statvfs(path)?.available_bytes)
}

fn loop_rows(selection: &[&str]) -> Result<Vec<Value>> {
    let mut argv = vec![
        "losetup",
        "--json",
        "--list",
        "--output",
        "NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,SIZELIMIT,OFFSET,RO",
    ];
    argv.extend_from_slice(selection);
    let text = host(&argv, 60)?;
    if text.trim().is_empty() {
        // util-linux prints nothing (not an empty list) when no device matches.
        return Ok(Vec::new());
    }
    json::parse(text.as_bytes())?
        .at("loopdevices")
        .as_array()
        .map(<[_]>::to_vec)
        .ok_or_else(|| "invalid losetup output".to_owned())
}

/// Linux `dev_t` major:minor (glibc encoding).
pub fn device_numbers(dev: u64) -> String {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xffff_f000);
    let minor = (dev & 0xff) | ((dev >> 12) & 0xffff_ff00);
    format!("{major}:{minor}")
}

pub fn loop_matches(
    row: &Value,
    source: &str,
    image: &Path,
    inode: u64,
    device: &str,
    bytes: u64,
) -> bool {
    row.at("name").as_str() == Some(source)
        && row.at("back-file").as_str() == image.to_str()
        && row.at("back-ino").as_u64() == Some(inode)
        && row.at("back-maj:min").as_str() == Some(device)
        && row.at("offset").as_u64() == Some(0)
        && row.at("ro").as_bool() == Some(false)
        && row.at("sizelimit").as_u64() == Some(bytes)
}

fn is_loop_device(source: &str) -> bool {
    source
        .strip_prefix("/dev/loop")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()))
}

fn validate_loop(config: &Value, source: &str) -> Result<()> {
    protected_image_parent(config)?;
    let image = PathBuf::from(config.at("storage_image").as_str().unwrap_or(""));
    let bytes = u64_field(config, "storage_bytes")?;
    let metadata = fs::symlink_metadata(&image).map_err(|e| e.to_string())?;
    require(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.uid() == 0
            && metadata.mode() & 0o077 == 0
            && metadata.len() == bytes
            && metadata.blocks() * 512 >= metadata.len(),
        "job image is not a private preallocated regular file",
    )?;
    require(
        is_loop_device(source),
        "job filesystem is not a loop device",
    )?;
    let rows = loop_rows(&[source])?;
    let device = device_numbers(metadata.dev());
    require(
        rows.len() == 1 && loop_matches(&rows[0], source, &image, metadata.ino(), &device, bytes),
        "job loop device backing identity or limit differs",
    )
}

/// Pure mount-table checks for the dedicated bounded job filesystem.
pub fn check_mounts(config: &Value, root: &Path, rows: &[MountRow]) -> Result<String> {
    let exact: Vec<_> = rows.iter().filter(|row| row.path == root).collect();
    let filesystem = if config.at("storage_kind").as_str() == Some("loop-ext4") {
        "ext4"
    } else {
        "tmpfs"
    };
    require(
        exact.len() == 1
            && exact[0].kind == filesystem
            && exact[0].root == "/"
            && ["rw", "nosuid", "nodev"]
                .iter()
                .all(|o| exact[0].options.iter().any(|v| v == o)),
        "job storage must be a dedicated bounded filesystem",
    )?;
    require(
        !rows
            .iter()
            .any(|row| row.path != root && row.path.starts_with(root)),
        "nested mount bypasses job storage quota",
    )?;
    Ok(exact[0].source.clone())
}

pub fn validate_storage(config: &Value) -> Result<Value> {
    let root = validate_configuration(config)?;
    require(
        proc::euid() == 0,
        "Linux isolation controller must run as host root",
    )?;
    require(root.is_dir(), "job storage root missing")?;
    let source = check_mounts(config, &root, &mounts()?)?;
    let ext4 = config.at("storage_kind").as_str() == Some("loop-ext4");
    if ext4 {
        validate_loop(config, &source)?;
    }
    let capacity = proc::statvfs(&root)?;
    require(
        capacity.capacity_bytes > 0
            && capacity.capacity_bytes <= u64_field(config, "storage_bytes")?
            && capacity.capacity_inodes > 0
            && capacity.capacity_inodes <= u64_field(config, "storage_inodes")?,
        "job storage exceeds byte or inode quota",
    )?;
    Ok(object([
        ("root", root.to_string_lossy().as_ref().into()),
        ("bytes", capacity.capacity_bytes.into()),
        ("inodes", capacity.capacity_inodes.into()),
        ("filesystem", if ext4 { "ext4" } else { "tmpfs" }.into()),
    ]))
}

pub fn validate_userns(config: &Value, daemon: &Value) -> Result<Value> {
    validate_configuration(config)?;
    require(
        daemon
            .at("SecurityOptions")
            .as_array()
            .is_some_and(|rows| rows.iter().any(|v| v.as_str() == Some("name=userns"))),
        "Docker daemon requires userns-remap",
    )?;
    Ok(object([
        ("uid_map", config.at("uid_map").clone()),
        ("gid_map", config.at("gid_map").clone()),
    ]))
}

/// ext4 inode count rounded down to per-block-group granularity.
pub fn ext4_inodes(bytes: u64, inodes: u64) -> Result<u64> {
    let groups = bytes.div_ceil(128 << 20);
    let rounded = inodes / (groups * 8) * (groups * 8);
    require(rounded >= 128, "inode cap too small for ext4 geometry")?;
    Ok(rounded)
}

pub fn prepare(config: &Value) -> Result<Value> {
    let root = validate_configuration(config)?;
    require(
        proc::euid() == 0,
        "job storage preparation requires host root",
    )?;
    require(!root.exists(), "job storage must be fresh")?;
    let bytes = u64_field(config, "storage_bytes")?;
    let inodes = u64_field(config, "storage_inodes")?;
    let reserve = u64_field(config, "storage_reserve_bytes")?;
    let ext4 = config.at("storage_kind").as_str() == Some("loop-ext4");
    if ext4 {
        let parent = protected_image_parent(config)?;
        require(
            available_bytes(&parent)? >= bytes + reserve,
            "insufficient host disk capacity after required reserve",
        )?;
        require(
            !Path::new(config.at("storage_image").as_str().unwrap_or("")).exists(),
            "job storage image must be fresh",
        )?;
    }
    fs::create_dir(&root).map_err(|e| e.to_string())?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    let root_text = root.to_string_lossy().into_owned();
    let mut image: Option<PathBuf> = None;
    let mut device: Option<String> = None;
    let mut attempt = || -> Result<Value> {
        if !ext4 {
            let options = format!("nosuid,nodev,size={bytes},nr_inodes={inodes},mode=0755");
            host(
                &[
                    "mount",
                    "-t",
                    "tmpfs",
                    "-o",
                    &options,
                    "busbar-job",
                    &root_text,
                ],
                60,
            )?;
        } else {
            let path = PathBuf::from(config.at("storage_image").as_str().unwrap_or(""));
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(proc::O_NOFOLLOW)
                .mode(0o600)
                .open(&path)
                .map_err(|e| e.to_string())?;
            image = Some(path.clone());
            let text = path.to_string_lossy().into_owned();
            let parent = path.parent().unwrap().to_path_buf();
            let length = bytes.to_string();
            preparing(&["fallocate", "--length", &length, &text], 300)?;
            require(
                available_bytes(&parent)? >= reserve,
                "host disk reserve consumed during allocation",
            )?;
            let count = ext4_inodes(bytes, inodes)?.to_string();
            preparing(
                &[
                    "mkfs.ext4",
                    "-q",
                    "-b",
                    "4096",
                    "-g",
                    "32768",
                    "-m",
                    "0",
                    "-N",
                    &count,
                    "-E",
                    "nodiscard,lazy_itable_init=0,lazy_journal_init=0",
                    &text,
                ],
                600,
            )?;
            // Some backing filesystems release zeroed mkfs ranges even with
            // nodiscard. Re-reserve them before exposing the filesystem.
            preparing(&["fallocate", "--length", &length, &text], 300)?;
            require(
                available_bytes(&parent)? >= reserve,
                "host disk reserve consumed while formatting",
            )?;
            let name = host(
                &[
                    "losetup",
                    "--find",
                    "--show",
                    "--nooverlap",
                    "--sizelimit",
                    &length,
                    &text,
                ],
                60,
            )?
            .trim()
            .to_owned();
            device = Some(name.clone());
            validate_loop(config, &name)?;
            host(
                &[
                    "mount",
                    "-t",
                    "ext4",
                    "-o",
                    "nosuid,nodev,nodiscard",
                    &name,
                    &root_text,
                ],
                60,
            )?;
        }
        let mut observation = validate_storage(config)?;
        if let Some(image) = &image {
            observation.set("image_bytes", bytes.into());
            observation.set(
                "host_available_bytes",
                available_bytes(image.parent().unwrap())?.into(),
            );
            observation.set("host_reserve_bytes", reserve.into());
        }
        Ok(observation)
    };
    let result = attempt();
    if result.is_err() {
        // Roll back in reverse; a rollback failure must not hide the cause.
        if is_mount(&root).unwrap_or(true) {
            let _ = host(&["umount", &root_text], 60);
        }
        if let (Some(device), Some(image)) = (&device, &image) {
            let _ = detach_loop(device, image);
        }
        if let Some(image) = &image {
            let _ = fs::remove_file(image);
        }
        let _ = fs::remove_dir(&root);
    }
    result
}

fn detach_loop(device: &str, image: &Path) -> Result<()> {
    host(&["losetup", "--detach", device], 60)?;
    // Detach may defer release while another namespace retains a bind. Keep the
    // backing image until the kernel confirms there is no remaining association.
    let text = image.to_string_lossy().into_owned();
    for _ in 0..40 {
        if loop_rows(&["--associated", &text])?.is_empty() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err("job loop device is still in use".into())
}

pub fn dispose(config: &Value) -> Result<()> {
    let root = validate_configuration(config)?;
    validate_storage(config)?;
    let ext4 = config.at("storage_kind").as_str() == Some("loop-ext4");
    let device = if ext4 {
        Some(
            mounts()?
                .into_iter()
                .find(|row| row.path == root)
                .ok_or("storage mount missing")?
                .source,
        )
    } else {
        None
    };
    let root_text = root.to_string_lossy().into_owned();
    // The caller must confirm container disposal first: another mount namespace
    // may retain a bind even after this namespace unmounts its source.
    host(&["umount", &root_text], 120)?;
    require(!is_mount(&root)?, "job storage disposal was not confirmed")?;
    if let Some(device) = device {
        let image = PathBuf::from(config.at("storage_image").as_str().unwrap_or(""));
        detach_loop(&device, &image)?;
        fs::remove_file(&image).map_err(|e| e.to_string())?;
    }
    fs::remove_dir(&root).map_err(|e| e.to_string())
}

/// `validate_storage(config, writable_paths)`: every writable bind is a real
/// directory on the job filesystem, never the root itself or another device.
pub fn validate_storage_paths(config: &Value, writable: &[PathBuf]) -> Result<Value> {
    let observation = validate_storage(config)?;
    let root = PathBuf::from(config.at("storage_root").as_str().unwrap_or(""));
    for path in writable {
        require(
            path.is_dir()
                && exact_path(path)
                && !path.is_symlink()
                && *path != root
                && path.starts_with(&root),
            "writable bind escapes job storage quota",
        )?;
        let device = fs::metadata(path).map_err(|e| e.to_string())?.dev();
        let root_device = fs::metadata(&root).map_err(|e| e.to_string())?.dev();
        require(
            device == root_device,
            "writable bind uses another filesystem",
        )?;
    }
    Ok(observation)
}

/// `prepare_writable`: grant the remapped candidate ownership of its writable
/// binds without following candidate links or reowning hard-linked files.
pub fn prepare_writable(config: &Value, writable: &[PathBuf], uid: u64, gid: u64) -> Result<Value> {
    let observation = validate_storage_paths(config, writable)?;
    let uid_map = config.at("uid_map");
    let gid_map = config.at("gid_map");
    let span = |map: &Value| map.index(2).as_u64().unwrap_or(0);
    let start = |map: &Value| map.index(1).as_u64().unwrap_or(0);
    require(
        0 < uid && uid < span(uid_map) && 0 < gid && gid < span(gid_map),
        "candidate identity outside subordinate map",
    )?;
    let (mapped_uid, mapped_gid) = ((start(uid_map) + uid) as u32, (start(gid_map) + gid) as u32);
    // os.fwalk(follow_symlinks=False): the top directory must open, an
    // unreadable subdirectory is skipped (onerror=None), and every listed
    // entry is stat'ed without following links (errors propagate).
    fn walk(directory: &Path, top: bool, uid: u32, gid: u32) -> Result<()> {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(e) if top => return Err(format!("{}: {e}", directory.display())),
            Err(_) => return Ok(()),
        };
        for entry in entries {
            let path = entry.map_err(|e| e.to_string())?.path();
            let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            let kind = metadata.file_type();
            if kind.is_file() || kind.is_dir() {
                if (metadata.uid(), metadata.gid()) != (uid, gid) {
                    require(
                        !kind.is_file() || metadata.nlink() == 1,
                        "hard-linked candidate output cannot be reowned",
                    )?;
                    std::os::unix::fs::lchown(&path, Some(uid), Some(gid))
                        .map_err(|e| e.to_string())?;
                }
                if kind.is_dir() {
                    walk(&path, false, uid, gid)?;
                }
            }
        }
        Ok(())
    }
    for path in writable {
        std::os::unix::fs::lchown(path, Some(mapped_uid), Some(mapped_gid))
            .map_err(|e| e.to_string())?;
        walk(path, true, mapped_uid, mapped_gid)?;
    }
    Ok(observation)
}

/// `validate_userns(config, daemon, inspected)`.
pub fn validate_userns_inspected(
    config: &Value,
    daemon: &Value,
    inspected: &Value,
) -> Result<Value> {
    let rows = validate_userns(config, daemon)?;
    require(
        inspected
            .at("HostConfig")
            .get("UsernsMode")
            .is_none_or(|mode| mode.as_str() == Some("")),
        "candidate must inherit the remapped user namespace",
    )?;
    Ok(rows)
}

fn bounded_proc(name: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut data = Vec::new();
    fs::File::open(format!("/proc/{name}"))
        .map_err(|e| e.to_string())?
        .take(65537)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    require(data.len() <= 65536, "kernel swap evidence exceeds bound")?;
    Ok(data)
}

fn byte_lines(data: &[u8]) -> Vec<&[u8]> {
    // bytes.splitlines(): \n, \r\n and \r terminate lines.
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\n' || data[i] == b'\r' {
            lines.push(&data[start..i]);
            if data[i] == b'\r' && data.get(i + 1) == Some(&b'\n') {
                i += 1;
            }
            start = i + 1;
        }
        i += 1;
    }
    if start < data.len() {
        lines.push(&data[start..]);
    }
    lines
}

fn fields(line: &[u8]) -> Vec<&[u8]> {
    line.split(|b| b.is_ascii_whitespace() || *b == 0x0b || *b == 0x0c)
        .filter(|f| !f.is_empty())
        .collect()
}

/// `kernel_no_swap()`: zero host swap capacity, with the observed evidence.
pub fn kernel_no_swap() -> Result<Value> {
    let swaps = bounded_proc("swaps")?;
    let meminfo = bounded_proc("meminfo")?;
    kernel_no_swap_from(&swaps, &meminfo)
}

pub fn kernel_no_swap_from(swaps: &[u8], meminfo: &[u8]) -> Result<Value> {
    let rows = byte_lines(swaps);
    let totals: Vec<&[u8]> = byte_lines(meminfo)
        .into_iter()
        .filter(|line| line.starts_with(b"SwapTotal:"))
        .collect();
    let header: [&[u8]; 5] = [b"Filename", b"Type", b"Size", b"Used", b"Priority"];
    let total: [&[u8]; 3] = [b"SwapTotal:", b"0", b"kB"];
    require(
        rows.len() == 1
            && fields(rows[0]) == header
            && totals.len() == 1
            && fields(totals[0]) == total,
        "runtime swap is unbounded: kernel has swap capacity or invalid evidence",
    )?;
    let ascii = |data: &[u8]| -> Result<String> {
        // bytes.decode('ascii') and its UnicodeDecodeError text.
        if let Some(position) = data.iter().position(|b| !b.is_ascii()) {
            return Err(format!(
                "'ascii' codec can't decode byte 0x{:02x} in position {position}: ordinal not in range(128)",
                data[position]
            ));
        }
        Ok(String::from_utf8_lossy(data).into_owned())
    };
    Ok(object([
        ("mechanism", "kernel-zero-swap-capacity".into()),
        ("effective_swap_bytes", 0u64.into()),
        ("proc_swaps", ascii(swaps)?.into()),
        ("proc_swaps_sha256", crate::sha256::hex(swaps).into()),
        ("swap_total_entry", ascii(totals[0])?.into()),
        (
            "swap_total_entry_sha256",
            crate::sha256::hex(totals[0]).into(),
        ),
    ]))
}

/// `validate_swap_bound(daemon, host, required_memory)`.
pub fn validate_swap_bound(daemon: &Value, host: &Value, required: u64) -> Result<Value> {
    require(
        required > 0 && host.at("Memory").is_int() && host.at("Memory").as_u64() == Some(required),
        "runtime Memory differs from the protected RAM bound",
    )?;
    let observed = host.at("MemorySwap");
    let swap_limit = daemon.at("SwapLimit").as_bool();
    let mut proof =
        if swap_limit == Some(true) && observed.is_int() && observed.as_u64() == Some(required) {
            object([
                ("mechanism", "docker-memory-swap-limit".into()),
                ("effective_swap_bytes", 0u64.into()),
            ])
        } else if swap_limit == Some(false)
            && observed.is_int()
            && (observed.as_u64() == Some(required) || observed.as_int() == Some(-1))
        {
            let mut proof = kernel_no_swap()?;
            proof.set("daemon_swap_limit", false.into());
            proof
        } else {
            return Err(
                "runtime MemorySwap/SwapLimit do not prove the protected no-swap request".into(),
            );
        };
    proof.set("requested_memory_swap_bytes", required.into());
    proof.set("observed_memory_swap_bytes", observed.clone());
    Ok(proof)
}

/// `recheck_swap_bound(proof)`: reobserve host backing after disposal.
pub fn recheck_swap_bound(proof: &mut Value) -> Result<()> {
    if proof.at("mechanism").as_str() == Some("kernel-zero-swap-capacity") {
        proof.set("after_disposal", kernel_no_swap()?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(base: &Path, kind: &str) -> Value {
        let mut value = object([
            ("storage_kind", kind.into()),
            (
                "storage_root",
                base.join("store").to_string_lossy().as_ref().into(),
            ),
            ("storage_bytes", (24 * GIB).into()),
            ("storage_inodes", 1048576u64.into()),
            ("storage_reserve_bytes", (6 * GIB).into()),
            (
                "uid_map",
                vec![0u64.into(), 524288u64.into(), 65536u64.into()].into(),
            ),
            (
                "gid_map",
                vec![0u64.into(), 524288u64.into(), 65536u64.into()].into(),
            ),
        ]);
        if kind == "loop-ext4" {
            value.set(
                "storage_image",
                base.join("job.ext4").to_string_lossy().as_ref().into(),
            );
        }
        value
    }

    fn base() -> PathBuf {
        fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join("busbar-ci-isolation")
    }

    #[test]
    fn configuration_contract_is_exact() {
        let base = base();
        validate_configuration(&config(&base, "loop-ext4")).unwrap();
        validate_configuration(&config(&base, "tmpfs")).unwrap();
        let mut tmpfs = config(&base, "loop-ext4");
        tmpfs.set("storage_kind", "tmpfs".into());
        assert!(
            validate_configuration(&tmpfs).is_err(),
            "tmpfs must not carry an image"
        );
        let cases: Vec<(&str, Value)> = vec![
            ("storage_kind", "overlay".into()),
            ("storage_root", "relative/store".into()),
            (
                "storage_root",
                base.join("a,b").to_string_lossy().as_ref().into(),
            ),
            (
                "storage_root",
                base.join("x/../store").to_string_lossy().as_ref().into(),
            ),
            ("storage_bytes", 4097u64.into()),
            ("storage_bytes", json::parse(b"1.5").unwrap()),
            ("storage_inodes", 8u64.into()),
            ("storage_reserve_bytes", 0u64.into()),
            ("storage_image", "/elsewhere/job.ext4".into()),
            (
                "uid_map",
                vec![0u64.into(), 1000u64.into(), 65536u64.into()].into(),
            ),
            (
                "gid_map",
                vec![1u64.into(), 524288u64.into(), 65536u64.into()].into(),
            ),
        ];
        for (key, value) in cases {
            let mut bad = config(&base, "loop-ext4");
            bad.set(key, value);
            assert!(validate_configuration(&bad).is_err(), "{key}");
        }
        let mut extra = config(&base, "loop-ext4");
        extra.set("unexpected", true.into());
        assert!(validate_configuration(&extra).is_err());
        // The storage root comes from protected configuration and must be link-free: a root
        // reached through a directory link refuses even though it is lexically exact.
        let linked = base.join(format!("linked-{}", std::process::id()));
        let _ = fs::remove_dir_all(&linked);
        fs::create_dir_all(linked.join("real")).unwrap();
        std::os::unix::fs::symlink(linked.join("real"), linked.join("link")).unwrap();
        for unsafe_root in [linked.join("link/store"), linked.join("link"), "/".into()] {
            let mut bad = config(&base, "tmpfs");
            bad.set(
                "storage_root",
                unsafe_root.to_string_lossy().as_ref().into(),
            );
            assert!(validate_configuration(&bad).is_err(), "{unsafe_root:?}");
        }
        fs::remove_dir_all(&linked).unwrap();
    }

    #[test]
    fn mount_table_requires_one_dedicated_filesystem_without_nesting() {
        let base = base();
        let value = config(&base, "loop-ext4");
        let root = base.join("store");
        let line = |path: &Path, kind: &str, source: &str, options: &str| {
            format!(
                "36 25 7:0 / {} {options} shared:1 - {kind} {source} rw",
                path.display()
            )
        };
        let good = parse_mounts(&line(
            &root,
            "ext4",
            "/dev/loop7",
            "rw,nosuid,nodev,relatime",
        ))
        .unwrap();
        assert_eq!(check_mounts(&value, &root, &good).unwrap(), "/dev/loop7");
        for rows in [
            line(&root, "tmpfs", "busbar-job", "rw,nosuid,nodev"),
            line(&root, "ext4", "/dev/loop7", "rw,nodev"),
            format!(
                "{}\n{}",
                line(&root, "ext4", "/dev/loop7", "rw,nosuid,nodev"),
                line(&root.join("nested"), "tmpfs", "x", "rw,nosuid,nodev")
            ),
            String::new(),
        ] {
            assert!(
                check_mounts(&value, &root, &parse_mounts(&rows).unwrap()).is_err(),
                "{rows}"
            );
        }
        let escaped = parse_mounts("1 2 0:1 / /a\\040b rw - tmpfs x rw").unwrap();
        assert_eq!(escaped[0].path, PathBuf::from("/a b"));
    }

    #[test]
    fn loop_identity_and_geometry() {
        assert_eq!(device_numbers((259 << 8) | 3), "259:3");
        assert_eq!(device_numbers((8 << 8) | 5 | (1 << 20)), "8:261");
        let row = json::parse(
            br#"{"name":"/dev/loop7","back-file":"/srv/x/job.ext4","back-ino":12,"back-maj:min":"259:3","sizelimit":4096,"offset":0,"ro":false}"#,
        )
        .unwrap();
        let image = Path::new("/srv/x/job.ext4");
        assert!(loop_matches(&row, "/dev/loop7", image, 12, "259:3", 4096));
        assert!(!loop_matches(&row, "/dev/loop7", image, 13, "259:3", 4096));
        assert!(!loop_matches(&row, "/dev/loop7", image, 12, "259:3", 8192));
        assert!(
            is_loop_device("/dev/loop12")
                && !is_loop_device("/dev/loop")
                && !is_loop_device("/dev/sda")
        );
        assert_eq!(
            ext4_inodes(24 * GIB, 1048576).unwrap(),
            1048576 / (192 * 8) * (192 * 8)
        );
        assert!(ext4_inodes(64 << 20, 100).is_err());
    }

    /// Needs host root with mount/loop privileges (run with `--ignored` in a
    /// privileged Linux container); proves prepare/dispose on the real kernel.
    #[test]
    #[ignore]
    fn privileged_storage_round_trip() {
        let parent = PathBuf::from(format!("/run/busbar-ci-storage-{}", std::process::id()));
        fs::create_dir(&parent).unwrap();
        for kind in ["tmpfs", "loop-ext4"] {
            let mut value = config(&parent, kind);
            value.set("storage_bytes", (256u64 << 20).into());
            value.set("storage_inodes", 4096u64.into());
            value.set(
                "storage_reserve_bytes",
                if kind == "tmpfs" { 0u64 } else { 4096 }.into(),
            );
            let observation = prepare(&value).unwrap();
            assert_eq!(
                observation.at("filesystem").as_str(),
                Some(if kind == "tmpfs" { "tmpfs" } else { "ext4" })
            );
            assert!(observation.at("bytes").as_u64().unwrap() <= 256 << 20);
            assert!(prepare(&value).unwrap_err().contains("fresh"));
            let root = parent.join("store");
            fs::create_dir(root.join("nested")).unwrap();
            host(
                &[
                    "mount",
                    "-t",
                    "tmpfs",
                    "nested",
                    root.join("nested").to_str().unwrap(),
                ],
                30,
            )
            .unwrap();
            assert!(
                validate_storage(&value)
                    .unwrap_err()
                    .contains("nested mount")
            );
            host(&["umount", root.join("nested").to_str().unwrap()], 30).unwrap();
            dispose(&value).unwrap();
            assert!(!root.exists() && !parent.join("job.ext4").exists());
            assert!(dispose(&value).is_err(), "second disposal must refuse");
        }
        fs::remove_dir(&parent).unwrap();
    }

    #[test]
    fn userns_daemon_is_required() {
        let value = config(&base(), "loop-ext4");
        let daemon =
            json::parse(br#"{"SecurityOptions":["name=seccomp,profile=builtin","name=userns"]}"#)
                .unwrap();
        assert_eq!(
            validate_userns(&value, &daemon).unwrap().at("uid_map"),
            value.at("uid_map")
        );
        let plain =
            json::parse(br#"{"SecurityOptions":["name=seccomp,profile=builtin"]}"#).unwrap();
        assert!(validate_userns(&value, &plain).is_err());
        assert!(validate_userns(&value, &json::parse(b"{}").unwrap()).is_err());
    }

    #[test]
    fn supported_swap_limit_requires_the_exact_protected_bound() {
        let daemon = json::parse(br#"{"SwapLimit": true}"#).unwrap();
        let host = json::parse(br#"{"Memory": 1073741824, "MemorySwap": 1073741824}"#).unwrap();
        let proof = validate_swap_bound(&daemon, &host, 1 << 30).unwrap();
        assert_eq!(
            json::dumps(&proof, false),
            "{\"mechanism\": \"docker-memory-swap-limit\", \"effective_swap_bytes\": 0, \"requested_memory_swap_bytes\": 1073741824, \"observed_memory_swap_bytes\": 1073741824}"
        );
        let doubled = json::parse(br#"{"Memory": 1073741824, "MemorySwap": 2147483648}"#).unwrap();
        assert_eq!(
            validate_swap_bound(&daemon, &doubled, 1 << 30).unwrap_err(),
            "runtime MemorySwap/SwapLimit do not prove the protected no-swap request"
        );
        let unlimited = json::parse(br#"{"Memory": 1073741824, "MemorySwap": -1}"#).unwrap();
        assert!(validate_swap_bound(&daemon, &unlimited, 1 << 30).is_err());
        let other = json::parse(br#"{"Memory": 1, "MemorySwap": 1}"#).unwrap();
        assert_eq!(
            validate_swap_bound(&daemon, &other, 1 << 30).unwrap_err(),
            "runtime Memory differs from the protected RAM bound"
        );
    }

    #[test]
    fn unsupported_swap_requires_zero_kernel_backing_evidence() {
        let swaps = b"Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
        let meminfo = b"MemTotal:       8000000 kB\nSwapTotal:             0 kB\nSwapFree: 0 kB\n";
        let proof = kernel_no_swap_from(swaps, meminfo).unwrap();
        assert_eq!(
            proof.at("mechanism").as_str(),
            Some("kernel-zero-swap-capacity")
        );
        assert_eq!(
            proof.at("swap_total_entry").as_str(),
            Some("SwapTotal:             0 kB")
        );
        assert_eq!(
            proof.at("proc_swaps_sha256").as_str(),
            Some(crate::sha256::hex(swaps).as_str())
        );
        let swapping = b"Filename Type Size Used Priority\n/swapfile file 1024 0 -2\n";
        assert!(kernel_no_swap_from(swapping, meminfo).is_err());
        let backed = b"SwapTotal:       1024 kB\n";
        assert!(kernel_no_swap_from(swaps, backed).is_err());
    }
}
