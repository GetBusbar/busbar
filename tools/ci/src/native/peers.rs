//! Pinned service peers with no host or external network route (former
//! `native_service_peers.Peers`). Peer root is a remapped identity; image
//! root is read-only and writable image folders are copied into the bounded
//! job filesystem. Candidates only receive opaque streams to a pinned network
//! namespace and fixed loopback port.
use super::Q;
use super::fixtures::Services;
use super::sp::{self, Io, R, Spec, at, runtime, value_error};
use crate::isolation;
use crate::json::{self, Value, object};
use crate::sha256;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

pub const PORTS: [(&str, i128); 6] = [
    ("postgres", 5432),
    ("mysql", 3306),
    ("valkey", 6379),
    ("vault", 8200),
    ("wiremock", 8080),
    ("openldap", 389),
];

fn writable(service: &str) -> &'static [&'static str] {
    match service {
        "postgres" => &["/var/lib/postgresql/data", "/var/run/postgresql"],
        "mysql" => &["/var/lib/mysql", "/var/run/mysqld"],
        "valkey" => &["/data"],
        "vault" => &["/vault/file", "/vault/logs", "/home/vault"],
        "wiremock" => &["/home/wiremock"],
        "openldap" => &[
            "/root",
            "/etc",
            "/usr/sbin",
            "/var/lib/ldap",
            "/container",
            "/var/run",
            "/var/cache",
            "/var/log",
            "/var/backups",
            "/var/lib/dpkg",
        ],
        _ => &[],
    }
}

fn environment(service: &str) -> &'static [(&'static str, &'static str)] {
    match service {
        "postgres" => &[
            ("POSTGRES_USER", "busbar"),
            ("POSTGRES_PASSWORD", "busbar"),
            ("POSTGRES_DB", "busbar_store_qa"),
        ],
        "mysql" => &[
            ("MYSQL_ROOT_PASSWORD", "busbar"),
            ("MYSQL_USER", "busbar"),
            ("MYSQL_PASSWORD", "busbar"),
            ("MYSQL_DATABASE", "busbar_store_qa"),
        ],
        "vault" => &[
            ("VAULT_DEV_ROOT_TOKEN_ID", "busbar-fixture"),
            ("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200"),
            ("SKIP_SETCAP", "true"),
            ("SKIP_CHOWN", "true"),
        ],
        "openldap" => &[
            ("LDAP_ORGANISATION", "Example Org"),
            ("LDAP_DOMAIN", "example.org"),
            ("LDAP_ADMIN_PASSWORD", "adminpassword"),
            ("LDAP_TLS", "false"),
        ],
        _ => &[],
    }
}

fn command(service: &str) -> &'static [&'static str] {
    match service {
        "mysql" => &["--log-bin-trust-function-creators=1"],
        "vault" => &["server", "-dev"],
        _ => &[],
    }
}

const CAPS: [&str; 6] = [
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "SETGID",
    "SETUID",
    "NET_BIND_SERVICE",
];
const TMPFS_PATH: &str = "/tmp";
const TMPFS_OPTIONS: &str = "rw,nosuid,nodev,size=64m,nr_inodes=4096,mode=1777";
const GIB: i128 = 1 << 30;

/// `ldap_readiness_command(name)` (from `native_fixtures`): probe only after
/// the pinned image's first-start bootstrap marker exists.
pub fn ldap_readiness(name: &str) -> Vec<String> {
    sp::strings(&[
        "docker",
        "exec",
        name,
        "sh",
        "-ec",
        "test -f \"$1\"; shift; exec ldapsearch \"$@\"",
        "ldap-ready",
        "/container/run/state/slapd-first-start-done",
        "-x",
        "-H",
        "ldap://127.0.0.1",
        "-D",
        "cn=admin,dc=example,dc=org",
        "-w",
        "adminpassword",
        "-b",
        "dc=example,dc=org",
    ])
}

fn path_class(text: &str, absolute: bool) -> bool {
    let body = if absolute {
        match text.strip_prefix('/') {
            Some(rest) => rest,
            None => return false,
        }
    } else {
        text
    };
    !body.is_empty()
        && body
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.+-".contains(&c) || (absolute && c == b'/'))
}

/// `elf_dependencies(output)`: the fixed image's loader listing, never shell text.
pub fn elf_dependencies(output: &str) -> R<(Vec<(String, String)>, String)> {
    if output.trim().is_empty() || output.chars().count() > 16384 {
        return Err(value_error("invalid fixture ELF dependency listing"));
    }
    let mut paths: Vec<(String, String)> = Vec::new();
    let mut loaders = Vec::new();
    for line in super::staged::splitlines(output) {
        let core = line.trim();
        let Some(open) = core.rfind(" (0x") else {
            return Err(value_error("unresolved or invalid fixture ELF dependency"));
        };
        let address = &core[open + 4..];
        let valid_address = address.strip_suffix(')').is_some_and(|hex| {
            !hex.is_empty()
                && hex
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        });
        if !valid_address {
            return Err(value_error("unresolved or invalid fixture ELF dependency"));
        }
        let left = &core[..open];
        if left == "linux-vdso.so.1" {
            continue;
        }
        let path = match left.split_once(" => ") {
            Some((name, path))
                if (path_class(name, false) || path_class(name, true))
                    && path_class(path, true) =>
            {
                path
            }
            None if path_class(left, true) => left,
            _ => return Err(value_error("unresolved or invalid fixture ELF dependency")),
        };
        let normalized: PathBuf = Path::new(path).components().collect();
        if Path::new(path)
            .components()
            .any(|c| c == Component::ParentDir)
            || sp::text(&normalized) != path
            || path.contains("/./")
            || path.ends_with("/.")
            || paths.len() >= 64
        {
            return Err(value_error("invalid fixture ELF dependency path"));
        }
        let name = normalized
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Some((_, existing)) = paths.iter().find(|(n, _)| *n == name) {
            if existing != path {
                return Err(value_error("ambiguous fixture ELF dependency basename"));
            }
        } else {
            paths.push((name.clone(), path.to_owned()));
        }
        if name.starts_with("ld-linux-") {
            loaders.push(path.to_owned());
        }
    }
    if loaders.len() != 1 || paths.is_empty() {
        return Err(value_error(
            "fixture ELF dependency listing lacks one loader",
        ));
    }
    Ok((paths, loaders.remove(0)))
}

/// `shlex.quote(text)`.
pub fn shell_quote(text: &str) -> String {
    if text.is_empty() {
        return "''".into();
    }
    if text
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&c))
    {
        return text.to_owned();
    }
    format!("'{}'", text.replace('\'', "'\"'\"'"))
}

struct Peer {
    service: String,
    name: String,
    port: i128,
}

pub struct Peers {
    peers: Vec<Peer>,
    names: Vec<String>,
    namespaces: Vec<i32>,
    root: PathBuf,
    daemon: Value,
}

fn first(rows: &Value) -> R<Value> {
    rows.as_array()
        .and_then(|r| r.first())
        .cloned()
        .ok_or_else(|| value_error("list index out of range"))
}

fn inode(path: &str) -> R<u64> {
    Ok(std::fs::metadata(path).at(Path::new(path))?.ino())
}

/// `PurePosixPath(name).parts` for a tar member.
fn member_parts(name: &str) -> (bool, Vec<String>) {
    let absolute = name.starts_with('/');
    let parts = name
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .map(str::to_owned)
        .collect();
    (absolute, parts)
}

impl Peers {
    pub fn new(q: &mut Q) -> R<Peers> {
        let job = q.job_id();
        if job.is_empty() || job.len() > 20 || !job.bytes().all(|c| c.is_ascii_digit()) {
            return Err(value_error("invalid protected fixture job identity"));
        }
        let root = q.control.join("service-peers");
        sp::mkdir(&root, 0o777, false)?;
        let execution = q.execution.as_ref().unwrap();
        let info = execution
            .client(&sp::strings(&["info", "--format", "{{json .}}"]))?
            .checked()?;
        let daemon = sp::loads(&info.stdout)?;
        isolation::validate_userns(execution.config.at("isolation"), &daemon)
            .map_err(sp::from_text)?;
        Ok(Peers {
            peers: Vec::new(),
            names: Vec::new(),
            namespaces: Vec::new(),
            root,
            daemon,
        })
    }

    fn client(q: &Q, args: &[String]) -> R<sp::Done> {
        q.execution.as_ref().unwrap().client(args)?.checked()
    }

    /// Stage the immutable service digest from the controller's public cache.
    fn image(&self, q: &Q, reference: &str) -> R<Value> {
        let execution = q.execution.as_ref().unwrap();
        let local = execution.client(&sp::strings(&["image", "inspect", reference]))?;
        if local.code == 0 {
            return first(&sp::loads(&local.stdout)?);
        }
        let collector =
            |args: &[&str]| sp::run(execution.collector_spec(&sp::strings(args)).capture());
        let mut export_reference = reference.to_owned();
        let mut found = collector(&["image", "inspect", reference])?;
        if found.code != 0 {
            // Same pinned public cache route as trusted scanner provisioning:
            // one bounded mirror attempt, never an anonymous Hub fallback loop.
            let (repository, pin) = reference
                .rsplit_once('@')
                .ok_or_else(|| value_error("not enough values to unpack (expected 2, got 1)"))?;
            let mut repository = repository.to_owned();
            let last = repository.rsplit('/').next().unwrap_or("").to_owned();
            if last.contains(':') {
                repository = repository
                    .rsplit_once(':')
                    .map(|(r, _)| r.to_owned())
                    .unwrap_or(repository);
            }
            if !repository.contains('/') {
                repository = format!("library/{repository}");
            }
            export_reference = format!("mirror.gcr.io/{repository}@{pin}");
            let mut pull = execution
                .collector_spec(&sp::strings(&["pull", &export_reference]))
                .capture();
            pull.timeout = Some((300.0, "300".into()));
            sp::run(pull)?.checked()?;
            found = collector(&["image", "inspect", &export_reference])?.checked()?;
        }
        let value = first(&sp::loads(&found.stdout)?)?;
        let pin = reference.rsplit('@').next().unwrap_or("");
        let present = value
            .at("RepoDigests")
            .as_array()
            .unwrap_or(&[])
            .iter()
            .any(|d| d.as_str().is_some_and(|d| d.ends_with(&format!("@{pin}"))));
        if !present {
            return Err(value_error(
                "fixture image digest is not present in trusted cache",
            ));
        }
        let mut save = execution.collector_spec(&sp::strings(&["save", &export_reference]));
        save.timeout = None;
        save.stdout = sp::Output::Capture;
        save.stderr = sp::Output::Null;
        let mut producer = sp::spawn(&mut save)?;
        let piped = producer.stdout.take().unwrap();
        let loaded = (|| -> R<sp::Done> {
            let mut load = execution.client_spec(&sp::strings(&["load"]))?.capture();
            load.timeout = Some((300.0, "300".into()));
            load.stdin = sp::Input::Pipe(piped);
            let loaded = sp::run(load)?.checked()?;
            let deadline = Instant::now() + Duration::from_secs(300);
            loop {
                if let Some(status) = producer.try_wait().map_err(|e| sp::os_error(&e, None))? {
                    if sp::returncode(status) != 0 {
                        return Err(runtime("cached fixture image export failed"));
                    }
                    return Ok(loaded);
                }
                if Instant::now() >= deadline {
                    return Err(sp::timeout_error(&save.argv, "300"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        if matches!(producer.try_wait(), Ok(None)) {
            let _ = producer.kill();
            let _ = producer.wait();
        }
        let loaded = loaded?;
        let identities: Vec<String> = loaded
            .text()
            .lines()
            .filter_map(|line| {
                line.strip_prefix("Loaded image ID: ")
                    .or_else(|| line.strip_prefix("Loaded image: "))
                    .filter(|rest| !rest.is_empty())
                    .map(str::to_owned)
            })
            .collect();
        if identities.len() != 1 {
            return Err(value_error(
                "fixture export did not produce exactly one image",
            ));
        }
        let imported = first(&sp::loads(
            &Self::client(q, &sp::strings(&["image", "inspect", &identities[0]]))?.stdout,
        )?)?;
        // Docker's containerd store identifies images by manifest while the
        // remapped legacy graph driver uses config IDs. Verify execution bytes.
        if ["RootFS", "Config", "Os", "Architecture"]
            .iter()
            .any(|k| imported.get(k) != value.get(k))
        {
            return Err(value_error(
                "imported fixture image execution content differs",
            ));
        }
        Ok(imported)
    }

    /// `mapped_copy(source, destination, name)`: copy an image folder into
    /// the bounded job filesystem under the remapped identity.
    fn mapped_copy(&self, q: &Q, source: &str, destination: &Path, name: &str) -> R<PathBuf> {
        sp::mkdir(destination, 0o777, false)?;
        let execution = q.execution.as_ref().unwrap();
        let isolation = execution.config.at("isolation");
        let number = |map: &str, i: usize| isolation.at(map).index(i).as_u64().unwrap_or(0);
        let (uid_start, gid_start) = (number("uid_map", 1), number("gid_map", 1));
        let (uid_count, gid_count) = (number("uid_map", 2), number("gid_map", 2));
        let mut argv = execution.docker.clone();
        argv.extend([
            "cp".to_owned(),
            format!("{name}:{source}/."),
            "-".to_owned(),
        ]);
        let mut spec = Spec::new(argv).env(&execution.client_env);
        spec.stdout = sp::Output::Capture;
        spec.stderr = sp::Output::Capture;
        let mut process = sp::spawn(&mut spec)?;
        let stdout = process.stdout.take().unwrap();
        let mut stderr = process.stderr.take().unwrap();
        let detail_reader = std::thread::spawn(move || {
            let mut detail = Vec::new();
            let _ = (&mut stderr).take(8192).read_to_end(&mut detail);
            detail
        });
        let pid = process.id();
        let (cancel, cancelled) = std::sync::mpsc::channel::<()>();
        let watchdog = std::thread::spawn(move || {
            if cancelled.recv_timeout(Duration::from_secs(120)).is_err() {
                crate::proc::signal_process(pid as i32, crate::proc::SIGKILL);
            }
        });
        let mut empty_archive = false;
        let outcome = (|| -> R<()> {
            let mut archive = crate::tar::Reader::new(stdout);
            let mut count = 0usize;
            let mut total = 0u64;
            loop {
                let entry = archive
                    .next()
                    .map_err(|e| sp::Error::new(sp::Kind::Value, format!("ReadError: {e}")))?;
                let Some(entry) = entry else {
                    if count == 0 {
                        empty_archive = true;
                        return Err(sp::Error::new(sp::Kind::Value, "empty header"));
                    }
                    break;
                };
                count += 1;
                let (absolute, parts) = member_parts(&entry.name);
                if absolute || parts.iter().any(|p| p == "..") || count > 100_000 {
                    return Err(value_error("invalid fixture image directory entry"));
                }
                let path = parts
                    .iter()
                    .fold(destination.to_owned(), |p, part| p.join(part));
                let indirect = sp::self_and_parents(&path)
                    .into_iter()
                    .skip(1)
                    .filter(|p| p.starts_with(destination))
                    .any(|p| sp::is_symlink(&p));
                if indirect {
                    return Err(value_error("indirect fixture image directory entry"));
                }
                let mut uid = entry.uid;
                let mut gid = entry.gid;
                // Remapped archive exports can already carry host subordinate
                // IDs. Avoid applying the namespace offset twice.
                if uid_start <= uid && uid < uid_start + uid_count {
                    uid -= uid_start;
                }
                if gid_start <= gid && gid < gid_start + gid_count {
                    gid -= gid_start;
                }
                if !(uid < uid_count && gid < gid_count) {
                    return Err(value_error(
                        "fixture image identity is outside subordinate range",
                    ));
                }
                if let Some(parent) = path.parent() {
                    sp::mkdirs(parent, true)?;
                }
                let symlink = entry.kind == b'2';
                match entry.kind {
                    b'5' => sp::mkdir(&path, 0o777, true)?,
                    b'0' | 0 | b'7' => {
                        if entry.size > 256 << 20 {
                            return Err(value_error("fixture image file exceeds bound"));
                        }
                        total += entry.size;
                        if total > 2 << 30 {
                            return Err(value_error("fixture image directory exceeds bound"));
                        }
                        let mut output = sp::create_new(&path)?;
                        let mut member = archive.data(entry.size);
                        std::io::copy(&mut member, &mut output)
                            .map_err(|e| sp::os_error(&e, Some(&path)))?;
                    }
                    b'2' => {
                        // Preserve image-internal symlinks without ever following them.
                        std::os::unix::fs::symlink(&entry.linkname, &path).at(&path)?;
                    }
                    b'1' => {
                        let (target_absolute, target_parts) = member_parts(&entry.linkname);
                        if target_absolute || target_parts.iter().any(|p| p == "..") {
                            return Err(value_error("indirect fixture image hard link"));
                        }
                        let original = target_parts
                            .iter()
                            .fold(destination.to_owned(), |p, part| p.join(part));
                        let indirect = sp::self_and_parents(&original)
                            .into_iter()
                            .skip(1)
                            .filter(|p| p.starts_with(destination))
                            .any(|p| sp::is_symlink(&p));
                        if !original.is_file() || sp::is_symlink(&original) || indirect {
                            return Err(value_error("missing fixture image hard link target"));
                        }
                        total += std::fs::metadata(&original).at(&original)?.len();
                        if total > 2 << 30 {
                            return Err(value_error("fixture image directory exceeds bound"));
                        }
                        let mut input = std::fs::File::open(&original).at(&original)?;
                        let mut output = sp::create_new(&path)?;
                        std::io::copy(&mut input, &mut output)
                            .map_err(|e| sp::os_error(&e, Some(&path)))?;
                    }
                    _ => return Err(value_error("special file in fixture image directory")),
                }
                if !symlink {
                    sp::chmod(&path, entry.mode & 0o1777)?;
                }
                std::os::unix::fs::lchown(
                    &path,
                    Some((uid_start + uid) as u32),
                    Some((gid_start + gid) as u32),
                )
                .at(&path)?;
            }
            let _ = archive.finish();
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                if let Some(status) = process.try_wait().map_err(|e| sp::os_error(&e, None))? {
                    if sp::returncode(status) != 0 {
                        return Err(runtime("fixture image directory export failed"));
                    }
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(sp::timeout_error(&spec.argv, "60"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        let _ = cancel.send(());
        let _ = watchdog.join();
        if matches!(process.try_wait(), Ok(None)) {
            let _ = process.kill();
        }
        let _ = process.wait();
        let detail =
            String::from_utf8_lossy(&detail_reader.join().unwrap_or_default()).into_owned();
        match outcome {
            Ok(()) => Ok(destination.to_owned()),
            Err(error) if empty_archive || error.message.starts_with("ReadError") => {
                if detail.contains("Could not find the file") {
                    std::os::unix::fs::chown(
                        destination,
                        Some(uid_start as u32),
                        Some(gid_start as u32),
                    )
                    .at(destination)?;
                    Ok(destination.to_owned())
                } else {
                    Err(runtime(format!(
                        "fixture image export failed for {source}: {}; {detail}",
                        error.message
                    )))
                }
            }
            Err(error) if error.kind == sp::Kind::Interrupted => Err(error),
            Err(error) => Err(runtime(format!(
                "fixture image export failed for {source}: {}; {detail}",
                error.message
            ))),
        }
    }

    fn start(&mut self, q: &mut Q, owner: &mut Services, service: &str) -> R<()> {
        let Some(index) = PORTS.iter().position(|(s, _)| *s == service) else {
            return Err(value_error("unknown or duplicate declared fixture"));
        };
        if self.peers.iter().any(|p| p.service == service) {
            return Err(value_error("unknown or duplicate declared fixture"));
        }
        let name = format!("busbar-peer-{}-{service}", q.job_id());
        let requested_image = owner.image(service)?;
        let image = self.image(q, &requested_image)?;
        let roots = writable(service);
        let declared = image
            .at("Config")
            .at("Volumes")
            .keys()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if declared.iter().any(|path| {
            !roots
                .iter()
                .any(|root| path == root || path.starts_with(&format!("{root}/")))
        }) {
            return Err(value_error("unbounded image-declared fixture volume"));
        }
        let image_id = sp::at_str(&image, "Id")?.to_owned();
        let source = format!("{name}-source");
        self.names.push(source.clone());
        Self::client(
            q,
            &sp::strings(&[
                "create",
                "--name",
                &source,
                "--network=none",
                "--entrypoint=/bin/true",
                &image_id,
            ]),
        )?;
        let mut folders: Vec<(PathBuf, String)> = Vec::new();
        let copied = (|| -> R<()> {
            for (i, path) in roots.iter().enumerate() {
                let folder =
                    self.mapped_copy(q, path, &self.root.join(format!("{service}-{i}")), &source)?;
                folders.push((folder, (*path).to_owned()));
            }
            Ok(())
        })();
        let removed = Self::client(q, &sp::strings(&["rm", "--force", "--volumes", &source]));
        self.names.retain(|n| *n != source);
        removed?;
        copied?;
        let execution = q.execution.as_ref().unwrap();
        let isolation = execution.config.at("isolation").clone();
        let mut writable_paths = vec![self.root.clone()];
        writable_paths.extend(folders.iter().map(|(p, _)| p.clone()));
        let storage = isolation::validate_storage_paths(&isolation, &writable_paths)
            .map_err(sp::from_text)?;
        if service == "openldap" {
            // The pinned upstream bootstrap rewrites /etc/hosts; keep that file
            // inside the job quota instead of the daemon-managed host file.
            let hosts = self.root.join("openldap-hosts");
            sp::write(
                &hosts,
                "127.0.0.1 localhost busbar-ldap.example.org\n::1 localhost\n",
            )?;
            let start = |map: &str| isolation.at(map).index(1).as_u64().unwrap_or(0) as u32;
            std::os::unix::fs::chown(&hosts, Some(start("uid_map")), Some(start("gid_map")))
                .at(&hosts)?;
            sp::chmod(&hosts, 0o644)?;
            folders.push((hosts, "/etc/hosts".into()));
        }
        let runtime_name = execution
            .config
            .get("runtime")
            .and_then(Value::as_str)
            .unwrap_or("runc")
            .to_owned();
        let (args, capabilities) = create_arguments(
            service,
            &name,
            &image_id,
            &folders,
            &runtime_name,
            &q.job_id(),
        );
        self.names.push(name.clone());
        Self::client(q, &args)?;
        let inspected = first(&sp::loads(
            &Self::client(q, &sp::strings(&["inspect", &name]))?.stdout,
        )?)?;
        let swap_bound = self.verify(
            q,
            &inspected,
            &image_id,
            &folders,
            &capabilities,
            &runtime_name,
        )?;
        Self::client(q, &sp::strings(&["start", &name]))?;
        let inspected = first(&sp::loads(
            &Self::client(q, &sp::strings(&["inspect", &name]))?.stdout,
        )?)?;
        if !at(at(&inspected, "State")?, "Running")?.truthy() {
            return Err(runtime("fixture failed before namespace capture"));
        }
        let pid = at(at(&inspected, "State")?, "Pid")?.clone();
        let pid_text = crate::py::str(&pid);
        for key in ["uid_map", "gid_map"] {
            let text = sp::read_text(Path::new(&format!("/proc/{pid_text}/{key}")))?;
            let rows: Vec<Value> = text
                .lines()
                .map(|row| -> R<Value> {
                    Ok(Value::Array(
                        row.split_whitespace()
                            .map(|n| sp::py_int(n).map(Value::int))
                            .collect::<R<Vec<_>>>()?,
                    ))
                })
                .collect::<R<Vec<_>>>()?;
            if Value::Array(rows) != Value::Array(vec![isolation.at(key).clone()]) {
                return Err(value_error("fixture kernel identity map differs"));
            }
        }
        if inode(&format!("/proc/{pid_text}/ns/pid"))? == inode("/proc/self/ns/pid")? {
            return Err(value_error("fixture shares controller PID namespace"));
        }
        let namespace = sp::openat(
            sp::AT_FDCWD,
            std::ffi::OsStr::new(&format!("/proc/{pid_text}/ns/net")),
            0,
        )?;
        self.namespaces.push(namespace);
        let namespace_inode = {
            use std::os::fd::{FromRawFd, IntoRawFd};
            let file = unsafe { std::fs::File::from_raw_fd(namespace) };
            let inode = file.metadata().map_err(|e| sp::os_error(&e, None))?.ino();
            let _ = file.into_raw_fd();
            inode
        };
        if namespace_inode == inode("/proc/self/ns/net")? {
            return Err(value_error("fixture shares controller network namespace"));
        }
        let again = first(&sp::loads(
            &Self::client(q, &sp::strings(&["inspect", &name]))?.stdout,
        )?)?;
        if !at(at(&again, "State")?, "Running")?.truthy()
            || at(at(&again, "State")?, "Pid")? != &pid
        {
            return Err(runtime("fixture process changed during namespace capture"));
        }
        let port = 27000 + index as i128;
        let peer_port = PORTS[index].1;
        owner.proxy().add(port, Some((namespace, peer_port)))?;
        self.peers.push(Peer {
            service: service.to_owned(),
            name: name.clone(),
            port,
        });
        let record = object([
            ("image", at(&inspected, "Image")?.clone()),
            ("requested_image", requested_image.into()),
            ("network", "none".into()),
            ("namespace_inode", namespace_inode.into()),
            (
                "capabilities",
                Value::Array(capabilities.iter().map(|c| c.as_str().into()).collect()),
            ),
            ("storage", storage),
            ("swap_bound", swap_bound),
            ("readonly_root", true.into()),
            ("memory_bytes", Value::int(GIB)),
            ("pids", Value::int(256)),
            ("uid_map", isolation.at("uid_map").clone()),
            ("port", Value::int(peer_port)),
        ]);
        if q.receipt.get("service_peers").is_none() {
            q.receipt.set("service_peers", Value::Object(Vec::new()));
        }
        q.receipt
            .get_mut("service_peers")
            .unwrap()
            .set(service, record);
        Ok(())
    }

    fn verify(
        &self,
        q: &Q,
        actual: &Value,
        image_id: &str,
        folders: &[(PathBuf, String)],
        capabilities: &[String],
        runtime_name: &str,
    ) -> R<Value> {
        let isolation = q.execution.as_ref().unwrap().config.at("isolation");
        isolation::validate_userns_inspected(isolation, &self.daemon, actual)
            .map_err(sp::from_text)?;
        let (requested, observed) = control_values(actual, image_id, capabilities, runtime_name)?;
        let host = at(actual, "HostConfig")?;
        let swap_bound = isolation::validate_swap_bound(&self.daemon, host, GIB as u64)
            .map_err(sp::from_text)?;
        let mismatches: Vec<(String, Value)> = requested
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(key, value)| key != "MemorySwap" && observed.at(key) != value)
            .map(|(key, value)| {
                (
                    key.clone(),
                    object([
                        ("requested", value.clone()),
                        ("observed", observed.at(key).clone()),
                    ]),
                )
            })
            .collect();
        if !mismatches.is_empty() {
            // Never serialize Config.Env or the full inspection: only bounded control fields.
            let detail = json::encoded(&Value::Object(mismatches));
            let detail = String::from_utf8_lossy(&detail[..detail.len() - 1]).into_owned();
            let detail: String = detail.chars().take(4096).collect();
            return Err(value_error(format!(
                "fixture runtime controls differ from protected request: {detail}"
            )));
        }
        let mut mounts: Vec<(String, String, bool)> = Vec::new();
        for mount in at(actual, "Mounts")?.as_array().unwrap_or(&[]) {
            if at(mount, "Type")?.as_str() != Some("tmpfs") {
                mounts.push((
                    sp::at_str(mount, "Source")?.to_owned(),
                    sp::at_str(mount, "Destination")?.to_owned(),
                    at(mount, "RW")?.truthy(),
                ));
            }
        }
        mounts.sort();
        mounts.dedup();
        let mut expected: Vec<(String, String, bool)> = folders
            .iter()
            .map(|(s, d)| (sp::text(s), d.clone(), true))
            .collect();
        expected.sort();
        expected.dedup();
        if mounts != expected {
            return Err(value_error(
                "fixture writable mounts differ from bounded storage",
            ));
        }
        Ok(swap_bound)
    }

    fn exec(q: &Q, name: &str, args: &[String], check: bool) -> R<sp::Done> {
        let mut argv = vec!["exec".to_owned(), name.to_owned()];
        argv.extend(args.iter().cloned());
        let done = q.execution.as_ref().unwrap().client(&argv)?;
        if check { done.checked() } else { Ok(done) }
    }

    fn peer(&self, service: &str) -> &Peer {
        self.peers.iter().find(|p| p.service == service).unwrap()
    }

    /// An executable copied out of a newer image keeps its complete ELF closure.
    fn stage_server_binary(
        &self,
        q: &mut Q,
        owner: &Services,
        service: &str,
        source: &str,
        fixture: &Path,
    ) -> R<PathBuf> {
        let name = self.peer(service).name.clone();
        let listing = Self::exec(q, &name, &sp::strings(&["ldd", source]), true)?;
        let (dependencies, loader_source) = elf_dependencies(&listing.text())?;
        let runtime_dir = fixture.join("runtime");
        sp::mkdir(&runtime_dir, 0o777, false)?;
        let binary = runtime_dir.join("server");
        let mut sources = vec![(binary.clone(), source.to_owned())];
        sources.extend(
            dependencies
                .iter()
                .map(|(n, p)| (runtime_dir.join(n), p.clone())),
        );
        let mut files: Vec<(String, Value)> = Vec::new();
        let mut total = 0u64;
        for (destination, path) in &sources {
            Self::client(
                q,
                &[
                    "cp".into(),
                    "-L".into(),
                    format!("{name}:{path}"),
                    sp::text(destination),
                ],
            )?;
            let observed = std::fs::symlink_metadata(destination).at(destination)?;
            total += observed.len();
            if !observed.file_type().is_file() || observed.nlink() != 1 || total > 128 << 20 {
                return Err(value_error(
                    "fixture ELF closure is not bounded regular files",
                ));
            }
            sp::chmod(destination, 0o755)?;
            let key = destination
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            files.retain(|(k, _)| *k != key);
            files.push((
                key,
                object([
                    ("source", path.as_str().into()),
                    ("bytes", observed.len().into()),
                    ("sha256", sha256::hex(&sp::read(destination)?).into()),
                ]),
            ));
        }
        let loader = runtime_dir.join(Path::new(&loader_source).file_name().unwrap_or_default());
        let command = vec![
            sp::text(&loader),
            "--inhibit-cache".into(),
            "--inhibit-rpath".into(),
            String::new(),
            "--library-path".into(),
            sp::text(&runtime_dir),
        ];
        let mut check = command.clone();
        check.extend(["--list".into(), sp::text(&binary)]);
        let listing = q.run_timeout(&format!("fixture-{service}-closure-check"), check, 30)?;
        let (resolved, _) = elf_dependencies(&sp::read_text(&listing)?)?;
        let mut actual: Vec<String> = resolved.iter().map(|(_, p)| p.clone()).collect();
        actual.sort();
        actual.dedup();
        let mut wanted: Vec<String> = dependencies
            .iter()
            .map(|(n, _)| sp::text(&runtime_dir.join(n)))
            .collect();
        wanted.sort();
        wanted.dedup();
        if actual != wanted {
            return Err(value_error(
                "fixture ELF closure resolved outside its pinned runtime",
            ));
        }
        let wrapper = fixture.join(format!("{service}-server"));
        let mut words = command.clone();
        words.push(sp::text(&binary));
        let joined = words
            .iter()
            .map(|w| shell_quote(w))
            .collect::<Vec<_>>()
            .join(" ");
        sp::write(
            &wrapper,
            format!("#!/bin/sh\nunset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT\nexec {joined} \"$@\"\n"),
        )?;
        sp::chmod(&wrapper, 0o755)?;
        let record = object([
            (
                "image",
                q.receipt
                    .at("service_peers")
                    .at(service)
                    .at("image")
                    .clone(),
            ),
            ("requested_image", owner.image(service)?.into()),
            ("files", Value::Object(files)),
            ("wrapper_sha256", sha256::hex(&sp::read(&wrapper)?).into()),
            (
                "resolved_libraries",
                Value::Object(
                    resolved
                        .iter()
                        .map(|(n, p)| (n.clone(), Value::from(p.as_str())))
                        .collect(),
                ),
            ),
        ]);
        if q.receipt.get("fixture_executables").is_none() {
            q.receipt
                .set("fixture_executables", Value::Object(Vec::new()));
        }
        q.receipt
            .get_mut("fixture_executables")
            .unwrap()
            .set(service, record);
        Ok(wrapper)
    }

    /// Fixed fixture diagnostics, never Config.Env or process arguments.
    fn readiness_failure(
        &self,
        q: &Q,
        service: &str,
        reason: &str,
        result: Option<&sp::Done>,
    ) -> sp::Error {
        let mut secrets: Vec<&str> = PORTS
            .iter()
            .flat_map(|(s, _)| environment(s).iter())
            .filter(|(k, _)| k.contains("PASSWORD") || k.contains("TOKEN"))
            .map(|(_, v)| *v)
            .collect();
        secrets.sort();
        secrets.dedup();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        let bounded = |value: &[u8], limit: usize| -> Value {
            let mut text = String::from_utf8_lossy(value).into_owned();
            for secret in &secrets {
                text = text.replace(secret, "[REDACTED]");
            }
            let count = text.chars().count();
            text.chars()
                .skip(count.saturating_sub(limit))
                .collect::<String>()
                .into()
        };
        let mut record = object([
            ("schema", "busbar.native-fixture-readiness/1".into()),
            ("service", service.into()),
            ("reason", reason.into()),
        ]);
        if let Some(result) = result {
            record.set(
                "last_readiness",
                object([
                    ("returncode", Value::int(result.code)),
                    ("stdout", bounded(&result.stdout, 4096)),
                    ("stderr", bounded(&result.stderr, 4096)),
                ]),
            );
        }
        let name = self.peer(service).name.clone();
        let mut probes: Vec<(&str, Vec<String>)> = vec![
            (
                "state",
                sp::strings(&["inspect", "--format", "{{json .State}}", &name]),
            ),
            ("logs", sp::strings(&["logs", "--tail", "100", &name])),
            (
                "processes",
                sp::strings(&["exec", &name, "ps", "-eo", "pid,ppid,state,comm"]),
            ),
        ];
        if service == "openldap" {
            probes.push((
                "bootstrap_marker",
                sp::strings(&[
                    "exec",
                    &name,
                    "test",
                    "-f",
                    "/container/run/state/slapd-first-start-done",
                ]),
            ));
        }
        let execution = q.execution.as_ref().unwrap();
        for (key, args) in probes {
            let limit = if key == "logs" { 16384 } else { 4096 };
            let value = execution.client_spec(&args).and_then(|mut spec| {
                spec.timeout = Some((5.0, "5".into()));
                sp::run(spec.capture())
            });
            let row = match value {
                Ok(done) => object([
                    ("returncode", Value::int(done.code)),
                    ("stdout", bounded(&done.stdout, limit)),
                    ("stderr", bounded(&done.stderr, limit)),
                ]),
                Err(error) => {
                    // Exception strings can contain the command; its class
                    // distinguishes timeout from collection failure.
                    let class = match error.kind {
                        sp::Kind::Timeout => "TimeoutExpired",
                        sp::Kind::Os => "FileNotFoundError",
                        _ => "ValueError",
                    };
                    object([("collection_error", class.into())])
                }
            };
            record.set(key, row);
        }
        let path = q.evidence.join(format!("fixture-{service}-readiness.json"));
        if let Err(error) = sp::write(&path, json::dumps_indent(&record) + "\n") {
            return error;
        }
        runtime(format!("{service} fixture {reason}"))
    }

    fn running(q: &Q, name: &str) -> R<bool> {
        let state = first(&sp::loads(
            &Self::client(q, &sp::strings(&["inspect", name]))?.stdout,
        )?)?;
        Ok(at(at(&state, "State")?, "Running")?.truthy())
    }

    fn wait(&self, q: &Q, service: &str, command: &[String]) -> R<()> {
        let deadline = Instant::now() + Duration::from_secs(120);
        let name = self.peer(service).name.clone();
        loop {
            let result = Self::exec(q, &name, command, false)?;
            if result.code == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(self.readiness_failure(
                    q,
                    service,
                    "failed bounded readiness",
                    Some(&result),
                ));
            }
            if !Self::running(q, &name)? {
                return Err(self.readiness_failure(
                    q,
                    service,
                    "exited during readiness",
                    Some(&result),
                ));
            }
            sp::poll_interrupt()?;
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    fn http_ready(&self, q: &Q, service: &str, path: &str) -> R<()> {
        let deadline = Instant::now() + Duration::from_secs(90);
        let peer = self.peer(service);
        let socket = q
            .execution
            .as_ref()
            .unwrap()
            .fixture_directory
            .join(format!("{}.sock", peer.port));
        loop {
            let ok = (|| -> std::io::Result<bool> {
                let mut stream = std::os::unix::net::UnixStream::connect(&socket)?;
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                stream.write_all(
                    format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept-Encoding: identity\r\n\r\n").as_bytes(),
                )?;
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n") && head.len() < 1024 {
                    if stream.read(&mut byte)? == 0 {
                        break;
                    }
                    head.push(byte[0]);
                }
                let line = String::from_utf8_lossy(&head);
                let mut fields = line.split_whitespace();
                Ok(fields.next().is_some_and(|v| v.starts_with("HTTP/"))
                    && fields.next() == Some("200"))
            })();
            if ok.unwrap_or(false) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(runtime(format!("{service} fixture HTTP readiness failed")));
            }
            if !Self::running(q, &peer.name)? {
                return Err(runtime(format!(
                    "{service} fixture exited during readiness"
                )));
            }
            sp::poll_interrupt()?;
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    pub fn provision(&mut self, q: &mut Q, owner: &mut Services, requested: &[String]) -> R<()> {
        // Start every peer before waiting on any: database initialisation and
        // JVM/LDAP boot then overlap instead of running back to back. Each peer
        // keeps its own bounded readiness check, in the same order.
        for service in requested {
            self.start(q, owner, service)?;
        }
        for service in requested {
            let peer = self.peer(service);
            let (name, port) = (peer.name.clone(), peer.port);
            let token = format!("busbar_oracle_{}_v4", owner.tag.replace('-', "_"));
            match service.as_str() {
                "postgres" => {
                    self.wait(q, service, &sp::strings(&["pg_isready", "-U", "busbar"]))?;
                    Self::exec(
                        q,
                        &name,
                        &sp::strings(&[
                            "psql",
                            "-U",
                            "busbar",
                            "-d",
                            "busbar_store_qa",
                            "-v",
                            "ON_ERROR_STOP=1",
                            "-c",
                            &format!("CREATE DATABASE {token}"),
                        ]),
                        true,
                    )?;
                    let url = format!("postgres://busbar:busbar@127.0.0.1:{port}/busbar_store_qa");
                    q.env.set("BUSBAR_TEST_POSTGRES_URL", url.as_str());
                    q.env.set("BUSBAR_TEST_POSTGRES_IMPORT_URL", url.as_str());
                    q.env.set(
                        "BUSBAR_TEST_POSTGRES_V4_URL",
                        url.replace("busbar_store_qa", &token),
                    );
                }
                "mysql" => {
                    self.wait(
                        q,
                        service,
                        &sp::strings(&[
                            "mysqladmin",
                            "ping",
                            "--protocol=TCP",
                            "-h",
                            "127.0.0.1",
                            "-ubusbar",
                            "-pbusbar",
                        ]),
                    )?;
                    Self::exec(
                        q,
                        &name,
                        &sp::strings(&[
                            "mysql",
                            "-uroot",
                            "-pbusbar",
                            "-e",
                            &format!(
                                "CREATE DATABASE {token}; GRANT ALL ON {token}.* TO 'busbar'@'%'"
                            ),
                        ]),
                        true,
                    )?;
                    let status = Self::exec(
                        q,
                        &name,
                        &sp::strings(&[
                            "mysql",
                            "-uroot",
                            "-pbusbar",
                            "-N",
                            "-B",
                            "--raw",
                            "-e",
                            "SHOW STATUS LIKE 'Caching_sha2_password_rsa_public_key'",
                        ]),
                        true,
                    )?
                    .text();
                    let pem = status
                        .split_once('\t')
                        .map(|(_, p)| p.to_owned())
                        .ok_or_else(|| value_error("list index out of range"))?;
                    let body = public_key_body(&pem).ok_or_else(|| {
                        runtime("pinned MySQL fixture did not expose its active RSA public key")
                    })?;
                    let compact: String = body.split_whitespace().collect();
                    let pin = sha256::hex(&super::oracle::b64decode(&compact)?);
                    let url = format!(
                        "mysql://busbar:busbar@127.0.0.1:{port}/busbar_store_qa?server_public_key_sha256={pin}"
                    );
                    q.env.set("BUSBAR_TEST_MYSQL_URL", url.as_str());
                    q.env.set("BUSBAR_TEST_MYSQL_ROOT_PASSWORD", "busbar");
                    q.env.set(
                        "BUSBAR_TEST_MYSQL_V4_URL",
                        url.replace("/busbar_store_qa?", &format!("/{token}?")),
                    );
                }
                "valkey" => {
                    self.wait(q, service, &sp::strings(&["valkey-cli", "ping"]))?;
                    let url = format!("redis://127.0.0.1:{port}/0");
                    for key in [
                        "BUSBAR_TEST_VALKEY_URL",
                        "BUSBAR_TEST_VALKEY_V4_URL",
                        "VALKEY_URL",
                        "BUSBAR_V4_TRANSPORT_URL",
                    ] {
                        q.env.set(key, url.as_str());
                    }
                    if owner.required.at("server_binary").as_str() == Some("valkey") {
                        let fixture = q.work.join("valkey-native");
                        sp::mkdir(&fixture, 0o777, false)?;
                        let binary = self.stage_server_binary(
                            q,
                            owner,
                            service,
                            "/usr/local/bin/valkey-server",
                            &fixture,
                        )?;
                        q.run_timeout(
                            "fixture-valkey-server-check",
                            vec![sp::text(&binary), "--version".into()],
                            30,
                        )?;
                        q.env.set("BUSBAR_V4_TEST_TMP", sp::text(&fixture));
                        q.env.set("BUSBAR_VALKEY_SERVER", sp::text(&binary));
                    }
                }
                "wiremock" => {
                    self.http_ready(q, service, "/__admin/mappings")?;
                    q.env.set(
                        "BUSBAR_TEST_WIREMOCK_URL",
                        format!("http://127.0.0.1:{port}"),
                    );
                }
                "vault" => {
                    self.http_ready(q, service, "/v1/sys/health")?;
                    q.env
                        .set("BUSBAR_TEST_VAULT_ADDR", format!("http://127.0.0.1:{port}"));
                    q.env.set("BUSBAR_TEST_VAULT_TOKEN", "busbar-fixture");
                }
                "openldap" => {
                    self.wait(q, service, &ldap_readiness(&name)[3..])?;
                    let seed = sp::read(&q.trusted.join("scripts/fixtures/auth-ldap/seed.ldif"))?;
                    let execution = q.execution.as_ref().unwrap();
                    let spec = execution
                        .client_spec(&sp::strings(&[
                            "exec",
                            "-i",
                            &name,
                            "ldapadd",
                            "-x",
                            "-H",
                            "ldap://127.0.0.1",
                            "-D",
                            "cn=admin,dc=example,dc=org",
                            "-w",
                            "adminpassword",
                        ]))?
                        .capture()
                        .input(seed);
                    sp::run(spec)?.checked()?;
                    q.env
                        .set("BUSBAR_TEST_LDAP_URL", format!("ldap://127.0.0.1:{port}"));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn close(&mut self, q: &mut Q) -> R<()> {
        let mut failed = Vec::new();
        for name in self.names.iter().rev() {
            let execution = q.execution.as_ref().unwrap();
            let removed = execution.client(&sp::strings(&["rm", "--force", "--volumes", name]))?;
            if removed.code != 0 && execution.client(&sp::strings(&["inspect", name]))?.code == 0 {
                failed.push(name.clone());
            }
        }
        if !failed.is_empty() {
            return Err(runtime(format!(
                "fixture peer disposal failed: {}",
                failed.join(", ")
            )));
        }
        self.names.clear();
        for fd in self.namespaces.drain(..) {
            sp::close(fd);
        }
        let mut zero_swap = false;
        if let Some(Value::Object(rows)) = q.receipt.get_mut("service_peers") {
            for (_, value) in rows.iter_mut() {
                value.set("disposed", true.into());
                zero_swap |= value.at("swap_bound").at("mechanism").as_str()
                    == Some("kernel-zero-swap-capacity");
            }
        }
        if zero_swap {
            let finale = isolation::kernel_no_swap().map_err(sp::from_text)?;
            if let Some(Value::Object(rows)) = q.receipt.get_mut("service_peers") {
                for (_, value) in rows.iter_mut() {
                    if let Some(proof) = value.get_mut("swap_bound")
                        && proof.at("mechanism").as_str() == Some("kernel-zero-swap-capacity")
                    {
                        proof.set("after_disposal", finale.clone());
                    }
                }
            }
        }
        Ok(())
    }
}

/// The PEM body of MySQL's active RSA public key status value.
fn public_key_body(pem: &str) -> Option<&str> {
    for (begin, end) in [
        ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"),
        (
            "-----BEGIN RSA PUBLIC KEY-----",
            "-----END RSA PUBLIC KEY-----",
        ),
    ] {
        if let Some(start) = pem.find(begin) {
            let rest = &pem[start + begin.len()..];
            if let Some(stop) = rest.find(end) {
                let body = &rest[..stop];
                if !body.is_empty()
                    && body.chars().all(|c| {
                        c.is_ascii_alphanumeric()
                            || c == '+'
                            || c == '/'
                            || c == '='
                            || c.is_whitespace()
                    })
                {
                    return Some(body);
                }
            }
        }
    }
    None
}

/// `create_arguments(service, name, image, writable)`.
pub fn create_arguments(
    service: &str,
    name: &str,
    image_id: &str,
    writable: &[(PathBuf, String)],
    runtime_name: &str,
    job: &str,
) -> (Vec<String>, Vec<String>) {
    let mut args = sp::strings(&[
        "create",
        "--name",
        name,
        "--pull=never",
        "--network=none",
        "--read-only",
        "--runtime",
    ]);
    args.push(runtime_name.into());
    args.extend(sp::strings(&[
        "--ipc=private",
        "--cgroupns=private",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--memory=1073741824",
        "--memory-swap=1073741824",
        "--cpus=1",
        "--pids-limit=256",
        "--shm-size=64m",
        "--log-driver=local",
        "--log-opt=max-size=1m",
        "--log-opt=max-file=1",
        "--log-opt=compress=false",
        "--label",
    ]));
    args.push(format!("busbar.admission.job={job}"));
    if service == "openldap" {
        args.extend(sp::strings(&[
            "--hostname",
            "busbar-ldap.example.org",
            "--add-host",
            "busbar-ldap.example.org:127.0.0.1",
        ]));
    }
    let mut capabilities = sp::strings(&CAPS);
    if service == "openldap" {
        capabilities.push("KILL".into());
    }
    for cap in &capabilities {
        args.push("--cap-add".into());
        args.push(cap.clone());
    }
    args.push("--tmpfs".into());
    args.push(format!("{TMPFS_PATH}:{TMPFS_OPTIONS}"));
    for (source, destination) in writable {
        args.push("--mount".into());
        args.push(format!(
            "type=bind,src={},dst={destination}",
            sp::text(source)
        ));
    }
    for (key, value) in environment(service) {
        args.push("--env".into());
        args.push(format!("{key}={value}"));
    }
    args.push(image_id.into());
    args.extend(sp::strings(command(service)));
    (args, capabilities)
}

/// `control_values(actual, image, capabilities)`: requested and observed controls.
pub fn control_values(
    actual: &Value,
    image_id: &str,
    capabilities: &[String],
    runtime_name: &str,
) -> R<(Value, Value)> {
    let host = at(actual, "HostConfig")?;
    let mut sorted_caps: Vec<String> = capabilities.to_vec();
    sorted_caps.sort();
    let strings =
        |values: &[String]| Value::Array(values.iter().map(|v| v.as_str().into()).collect());
    let kill = capabilities.iter().any(|c| c == "KILL");
    let requested = object([
        ("Image", image_id.into()),
        ("NetworkMode", "none".into()),
        ("Privileged", false.into()),
        ("ReadonlyRootfs", true.into()),
        ("PidMode", "".into()),
        ("IpcMode", "private".into()),
        ("CgroupnsMode", "private".into()),
        ("Runtime", runtime_name.into()),
        ("CapDrop", Value::Array(vec!["ALL".into()])),
        ("CapAdd", strings(&sorted_caps)),
        ("NoNewPrivileges", true.into()),
        ("Memory", Value::int(GIB)),
        ("MemorySwap", Value::int(GIB)),
        ("NanoCpus", Value::int(1_000_000_000)),
        ("PidsLimit", Value::int(256)),
        ("ShmSize", Value::int(64 << 20)),
        ("Tmpfs", object([(TMPFS_PATH, TMPFS_OPTIONS.into())])),
        (
            "ExtraHosts",
            Value::Array(if kill {
                vec!["busbar-ldap.example.org:127.0.0.1".into()]
            } else {
                Vec::new()
            }),
        ),
        ("PortBindings", Value::Object(Vec::new())),
        ("Devices", Value::Array(Vec::new())),
        (
            "LogConfig",
            object([
                ("Type", "local".into()),
                (
                    "Config",
                    object([
                        ("max-size", "1m".into()),
                        ("max-file", "1".into()),
                        ("compress", "false".into()),
                    ]),
                ),
            ]),
        ),
    ]);
    let mut observed = Value::Object(
        requested
            .as_object()
            .into_iter()
            .flatten()
            .map(|(k, _)| (k.clone(), host.at(k).clone()))
            .collect(),
    );
    let texts = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .unwrap_or(&[])
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()
    };
    let mut drop: Vec<String> = texts(at(host, "CapDrop")?);
    drop.sort();
    drop.dedup();
    let mut add: Vec<String> = texts(at(host, "CapAdd")?)
        .into_iter()
        .map(|c| c.strip_prefix("CAP_").map(str::to_owned).unwrap_or(c))
        .collect();
    add.sort();
    add.dedup();
    let security = texts(at(host, "SecurityOpt")?);
    let or_empty = |value: &Value, empty: Value| if value.truthy() { value.clone() } else { empty };
    observed.set("Image", at(actual, "Image")?.clone());
    observed.set("CapDrop", strings(&drop));
    observed.set("CapAdd", strings(&add));
    observed.set(
        "NoNewPrivileges",
        security.iter().any(|s| s == "no-new-privileges").into(),
    );
    observed.set(
        "ExtraHosts",
        or_empty(host.at("ExtraHosts"), Value::Array(Vec::new())),
    );
    observed.set(
        "PortBindings",
        or_empty(host.at("PortBindings"), Value::Object(Vec::new())),
    );
    observed.set(
        "Devices",
        or_empty(host.at("Devices"), Value::Array(Vec::new())),
    );
    Ok((requested, observed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_listing_is_parsed_without_shell_interpretation() {
        let listing = "\tlinux-vdso.so.1 (0x00007ffd)\n\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f00)\n\t/lib64/ld-linux-x86-64.so.2 (0x00007f01)\n";
        let (paths, loader) = elf_dependencies(listing).unwrap();
        assert_eq!(
            paths[0],
            ("libc.so.6".into(), "/lib/x86_64-linux-gnu/libc.so.6".into())
        );
        assert_eq!(loader, "/lib64/ld-linux-x86-64.so.2");
        assert!(elf_dependencies("libx.so => not found\n").is_err());
        assert!(
            elf_dependencies("libc.so.6 => /lib/../etc/x (0x1)\n/lib64/ld-linux-x86-64.so.2 (0x1)")
                .is_err()
        );
        assert_eq!(
            elf_dependencies("libc.so.6 => /lib/libc.so.6 (0x1)\n")
                .unwrap_err()
                .message,
            "fixture ELF dependency listing lacks one loader"
        );
    }

    #[test]
    fn shell_quoting_matches_shlex() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("/a/b.so"), "/a/b.so");
        assert_eq!(shell_quote("it's"), "'it'\"'\"'s'");
    }

    #[test]
    fn peer_request_is_exact_and_observed_controls_compare() {
        let (args, caps) = create_arguments(
            "openldap",
            "p",
            "sha256:x",
            &[(PathBuf::from("/s/0"), "/etc".into())],
            "runc",
            "42",
        );
        assert_eq!(caps.last().unwrap(), "KILL");
        assert!(
            args.windows(2)
                .any(|w| w == ["--mount", "type=bind,src=/s/0,dst=/etc"])
        );
        assert!(args.contains(&"busbar.admission.job=42".to_owned()));
        assert_eq!(args.last().unwrap(), "sha256:x");
        let actual = crate::json::parse(br#"{"Image": "sha256:x", "HostConfig": {"NetworkMode": "none", "Privileged": false, "ReadonlyRootfs": true, "PidMode": "", "IpcMode": "private", "CgroupnsMode": "private", "Runtime": "runc", "CapDrop": ["ALL"], "CapAdd": ["CAP_CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "NET_BIND_SERVICE", "KILL"], "SecurityOpt": ["no-new-privileges"], "Memory": 1073741824, "MemorySwap": 1073741824, "NanoCpus": 1000000000, "PidsLimit": 256, "ShmSize": 67108864, "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=64m,nr_inodes=4096,mode=1777"}, "ExtraHosts": ["busbar-ldap.example.org:127.0.0.1"], "PortBindings": null, "Devices": null, "LogConfig": {"Type": "local", "Config": {"max-file": "1", "max-size": "1m", "compress": "false"}}}}"#).unwrap();
        let (requested, observed) = control_values(&actual, "sha256:x", &caps, "runc").unwrap();
        assert_eq!(requested, observed);
    }
}
