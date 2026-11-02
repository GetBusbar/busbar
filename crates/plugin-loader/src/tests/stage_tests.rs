// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn staging_dir_is_private_and_pid_named() {
    let mut state = staging_state().lock().unwrap_or_else(|p| p.into_inner());
    let dir = ensure_staging_dir(&mut state).expect("staging dir");
    assert!(dir.exists());
    let name = dir.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with(STAGING_PREFIX));
    assert!(name.contains(&std::process::id().to_string()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "staging dir must be 0700, got {mode:o}");
    }

    let parent = staging_parent_in(&std::env::temp_dir());
    assert_eq!(dir.parent(), Some(parent.as_path()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "staging parent must be 0700, got {mode:o}");
    }

    assert_eq!(ensure_staging_dir(&mut state).unwrap(), dir);
}

#[test]
fn temp_file_staging_cleans_up_on_drop() {
    let (path, pin) = stage_temp_file(b"pretend library bytes").expect("stage");
    assert!(path.exists());
    drop(Staged::TempFile {
        path: path.clone(),
        pin: Some(pin),
    });
    assert!(!path.exists(), "staged file must be removed on drop");
}

#[cfg(unix)]
#[test]
fn sweep_removes_dead_pid_dirs_only() {
    let (path, pin) = stage_temp_file(b"keepalive bytes").expect("stage keepalive");
    let held = Staged::TempFile {
        path,
        pin: Some(pin),
    };
    let own = {
        let state = staging_state().lock().unwrap_or_else(|p| p.into_inner());
        state
            .dir
            .clone()
            .expect("staging dir exists while a file is live")
    };

    let mut proven = false;
    for _ in 0..5 {
        let dead = staging_parent_in(&std::env::temp_dir())
            .join(format!("{STAGING_PREFIX}4294967294-{}", random_hex(8)));
        std::fs::create_dir_all(dead.join("sub")).unwrap();
        std::fs::write(dead.join("sub/lib.so"), b"junk").unwrap();

        let removed = sweep_dead_staging();
        assert!(
            !dead.exists(),
            "a dead-pid staging dir survived the sweep — the sweep is broken"
        );
        assert!(
            own.exists(),
            "own (live-pid) staging dir survives the sweep"
        );
        if removed >= 1 {
            proven = true;
            break;
        }
    }
    assert!(
        proven,
        "five consecutive sweeps each found the fixture already removed by a concurrent sweeper; \
         either this host is running a pathological number of busbar processes or `removed` is \
         miscounted"
    );
    drop(held);
}

fn private_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("busbar-sweep-{tag}-{}", random_hex(8)));
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[cfg(unix)]
#[test]
fn sweep_skips_symlinked_dead_pid_entry() {
    use std::os::unix::fs::symlink;

    let root = private_root("symlink");
    let parent = ensure_staging_parent(&root).expect("parent");

    let victim = root.join("victim");
    std::fs::create_dir_all(&victim).unwrap();
    let canary = victim.join("canary");
    std::fs::write(&canary, b"do not delete").unwrap();

    let link = parent.join(format!("{STAGING_PREFIX}4294967294-{}", random_hex(8)));
    symlink(&victim, &link).unwrap();

    let removed = sweep_dead_staging_under(&root, &mut list_dir_names);

    assert_eq!(removed, 0);
    assert!(
        link.symlink_metadata().is_ok(),
        "the sweep removed a symlink instead of skipping it — it treated a symlink as a staging dir"
    );
    assert!(
        canary.exists(),
        "the sweep followed a symlink into the victim directory"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn sweep_lists_only_the_staging_parent_not_the_temp_root() {
    let root = private_root("bounded");
    for i in 0..10_000 {
        std::fs::write(root.join(format!("unrelated-{i}")), b"").unwrap();
    }
    let parent = ensure_staging_parent(&root).expect("parent");
    let dead = parent.join(format!("{STAGING_PREFIX}4294967294-{}", random_hex(8)));
    std::fs::create_dir_all(dead.join("sub")).unwrap();

    let mut listed_dirs: Vec<PathBuf> = Vec::new();
    let mut entries_seen = 0usize;
    let mut counting = |dir: &std::path::Path| {
        listed_dirs.push(dir.to_path_buf());
        let names = list_dir_names(dir)?;
        entries_seen += names.len();
        Ok(names)
    };
    let removed = sweep_dead_staging_under(&root, &mut counting);

    assert_eq!(
        listed_dirs,
        vec![parent.clone()],
        "the sweep must list the dedicated staging parent and nothing else"
    );
    assert_eq!(
        entries_seen, 1,
        "the sweep iterated {entries_seen} entries; only the parent's single staging dir may be \
         seen, never the 10,000 unrelated temp-root entries"
    );
    assert_eq!(removed, 1);
    assert!(!dead.exists(), "the dead-pid dir in the parent is removed");
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn sweep_in_parent_removes_dead_keeps_live() {
    let root = private_root("liveness");
    let parent = ensure_staging_parent(&root).expect("parent");
    let dead = parent.join(format!("{STAGING_PREFIX}4294967294-{}", random_hex(8)));
    std::fs::create_dir_all(dead.join("sub")).unwrap();
    std::fs::write(dead.join("sub/lib.so"), b"junk").unwrap();
    let own = parent.join(format!(
        "{STAGING_PREFIX}{}-{}",
        std::process::id(),
        random_hex(8)
    ));
    std::fs::create_dir_all(&own).unwrap();
    let live_pid = std::os::unix::process::parent_id();
    assert!(
        pid_alive(live_pid),
        "precondition: our parent process is alive"
    );
    let live = parent.join(format!("{STAGING_PREFIX}{live_pid}-{}", random_hex(8)));
    std::fs::create_dir_all(&live).unwrap();
    let legacy = root.join(format!("{STAGING_PREFIX}4294967294-{}", random_hex(8)));
    std::fs::create_dir_all(&legacy).unwrap();

    let removed = sweep_dead_staging_under(&root, &mut list_dir_names);

    assert_eq!(removed, 1, "exactly the one dead-pid dir is removed");
    assert!(!dead.exists(), "dead-pid staging dir must be removed");
    assert!(own.exists(), "this process's staging dir must be kept");
    assert!(live.exists(), "a live process's staging dir must be kept");
    assert!(legacy.exists(), "legacy top-level layout is not swept");
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn symlinked_staging_parent_is_refused_and_not_swept() {
    use std::os::unix::fs::symlink;
    let root = private_root("parentlink");
    let elsewhere = root.join("elsewhere");
    let victim = elsewhere.join(format!("{STAGING_PREFIX}4294967294-{}", random_hex(8)));
    std::fs::create_dir_all(&victim).unwrap();
    symlink(&elsewhere, staging_parent_in(&root)).unwrap();

    assert!(
        ensure_staging_parent(&root).is_err(),
        "a symlinked parent is refused"
    );
    let mut listed = 0usize;
    let removed = sweep_dead_staging_under(&root, &mut |d| {
        listed += 1;
        list_dir_names(d)
    });
    assert_eq!(
        (removed, listed),
        (0, 0),
        "a symlinked parent is never listed"
    );
    assert!(victim.exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn loose_staging_parent_is_tightened_to_0700() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = private_root("loose");
    let parent = staging_parent_in(&root);
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    ensure_staging_parent(&root).expect("adopt own parent");
    let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn pid_liveness() {
    assert!(pid_alive(std::process::id()));
    assert!(!pid_alive(4_294_967_294));
}

#[cfg(target_os = "linux")]
const REUSED_FD_CHILD: &str = "BUSBAR_STAGE_REUSED_FD_CHILD";

#[cfg(target_os = "linux")]
fn build_probe_library(dir: &std::path::Path, stem: &str, src: &str, extra: &[&str]) -> Vec<u8> {
    let c = dir.join(format!("{stem}.c"));
    let so = dir.join(format!("{stem}.so"));
    std::fs::write(&c, src).expect("write probe source");
    let out = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&c)
        .args(extra)
        .output()
        .expect("run cc (the system C compiler rustc links with)");
    assert!(
        out.status.success(),
        "cc failed building {stem}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&so).expect("read probe library")
}

#[cfg(target_os = "linux")]
#[test]
fn a_replaced_image_on_a_reused_fd_runs_its_own_bytes() {
    if std::env::var_os(REUSED_FD_CHILD).is_none() {
        let out = std::process::Command::new(std::env::current_exe().expect("test binary path"))
            .args([
                "--exact",
                "stage::tests::a_replaced_image_on_a_reused_fd_runs_its_own_bytes",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(REUSED_FD_CHILD, "1")
            .output()
            .expect("re-exec the test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "the replaced-plugin child failed (status {:?}):\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
            out.status
        );
        return;
    }

    let dir = std::env::temp_dir().join(format!(
        "busbar-stage-reused-fd-{}-{}",
        std::process::id(),
        random_hex(4)
    ));
    std::fs::create_dir(&dir).expect("probe build dir");
    let a = build_probe_library(
        &dir,
        "probe_a",
        "int busbar_stage_probe(void) { return 1; }\nint busbar_stage_only_a(void) { return 1; }\n",
        &["-Wl,-z,nodelete"],
    );
    let b = build_probe_library(
        &dir,
        "probe_b",
        "int busbar_stage_probe(void) { return 2; }\nint busbar_stage_only_b(void) { return 2; }\n",
        &[],
    );
    let _ = std::fs::remove_dir_all(&dir);

    type Probe = unsafe extern "C" fn() -> i32;

    let (lib_a, staged_a) = load_library_from_bytes(&a, "probe-a").expect("stage plugin A");
    // SAFETY: the symbol is the `int (void)` function compiled above.
    let from_a = unsafe {
        lib_a
            .get::<Probe>(b"busbar_stage_probe")
            .expect("A's probe")()
    };
    assert_eq!(from_a, 1, "plugin A answers with A's bytes");

    crate::dlclose_on_worker(lib_a);
    drop(staged_a);

    let (lib_b, staged_b) = load_library_from_bytes(&b, "probe-b").expect("stage plugin B");
    // SAFETY: as above.
    let from_b = unsafe {
        lib_b
            .get::<Probe>(b"busbar_stage_probe")
            .expect("B's probe")()
    };
    assert_eq!(
        from_b, 2,
        "plugin B was loaded but plugin A's resident image answered: the replacement's verified \
         bytes never ran"
    );
    // SAFETY: as above.
    let only_b = unsafe { lib_b.get::<Probe>(b"busbar_stage_only_b") };
    assert!(
        only_b.is_ok(),
        "B's own symbol must resolve on B's handle (it resolved against A's image instead)"
    );
    // SAFETY: as above.
    let only_a = unsafe { lib_b.get::<Probe>(b"busbar_stage_only_a") };
    assert!(only_a.is_err(), "A's symbol must not answer on B's handle");

    crate::dlclose_on_worker(lib_b);
    drop(staged_b);
}

mod staged_file_pin {
    use super::*;

    pub(super) fn two_libraries() -> (Vec<u8>, Vec<u8>) {
        let verified = std::fs::read(crate::both_ways::example_cdylib("json_contract_auth"))
            .expect("read the verified fixture library");
        // Only the verified image is ever allowed to load. The staged-file check must refuse
        // these changed bytes before dlopen; an invalid-image error cannot pass assert_refused.
        let mut other = verified.clone();
        other[0] ^= 0xff;
        assert_ne!(verified, other, "the two fixtures must differ");
        (verified, other)
    }

    pub(super) fn release(loaded: (Library, Staged)) {
        let (lib, staged) = loaded;
        crate::dlclose_on_worker(lib);
        drop(staged);
    }

    pub(super) fn tamper_then_load(
        verified: &[u8],
        tamper: impl FnOnce(&std::path::Path) -> std::io::Result<()>,
    ) -> (std::io::Result<()>, Result<(Library, Staged), String>) {
        let mut tamper = Some(tamper);
        let mut outcome = None;
        let loaded = load_via_staged_file(verified, "w23-tamper", &mut |path| {
            if let Some(t) = tamper.take() {
                outcome = Some(t(path));
            }
        });
        (
            outcome.expect("the loader ran its before-load window"),
            loaded,
        )
    }

    pub(super) fn clean_load_holds_the_verified_bytes(verified: &[u8]) {
        let mut seen = None;
        let loaded = load_via_staged_file(verified, "w23-clean", &mut |path| {
            seen = Some(std::fs::read(path).expect("read the staged file"));
        })
        .expect("the verified bytes load");
        assert_eq!(
            seen.as_deref(),
            Some(verified),
            "the staged file must hold exactly the verified bytes"
        );
        release(loaded);
    }

    pub(super) fn assert_refused(what: &str, loaded: Result<(Library, Staged), String>) {
        match loaded {
            Ok(l) => {
                release(l);
                panic!(
                    "{what}: the loader mapped a staged file that no longer holds the verified \
                     bytes (the bytes that loaded are not the bytes that were verified)"
                );
            }
            Err(e) => assert!(
                e.contains("refusing to load"),
                "{what}: refused, but not by the staged-file check: {e}"
            ),
        }
    }
}

#[cfg(unix)]
mod on_unix {
    use super::staged_file_pin::*;
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn the_staged_bytes_are_the_verified_bytes() {
        let (verified, other) = two_libraries();
        clean_load_holds_the_verified_bytes(&verified);

        let (tampered, loaded) = tamper_then_load(&verified, |path| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)?;
            f.write_all(&other)?;
            f.flush()
        });
        tampered.expect("the owning uid can rewrite its own staged file in place");
        assert_refused("staged file rewritten in place", loaded);

        let (tampered, loaded) = tamper_then_load(&verified, |path| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
            let last = verified.len() as u64 - 1;
            std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(last))?;
            f.write_all(&[verified[verified.len() - 1] ^ 0xff])?;
            f.flush()?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
        });
        tampered.expect("the owning uid can flip a byte of its own staged file");
        assert_refused("staged file with one byte flipped", loaded);
    }

    #[test]
    fn a_staged_file_swapped_between_verify_and_load_is_refused() {
        let (verified, other) = two_libraries();

        let (swapped, loaded) = tamper_then_load(&verified, |path| {
            let decoy = path.with_extension("decoy");
            std::fs::write(&decoy, &other)?;
            std::fs::rename(&decoy, path)
        });
        swapped.expect("the owning uid can rename inside its own staging directory");
        assert_refused("staged file swapped by rename", loaded);
    }
}

#[cfg(windows)]
mod on_windows {
    use super::staged_file_pin::*;
    use super::*;

    fn judge(
        what: &str,
        verified: &[u8],
        tampered: std::io::Result<()>,
        loaded: Result<(Library, Staged), String>,
    ) {
        match (tampered, loaded) {
            (Ok(()), loaded) => assert_refused(what, loaded),
            (Err(_), Ok(l)) => {
                let Staged::TempFile { path, .. } = &l.1 else {
                    panic!("{what}: Windows stages into a file");
                };
                let now = std::fs::read(path).expect("read the staged file");
                assert!(
                    now == verified,
                    "{what}: the OS refused the tamper, yet the staged file changed"
                );
                release(l);
            }
            (Err(t), Err(e)) => {
                panic!("{what}: the OS refused the tamper ({t}) yet the verified bytes did not load: {e}")
            }
        }
    }

    #[test]
    fn the_staged_bytes_are_the_verified_bytes() {
        let (verified, other) = two_libraries();
        clean_load_holds_the_verified_bytes(&verified);

        let (tampered, loaded) = tamper_then_load(&verified, |path| {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)?;
            f.write_all(&other)?;
            f.flush()
        });
        judge(
            "staged file rewritten in place",
            &verified,
            tampered,
            loaded,
        );
    }

    #[test]
    fn a_staged_file_swapped_between_verify_and_load_is_refused() {
        let (verified, other) = two_libraries();

        let (swapped, loaded) = tamper_then_load(&verified, |path| {
            let decoy = path.with_extension("decoy");
            std::fs::write(&decoy, &other)?;
            let r = std::fs::rename(&decoy, path);
            if r.is_err() {
                let _ = std::fs::remove_file(&decoy);
            }
            r
        });
        judge("staged file swapped by rename", &verified, swapped, loaded);
    }
}

#[cfg(target_os = "linux")]
mod on_linux_memfd {
    use super::staged_file_pin::*;
    use super::*;
    use std::os::fd::AsRawFd as _;

    #[test]
    fn the_staged_bytes_are_the_verified_bytes() {
        let (verified, other) = two_libraries();
        let loaded =
            load_library_from_bytes(&verified, "w23-memfd").expect("the verified bytes load");
        let Staged::Memfd { fd: Some(fd) } = &loaded.1 else {
            panic!("Linux stages a verified library into a memfd");
        };
        let name = memfd_name(fd);
        assert!(
            std::fs::read(&name).expect("read the memfd") == verified,
            "the memfd must hold exactly the verified bytes"
        );
        // SAFETY: plain fcntl on an fd the guard owns; no pointers.
        let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
        let want = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        assert_eq!(
            seals & want,
            want,
            "the memfd must be sealed (got {seals:#x})"
        );

        let rewrite = std::fs::OpenOptions::new()
            .write(true)
            .open(&name)
            .and_then(|mut f| f.write_all(&other));
        assert!(rewrite.is_err(), "a sealed memfd must refuse a rewrite");
        release(loaded);
    }
}

#[test]
fn an_embedding_host_guard_runs_before_any_native_staging() {
    const CHILD: &str = "BUSBAR_NATIVE_GUARD_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "stage::tests::an_embedding_host_guard_runs_before_any_native_staging",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    install_native_load_guard(|_, _| Err("host archive/floor policy refused".into())).unwrap();
    assert!(
        crate::dispatch::rendering_of_library(std::path::Path::new("never-opened"))
            .unwrap_err()
            .to_string()
            .contains("retained admitted archive")
    );
    let before = STAGED_HERE.with(|counter| counter.get());
    let error = match load_library_from_bytes(b"no native format is consulted", "guarded-image") {
        Ok(_) => panic!("the policy must refuse before mapping"),
        Err(error) => error,
    };
    assert_eq!(error, "host archive/floor policy refused");
    assert_eq!(STAGED_HERE.with(|counter| counter.get()), before);
}
