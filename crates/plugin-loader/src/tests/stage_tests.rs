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
        let dead = staging_parent_in(&std::env::temp_dir()).join(format!(
            "{STAGING_PREFIX}4294967294-{}",
            random_hex(8).unwrap()
        ));
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

#[cfg(unix)]
fn private_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("busbar-sweep-{tag}-{}", random_hex(8).unwrap()));
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

    let link = parent.join(format!(
        "{STAGING_PREFIX}4294967294-{}",
        random_hex(8).unwrap()
    ));
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
    let dead = parent.join(format!(
        "{STAGING_PREFIX}4294967294-{}",
        random_hex(8).unwrap()
    ));
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
    let dead = parent.join(format!(
        "{STAGING_PREFIX}4294967294-{}",
        random_hex(8).unwrap()
    ));
    std::fs::create_dir_all(dead.join("sub")).unwrap();
    std::fs::write(dead.join("sub/lib.so"), b"junk").unwrap();
    let own = parent.join(format!(
        "{STAGING_PREFIX}{}-{}",
        std::process::id(),
        random_hex(8).unwrap()
    ));
    std::fs::create_dir_all(&own).unwrap();
    let live_pid = std::os::unix::process::parent_id();
    assert!(
        pid_alive(live_pid),
        "precondition: our parent process is alive"
    );
    let live = parent.join(format!(
        "{STAGING_PREFIX}{live_pid}-{}",
        random_hex(8).unwrap()
    ));
    std::fs::create_dir_all(&live).unwrap();
    let legacy = root.join(format!(
        "{STAGING_PREFIX}4294967294-{}",
        random_hex(8).unwrap()
    ));
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
    let victim = elsewhere.join(format!(
        "{STAGING_PREFIX}4294967294-{}",
        random_hex(8).unwrap()
    ));
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

/// A file that is not a shared object: the dynamic loader refuses it with its own reason.
#[cfg(unix)]
const NOT_A_LIBRARY: &[u8] = b"this is not an ELF image, only text";

/// The outcome of an open, said for a failure message (`Opened` and `Unopened` have no `Debug`).
#[cfg(unix)]
fn said(outcome: &Result<(busbar_ffi::image::Opened, Staged), Unopened>) -> String {
    match outcome {
        Ok(_) => "opened".into(),
        Err(Unopened::Stage(why)) => format!("Stage({why})"),
        Err(Unopened::Image(e)) => format!("Image({e:?})"),
        Err(Unopened::Panicked) => "Panicked".into(),
    }
}

/// An opened image released as the loader releases a refused one: the library on the worker, then its staging.
#[cfg(unix)]
fn release((opened, staged): (busbar_ffi::image::Opened, Staged)) {
    close_on_worker(opened);
    drop(staged);
}

/// The dynamic loader's reason for refusing an open, as a refusal carries it. `S` is what the open staged (none for
/// an open of a path the test made).
#[cfg(unix)]
fn load_reason<S>(what: &str, outcome: Result<(busbar_ffi::image::Opened, S), Unopened>) -> String {
    match outcome {
        Err(Unopened::Image(busbar_ffi::image::ImageError::Load(e))) => loader_error(&e),
        Ok((opened, staged)) => {
            close_on_worker(opened);
            drop(staged);
            panic!("{what}: a file that is not a library opened");
        }
        Err(Unopened::Stage(why)) => {
            panic!("{what}: refused while staging, not by the dynamic loader: {why}")
        }
        Err(Unopened::Image(e)) => panic!("{what}: refused, but not by the dynamic loader: {e:?}"),
        Err(Unopened::Panicked) => panic!("{what}: the open panicked"),
    }
}

/// Run the calling test alone in a fresh child of this test binary (`name` is its full path). The parent answers
/// `true` once the child passed; the child answers `false` and runs the body. Used where the body changes
/// process-wide state (the once-only native load guard) or depends on the process's fd numbering.
#[cfg(unix)]
fn ran_in_own_process(marker: &str, name: &str) -> bool {
    if std::env::var_os(marker).is_some() {
        return false;
    }
    let out = std::process::Command::new(std::env::current_exe().expect("the test binary's path"))
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env(marker, "1")
        .output()
        .expect("re-run the test binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "the own-process child of {name} failed (status {:?}):\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
        out.status
    );
    true
}

/// The stamp a native image's bytes carry (the 272 bytes starting at the stamp magic).
#[cfg(unix)]
fn stamp_in(bytes: &[u8]) -> &[u8] {
    bytes
        .windows(crate::scan::STAMP_SIZE)
        .find(|w| w.starts_with(&busbar_plugin_abi::stamp::STAMP_MAGIC))
        .expect("a native image carries a stamp")
}

#[cfg(unix)]
fn refuse_every_image(bytes: &[u8], display: &str) -> Result<(), String> {
    Err(format!(
        "the embedding host refuses native image '{display}' ({} bytes)",
        bytes.len()
    ))
}

/// PROOF-093-A:23. The host's native load guard is asked before anything is staged: a refusing guard's own words
/// are the refusal, and nothing was staged.
#[cfg(unix)]
#[test]
fn an_embedding_host_guard_runs_before_any_native_staging() {
    if ran_in_own_process(
        "BUSBAR_STAGE_GUARD_CHILD",
        "stage::tests::an_embedding_host_guard_runs_before_any_native_staging",
    ) {
        return;
    }
    let bytes = crate::test_host::cdylib_bytes("native_pack_fixture");
    let staged = || STAGED_HERE.with(std::cell::Cell::get);

    // The witness counts: with no guard, an open stages (this text then fails to load).
    let before = staged();
    let unguarded = open_image(NOT_A_LIBRARY, "unguarded");
    assert!(
        matches!(unguarded, Err(Unopened::Image(_))),
        "{}",
        said(&unguarded)
    );
    assert_eq!(staged(), before + 1, "an unguarded open stages its bytes");

    install_native_load_guard(refuse_every_image).expect("the first guard installs");
    let before = staged();
    let outcome = open_image(&bytes, "guarded");
    match outcome {
        Err(Unopened::Stage(why)) => assert_eq!(
            why,
            format!(
                "the embedding host refuses native image 'guarded' ({} bytes)",
                bytes.len()
            ),
            "the refusal is the guard's own words"
        ),
        other => {
            let what = said(&other);
            if let Ok(loaded) = other {
                release(loaded);
            }
            panic!("a refusing guard must refuse with Stage, got {what}");
        }
    }
    assert_eq!(staged(), before, "nothing is staged once the guard refused");
}

/// PROOF-093-A:108. An image opened from a memfd, closed, then a second image staged on the same (reused) fd
/// number answers with its own header and stamp, not the first image's: the verified bytes are the bytes that run.
#[cfg(target_os = "linux")]
#[test]
fn a_replaced_image_on_a_reused_fd_runs_its_own_bytes() {
    if ran_in_own_process(
        "BUSBAR_STAGE_REUSED_FD_CHILD",
        "stage::tests::a_replaced_image_on_a_reused_fd_runs_its_own_bytes",
    ) {
        return;
    }
    let a = crate::test_host::cdylib_bytes("native_pack_fixture");
    let b = crate::test_host::cdylib_bytes("native_schema_bomb");
    assert_ne!(
        stamp_in(&a),
        stamp_in(&b),
        "the two images must differ in stamp"
    );

    let staged_name = |s: &Staged| match s {
        Staged::Memfd { fd: Some(fd) } => memfd_name(fd),
        _ => panic!("Linux stages a verified image into a memfd"),
    };

    let first = open_image(&a, "image-a");
    let (opened_a, staged_a) = first.unwrap_or_else(|e| panic!("image A opens: {}", said(&Err(e))));
    assert_eq!(
        opened_a.stamp().0.as_slice(),
        stamp_in(&a),
        "image A answers with A's stamp"
    );
    let name_a = staged_name(&staged_a);
    release((opened_a, staged_a));

    let second = open_image(&b, "image-b");
    let (opened_b, staged_b) =
        second.unwrap_or_else(|e| panic!("image B opens: {}", said(&Err(e))));
    let name_b = staged_name(&staged_b);
    assert_eq!(
        name_b, name_a,
        "precondition: image B is staged on the fd image A was staged on"
    );
    let stamp_b = opened_b.stamp().0;
    assert_ne!(
        stamp_b.as_slice(),
        stamp_in(&a),
        "image B was opened but image A's resident image answered: B's verified bytes never ran"
    );
    assert_eq!(
        stamp_b.as_slice(),
        stamp_in(&b),
        "image B answers with B's own stamp"
    );
    release((opened_b, staged_b));
}

/// PROOF-093-A:114.
#[cfg(target_os = "linux")]
#[test]
fn a_refused_open_carries_the_loaders_reason() {
    let reason = load_reason("plain text", open_image(NOT_A_LIBRARY, "plain-text"));
    assert!(
        reason.contains("ELF") || reason.contains("too short"),
        "the dynamic loader's own reason must reach the refusal: {reason}"
    );
}

/// PROOF-093-A:116.
#[cfg(target_os = "linux")]
#[test]
fn a_refused_open_is_more_than_the_bare_label() {
    let reason = load_reason("plain text", open_image(NOT_A_LIBRARY, "plain-text"));
    assert_ne!(reason, "dlopen failed", "the loader's text was dropped");
    assert!(
        reason.starts_with("dlopen failed: ") && reason.len() > "dlopen failed: ".len() + 8,
        "libloading's Display is only the label; the dlerror text is its source: {reason}"
    );
}

/// PROOF-093-A:115. A crafted library path cannot forge a log line through the loader's reason, and the reason is
/// bounded.
#[cfg(target_os = "linux")]
#[test]
fn a_refused_opens_text_is_one_bounded_line() {
    // Every character class loader_reason escapes, exactly as it escapes them.
    let crafted = "a\tb\u{1b}c\u{7f}d\u{85}e\u{2028}f\u{2029}g\u{200e}h\u{200f}\
                   i\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}j\u{2066}\u{2067}\u{2068}\u{2069}k\nl\rm";
    assert_eq!(
        loader_reason(crafted),
        r"a\u{9}b\u{1b}c\u{7f}d\u{85}e\u{2028}f\u{2029}g\u{200e}h\u{200f}i\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}j\u{2066}\u{2067}\u{2068}\u{2069}k\nl\rm"
    );
    // The cut: 512 characters are kept whole; a 513th is replaced by one ellipsis.
    let exact = "\u{e9}".repeat(512);
    assert_eq!(loader_reason(&exact), exact);
    assert_eq!(
        loader_reason(&"\u{e9}".repeat(513)),
        format!("{exact}\u{2026}")
    );

    // End to end: the dynamic loader's text names the crafted path.
    let root = private_root("dlerror-forge");
    let forged = root.join("x\n[ERROR] forged line\r\u{202e}.so");
    std::fs::write(&forged, NOT_A_LIBRARY).unwrap();
    let reason = load_reason(
        "a crafted path",
        open_on_worker(forged.as_os_str(), NOT_A_LIBRARY).map(|o| (o, ())),
    );
    assert!(
        !reason.chars().any(|c| c.is_control()
            || matches!(c, '\u{2028}' | '\u{2029}' | '\u{200e}' | '\u{200f}'
                | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')),
        "a crafted path must not forge a log line: {reason:?}"
    );
    assert!(
        reason.contains(r"x\n[ERROR] forged line\r\u{202e}.so"),
        "the crafted path is carried escaped: {reason:?}"
    );

    let long = root
        .join("d".repeat(200))
        .join("d".repeat(200))
        .join("d".repeat(200))
        .join("x.so");
    std::fs::create_dir_all(long.parent().unwrap()).unwrap();
    std::fs::write(&long, NOT_A_LIBRARY).unwrap();
    let reason = load_reason(
        "a long path",
        open_on_worker(long.as_os_str(), NOT_A_LIBRARY).map(|o| (o, ())),
    );
    assert_eq!(
        reason.chars().count(),
        LOADER_REASON_CHARS + 1,
        "the reason is cut at {LOADER_REASON_CHARS} characters plus the ellipsis: {reason}"
    );
    assert!(
        reason.starts_with("dlopen failed: ") && reason.ends_with('\u{2026}'),
        "{reason}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
mod staged_file_pin {
    use super::*;

    /// The verified native image, and the same image with its first byte flipped.
    pub(super) fn two_libraries() -> (Vec<u8>, Vec<u8>) {
        let verified = crate::test_host::cdylib_bytes("native_pack_fixture");
        let mut other = verified.clone();
        other[0] ^= 0xff;
        assert_ne!(verified, other, "the two fixtures must differ");
        (verified, other)
    }

    /// Stage `verified` in the private temp file, run `tamper` on the staged file between staging and the first
    /// check, then open. Answers what the tamper did, the outcome, and the staged file's name.
    pub(super) fn tamper_then_open(
        verified: &[u8],
        tamper: impl FnOnce(&std::path::Path) -> std::io::Result<()>,
    ) -> (
        std::io::Result<()>,
        Result<(busbar_ffi::image::Opened, Staged), Unopened>,
        PathBuf,
    ) {
        let mut tamper = Some(tamper);
        let mut outcome = None;
        let mut staged_at = None;
        let opened = open_staged_file(verified, &mut |path| {
            staged_at = Some(path.to_path_buf());
            if let Some(t) = tamper.take() {
                outcome = Some(t(path));
            }
        });
        (
            outcome.expect("the loader ran its before-verify window"),
            opened,
            staged_at.expect("the loader staged a file"),
        )
    }

    pub(super) fn clean_open_holds_the_verified_bytes(verified: &[u8]) {
        let mut seen = None;
        let opened = open_staged_file(verified, &mut |path| {
            seen = Some(std::fs::read(path).expect("read the staged file"));
        });
        let opened =
            opened.unwrap_or_else(|e| panic!("the verified bytes open: {}", said(&Err(e))));
        assert!(
            seen.as_deref() == Some(verified),
            "the staged file must hold exactly the verified bytes"
        );
        assert!(matches!(opened.1, Staged::TempFile { .. }));
        release(opened);
    }

    /// Refused by the staged-file check, its file released, and no image of it left mapped.
    pub(super) fn assert_refused(
        what: &str,
        opened: Result<(busbar_ffi::image::Opened, Staged), Unopened>,
        staged_at: &std::path::Path,
    ) {
        match opened {
            Err(Unopened::Stage(why)) => assert!(
                why.starts_with("its staged file "),
                "{what}: refused, but not by the staged-file check: {why}"
            ),
            Ok(loaded) => {
                release(loaded);
                panic!(
                    "{what}: the loader mapped a staged file that no longer holds the verified bytes \
                     (the bytes that loaded are not the bytes that were verified)"
                );
            }
            Err(other) => panic!(
                "{what}: refused, but not by the staged-file check: {}",
                said(&Err(other))
            ),
        }
        assert!(
            staged_at.symlink_metadata().is_err(),
            "{what}: the refused staged file is released"
        );
        #[cfg(target_os = "linux")]
        assert!(
            !name_still_loaded(staged_at.to_str().expect("a staged name is UTF-8")),
            "{what}: no image of the refused file stays mapped"
        );
    }
}

/// The private temp-file staging (the fallback where no sealed memfd can be used).
#[cfg(unix)]
mod on_unix {
    use super::staged_file_pin::*;
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// PROOF-093-A:117.
    #[test]
    fn the_staged_bytes_are_the_verified_bytes() {
        let (verified, other) = two_libraries();
        clean_open_holds_the_verified_bytes(&verified);

        let (tampered, opened, at) = tamper_then_open(&verified, |path| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)?;
            f.write_all(&other)?;
            f.flush()
        });
        tampered.expect("the owning uid can rewrite its own staged file in place");
        assert_refused("staged file rewritten in place", opened, &at);

        let (tampered, opened, at) = tamper_then_open(&verified, |path| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
            let last = verified.len() as u64 - 1;
            std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(last))?;
            f.write_all(&[verified[verified.len() - 1] ^ 0xff])?;
            f.flush()?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
        });
        tampered.expect("the owning uid can flip a byte of its own staged file");
        assert_refused("staged file with one byte flipped", opened, &at);
    }

    /// PROOF-093-A:118.
    #[test]
    fn a_staged_file_swapped_between_verify_and_load_is_refused() {
        let (verified, other) = two_libraries();

        let (swapped, opened, at) = tamper_then_open(&verified, |path| {
            let decoy = path.with_extension("decoy");
            std::fs::write(&decoy, &other)?;
            std::fs::rename(&decoy, path)
        });
        swapped.expect("the owning uid can rename inside its own staging directory");
        assert_refused("staged file swapped by rename", opened, &at);
    }
}

/// The sealed memfd (Linux).
#[cfg(target_os = "linux")]
mod on_linux_memfd {
    use super::*;
    use rustix::fs::SealFlags;

    /// PROOF-093-A:113.
    #[test]
    fn the_staged_bytes_are_the_verified_bytes() {
        let (verified, other) = super::staged_file_pin::two_libraries();
        let opened = open_image(&verified, "memfd");
        let loaded =
            opened.unwrap_or_else(|e| panic!("the verified bytes open: {}", said(&Err(e))));
        let Staged::Memfd { fd: Some(fd) } = &loaded.1 else {
            panic!("Linux stages a verified image into a memfd");
        };
        let name = memfd_name(fd);
        assert!(
            std::fs::read(&name).expect("read the memfd") == verified,
            "the memfd must hold exactly the verified bytes"
        );
        let seals = rustix::fs::fcntl_get_seals(fd).expect("read the memfd's seals");
        let want = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
        assert_eq!(
            seals & want,
            want,
            "the memfd must be sealed (got {seals:?})"
        );

        let rewrite = std::fs::OpenOptions::new()
            .write(true)
            .open(&name)
            .and_then(|mut f| f.write_all(&other));
        assert!(rewrite.is_err(), "a sealed memfd must refuse a rewrite");
        assert!(
            std::fs::read(&name).expect("read the memfd again") == verified,
            "the memfd still holds exactly the verified bytes"
        );
        release(loaded);
    }
}

/// PROOF-093-A:26. `close_on_worker` unloads the image (its `dlclose`, which runs the image's finalizers before
/// it unmaps it) on a permanent ffi worker, never on the caller's thread: the image is loaded under its staged name
/// until the call, gone after it, and the thread that closed it is a permanent worker other than the caller.
#[cfg(target_os = "linux")]
#[test]
fn dlclose_on_worker_runs_this_images_finalizer_on_a_permanent_worker() {
    let bytes = crate::test_host::cdylib_bytes("native_pack_fixture");
    let (opened, staged) = open_image(&bytes, "finalizer")
        .unwrap_or_else(|e| panic!("the native fixture opens: {}", said(&Err(e))));
    let Staged::Memfd { fd: Some(fd) } = &staged else {
        panic!("Linux stages a verified image into a memfd");
    };
    let name = memfd_name(fd);
    assert!(name_still_loaded(&name), "the opened image is loaded");
    CLOSED_ON.with(|last| last.set(None));
    let caller = std::thread::current().id();
    close_on_worker(opened);
    let closed_on = CLOSED_ON
        .with(std::cell::Cell::get)
        .expect("close_on_worker closed the image")
        .expect("its dlclose ran on a permanent ffi worker");
    assert_ne!(closed_on, caller, "never on the caller's thread");
    assert!(
        !name_still_loaded(&name),
        "the dlclose ran to the end: the image's finalizers ran and it is unloaded"
    );
    drop(staged);
}
