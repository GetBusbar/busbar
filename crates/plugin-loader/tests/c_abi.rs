// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The external C ABI witness is a test input, not a shipped secret provider.
//! CI builds its source against this checkout's public header before running this target.

use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{
    Blob, InHead, OutHead, Outcome, BLOB_JSON, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC;
use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut};
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, out_head, rendering_of_library, Bind, ConnTable, DispatchConfig,
    Dispatcher, Frame, InFrame, LoadError, ManifestFacts, NoSink, OutFrame, Plugin,
};

fn supplied_path(name: &str) -> PathBuf {
    let path =
        PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required")));
    assert!(path.is_absolute(), "{name} must name an absolute path");
    assert!(path.exists(), "{name}={} does not exist", path.display());
    path
}

fn sources() -> Vec<PathBuf> {
    let mut sources: Vec<_> = std::fs::read_dir(supplied_path("BUSBAR_C_ABI_SOURCES"))
        .expect("read the external C witness source directory")
        .map(|entry| entry.expect("read a C witness source entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "c"))
        .collect();
    sources.sort();
    assert!(!sources.is_empty(), "the C witness has no C source");
    sources
}

fn stated(path: &Path) -> Vec<u8> {
    rendering_of_library(path)
        .expect("the C witness Statement is valid")
        .expect("the C witness exports busbar_plugin_door")
}

fn load(path: &Path, rendering: &[u8]) -> Result<(Plugin<Secret>, Arc<Dispatcher>), LoadError> {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = Bind {
        instance: Arc::from("c-abi-witness"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::NoNeeds,
    };
    load_dropped(path, rendering, bind).map(|plugin| (plugin, dispatcher))
}

fn input<T: InFrame>() -> T {
    // SAFETY: ABI input frames contain integers, raw pointers and nested ABI structs;
    // the all-zero representation is valid. InFrame places InHead at offset zero.
    let mut value: T = unsafe { MaybeUninit::zeroed().assume_init() };
    // SAFETY: the frame is live and its first field is InHead.
    unsafe {
        std::ptr::addr_of_mut!(value)
            .cast::<InHead>()
            .write(in_head())
    };
    value
}

fn output<T: OutFrame>() -> T {
    // SAFETY: as input(), with the OutFrame contract placing OutHead first.
    let mut value: T = unsafe { MaybeUninit::zeroed().assume_init() };
    // SAFETY: the frame is live and its first field is OutHead.
    unsafe {
        std::ptr::addr_of_mut!(value)
            .cast::<OutHead>()
            .write(out_head())
    };
    value
}

#[test]
fn a_header_only_c_image_loads_and_exchanges_host_owned_bytes() {
    for source in sources() {
        let text = std::fs::read_to_string(&source).expect("read the external C witness");
        let includes: Vec<_> = text
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("#include"))
            .collect();
        assert_eq!(
            includes,
            ["#include \"busbar_plugin.h\""],
            "{}",
            source.display()
        );
    }
    let library = supplied_path("BUSBAR_C_ABI_LIBRARY");
    let rendering = stated(&library);
    let facts = ManifestFacts::read(&rendering).expect("read the C Statement");
    assert_eq!(facts.mechanism_version, MECHANISM_VERSION);
    assert_eq!(facts.kind, KindCode::Secret);
    assert_eq!(facts.kind_abi, secret::ABI_VERSION);
    let (plugin, _dispatcher) = load(&library, &rendering).expect("the C ABI witness loads");
    let settings = br#"{"values":{"probe":"c-abi-bytes"}}"#;
    let mut open: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    open.input.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    open.input.generation = 1;
    assert_eq!(plugin.call(slot::OPEN, &mut open).outcome, Outcome::Ready);
    assert!(plugin.is_open());
    let reference = br#"{"name":"probe"}"#;
    let mut bytes = [0_u8; 64];
    let mut resolve: Frame<ResolveIn, ResolveOut> = Frame::new(input(), output());
    resolve.input.settings = Blob {
        ptr: reference.as_ptr(),
        len: reference.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    resolve.input.secret_buf = bytes.as_mut_ptr();
    resolve.input.secret_cap = bytes.len();
    let answer = plugin.call(secret::slot::RESOLVE, &mut resolve);
    assert_eq!(answer.outcome, Outcome::Ready);
    assert_eq!(answer.lease, 0);
    assert_eq!(resolve.out.secret.ptr, bytes.as_ptr());
    assert_eq!(resolve.out.secret.len, b"c-abi-bytes".len());
    assert_ne!(resolve.out.secret.flags & BLOB_SECRET, 0);
    assert_eq!(&bytes[..resolve.out.secret.len], b"c-abi-bytes");
    bytes.fill(0);
    let mut close: Frame<InHead, OutHead> = Frame::new(input(), output());
    assert_eq!(plugin.call(slot::CLOSE, &mut close).outcome, Outcome::Ready);
    assert!(!plugin.is_open());
}

struct Rebuilt {
    directory: PathBuf,
    library: PathBuf,
}

impl Drop for Rebuilt {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.directory) {
            eprintln!(
                "remove owned C ABI rebuild directory {}: {error}",
                self.directory.display()
            );
        }
    }
}

fn rebuild(define: &str) -> Rebuilt {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let directory = loop {
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("busbar-c-abi-{}-{serial}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create owned C ABI rebuild directory: {error}"),
        }
    };
    let library = directory.join(format!(
        "{}c_abi_negative{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let output = Command::new(compiler)
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-shared",
            "-fPIC",
        ])
        .arg("-I")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-contract/include"
        ))
        .arg(format!("-D{define}"))
        .arg("-o")
        .arg(&library)
        .args(sources())
        .output()
        .expect("run the C compiler");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Rebuilt { directory, library }
}

#[test]
fn a_c_image_at_another_kind_abi_is_refused_before_use() {
    let library = supplied_path("BUSBAR_C_ABI_LIBRARY");
    let rendering = stated(&library);
    for abi in [secret::ABI_VERSION - 1, secret::ABI_VERSION + 1] {
        let rebuilt = rebuild(&format!("BUSBAR_PLUGIN_KIND_ABI={abi}u"));
        let expected = LoadError::KindAbi {
            kind: KindCode::Secret,
            door: abi,
            host: secret::ABI_VERSION,
        };
        assert_eq!(
            rendering_of_library(&rebuilt.library).err(),
            Some(expected.clone())
        );
        assert_eq!(load(&rebuilt.library, &rendering).err(), Some(expected));
    }
    let mut mismatched = rendering;
    let offset = RENDERING_MAGIC.len() + 8;
    mismatched[offset..offset + 4].copy_from_slice(&(secret::ABI_VERSION + 1).to_le_bytes());
    assert_eq!(
        load(&library, &mismatched).err(),
        Some(LoadError::ManifestKindAbi {
            stated: secret::ABI_VERSION + 1,
            host: secret::ABI_VERSION
        })
    );
}

#[test]
fn a_c_image_cannot_be_admitted_as_another_kind() {
    let library = supplied_path("BUSBAR_C_ABI_LIBRARY");
    let mut rendering = stated(&library);
    let offset = RENDERING_MAGIC.len() + 4;
    rendering[offset..offset + 4].copy_from_slice(&(KindCode::Export as u32).to_le_bytes());
    assert_eq!(
        load(&library, &rendering).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Export,
            want: KindCode::Secret,
        })
    );
}
