// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! #65: the kernel's seal reaches the kernel and nothing else (`crate::seal`).
//!
//! Two witnesses. The first is the real one, in the integration test
//! `tests/seal_release_path.rs` (the library built without `cfg(test)`, where the release path is
//! the only one): the seal it hands the kernel opens, and the box `KernelSeal::deliver` hands any
//! OTHER caller does not open as a seal. The second, here, builds the mechanism's exact shape with
//! `rustc` — a contract crate that declares the root symbol, a kernel crate that defines it beside
//! its `#[inline(never)]` minter, and a program that links both — and proves the property the
//! design leans on: the honest program links and
//! gets its seal, and a program that defines the root symbol itself, to catch the seal on its way
//! to the kernel, does NOT link.

const CONTRACT: &str = r#"
pub struct Seal(());
impl Seal {
    #[inline]
    pub fn deliver() -> Box<dyn std::any::Any + Send + Sync> {
        unsafe { __busbar_kernel_root(Seal(())) }
    }
}
extern "Rust" {
    fn __busbar_kernel_root(seal: Seal) -> Box<dyn std::any::Any + Send + Sync>;
}
"#;

const KERNEL: &str = r#"
struct Held(contract::Seal);
#[inline(never)]
pub fn acquire() -> bool {
    contract::Seal::deliver().downcast::<Held>().is_ok()
}
#[no_mangle]
pub fn __busbar_kernel_root(seal: contract::Seal) -> Box<dyn std::any::Any + Send + Sync> {
    Box::new(Held(seal))
}
"#;

const HONEST: &str = r#"
fn main() {
    assert!(kernel::acquire(), "the kernel opened its own seal");
    println!("HONEST-LINKED");
}
"#;

const FORGER: &str = r#"
static mut CAUGHT: Option<contract::Seal> = None;
#[no_mangle]
pub fn __busbar_kernel_root(seal: contract::Seal) -> Box<dyn std::any::Any + Send + Sync> {
    unsafe { CAUGHT = Some(seal) };
    Box::new(())
}
fn main() {
    let _ = kernel::acquire();
    println!("FORGER-LINKED");
}
"#;

fn rustc(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    std::process::Command::new(rustc)
        .current_dir(dir)
        .args(["--edition", "2021", "-L", "."])
        .args(args)
        .output()
        .expect("rustc is on PATH wherever `cargo test` runs")
}

#[test]
fn a_second_definition_of_the_kernels_root_symbol_does_not_link() {
    let dir = std::env::temp_dir().join(format!("busbar-seal-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, src) in [
        ("contract.rs", CONTRACT),
        ("kernel.rs", KERNEL),
        ("honest.rs", HONEST),
        ("forger.rs", FORGER),
    ] {
        std::fs::write(dir.join(name), src).unwrap();
    }
    let lib = |crate_name: &str, extra: &[&str]| {
        let src = format!("{crate_name}.rs");
        let mut args = vec!["--crate-type", "rlib", "--crate-name", crate_name];
        args.extend_from_slice(extra);
        args.push(&src);
        let out = rustc(&dir, &args);
        assert!(
            out.status.success(),
            "building the {crate_name} fixture failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    lib("contract", &[]);
    lib("kernel", &["--extern", "contract=libcontract.rlib"]);
    let program = |name: &str| {
        let src = format!("{name}.rs");
        rustc(
            &dir,
            &[
                "--crate-type",
                "bin",
                "--extern",
                "contract=libcontract.rlib",
                "--extern",
                "kernel=libkernel.rlib",
                "-o",
                name,
                &src,
            ],
        )
    };

    // POSITIVE CONTROL: the honest program links, runs, and the kernel opens its seal.
    let honest = program("honest");
    assert!(
        honest.status.success(),
        "the honest program must link: {}",
        String::from_utf8_lossy(&honest.stderr)
    );
    let ran = std::process::Command::new(dir.join("honest"))
        .output()
        .unwrap();
    assert!(
        ran.status.success() && String::from_utf8_lossy(&ran.stdout).contains("HONEST-LINKED"),
        "the honest program must run and open its seal: {ran:?}"
    );

    // THE PROPERTY: a program that defines the root symbol to catch the seal does not link.
    let forger = program("forger");
    let stderr = String::from_utf8_lossy(&forger.stderr).to_lowercase();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !forger.status.success(),
        "a second definition of __busbar_kernel_root LINKED: the seal can be intercepted"
    );
    assert!(
        stderr.contains("duplicate")
            || stderr.contains("multiple definition")
            || stderr.contains("already defined"),
        "the forger must fail as a duplicate symbol, not for another reason: {stderr}"
    );
}
