//! Busbar CI controller. Not a product crate: it never enters the shipping graph.
//!
//! One static binary serves every trusted job: `security-scans` (former
//! scripts/security/scan.py), `native-bootstrap`/`native-root`/`native-daemon`
//! (former native_ci_bootstrap.py) and `retention`, the in-CI retain-or-fresh
//! decision native-bootstrap runs first (former scripts/architecture/
//! ci_retention.py). The `native` module is the step runner being ported
//! from scripts/architecture/native.py. See controller.pin for its delivery.
mod bootstrap;
mod fetch;
mod images;
mod inflate;
mod inputs;
mod isolation;
mod isotime;
mod json;
mod native;
mod policy;
mod proc;
mod py;
mod retention;
mod security;
mod sha256;
mod tar;
mod toml;
mod zip;

use std::path::{Component, Path, PathBuf};

const USAGE: &str = "usage: busbar-ci security-scans --trusted TRUSTED --checkout CHECKOUT --work WORK --output OUTPUT";
const COMMANDS: &str = "usage: busbar-ci {security-scans|retention|native-bootstrap|native-root|native-daemon} ...";
const OPTIONS: [&str; 4] = ["--trusted", "--checkout", "--work", "--output"];

fn usage_error(message: &str) -> ! {
    // Same contract as the former argparse interface: usage on stderr, exit 2.
    eprintln!("{USAGE}\nbusbar-ci security-scans: error: {message}");
    std::process::exit(2);
}

/// argparse semantics for four required options: `--name VALUE`, `--name=VALUE`,
/// unique prefixes, the last occurrence wins, option-like values are refused.
fn options(args: &[String]) -> [String; 4] {
    let mut values: [Option<String>; 4] = Default::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-h" || arg == "--help" {
            println!("{USAGE}");
            std::process::exit(0);
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value.to_owned())),
            _ => (arg.as_str(), None),
        };
        let matched: Vec<usize> = (0..4)
            .filter(|i| name.len() > 2 && OPTIONS[*i].starts_with(name))
            .collect();
        let [option] = matched.as_slice() else {
            usage_error(&format!("unrecognized or ambiguous argument: {arg}"));
        };
        let value = match inline {
            Some(value) => value,
            None => {
                index += 1;
                match args.get(index) {
                    Some(value) if !value.starts_with('-') || negative_number(value) => {
                        value.clone()
                    }
                    _ => usage_error(&format!(
                        "argument {}: expected one argument",
                        OPTIONS[*option]
                    )),
                }
            }
        };
        values[*option] = Some(value);
        index += 1;
    }
    let missing: Vec<_> = (0..4)
        .filter(|i| values[*i].is_none())
        .map(|i| OPTIONS[i])
        .collect();
    if !missing.is_empty() {
        usage_error(&format!(
            "the following arguments are required: {}",
            missing.join(", ")
        ));
    }
    values.map(Option::unwrap_or_default)
}

fn negative_number(value: &str) -> bool {
    let digits = &value[1..];
    !digits.is_empty()
        && digits.bytes().filter(|c| *c == b'.').count() <= 1
        && digits.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        && digits != "."
}

/// `Path(value).resolve()` (non-strict realpath): resolve existing links,
/// keep missing trailing components, normalize `.` and `..`.
fn resolve(value: &str) -> std::io::Result<PathBuf> {
    let path = Path::new(if value.is_empty() { "." } else { value });
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut resolved = PathBuf::from("/");
    let mut missing = false;
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) => {
                resolved.push(name);
                if !missing {
                    match std::fs::canonicalize(&resolved) {
                        Ok(real) => resolved = real,
                        Err(_) => missing = true,
                    }
                }
            }
        }
    }
    Ok(resolved)
}

fn security_scans(args: &[String]) -> i32 {
    let [trusted, checkout, work, output] = options(args);
    let paths = [&trusted, &checkout, &work, &output].map(|p| resolve(p));
    let result = match paths {
        [Ok(trusted), Ok(checkout), Ok(work), Ok(output)] => {
            security::run_source(&trusted, &checkout, &work, &output)
        }
        _ => Err(security::Fail::Abort("cannot resolve paths")),
    };
    match result {
        Ok(_) => {
            println!("{}", security::SUCCESS);
            0
        }
        Err(_) => {
            // Error detail can derive from source or tool output; never print it.
            eprintln!("{}", security::SAFE_FAILURE);
            1
        }
    }
}

fn security_main(args: Vec<String>) -> i32 {
    // Panic text may derive from source or tool output; the job prints only
    // the fixed safe failure line (exit 1), as for every other refusal.
    std::panic::set_hook(Box::new(|_| {}));
    // Report parsing recurses to CPython's json nesting bound (~10k levels);
    // a dedicated large stack keeps that a bounded refusal, not an overflow.
    let worker = std::thread::Builder::new()
        .stack_size(512 << 20)
        .spawn(move || security_scans(&args));
    match worker.map(|handle| handle.join()) {
        Ok(Ok(code)) => code,
        _ => {
            eprintln!("{}", security::SAFE_FAILURE);
            1
        }
    }
}

fn retention_main(args: Vec<String>) -> i32 {
    // The job environment as os.environ sees it (undecodable bytes replaced).
    let env: retention::Env = std::env::vars_os()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect();
    // Untrusted JSON nests to the decoder's recursion bound on a large stack;
    // any panic is a fresh decision (exit 1), never retained.
    let worker = std::thread::Builder::new()
        .stack_size(512 << 20)
        .spawn(move || retention::main(&args, &env));
    match worker.map(|handle| handle.join()) {
        Ok(Ok(code)) => code,
        _ => 1,
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let command = if args.is_empty() {
        String::new()
    } else {
        args.remove(0)
    };
    let code = match command.as_str() {
        "security-scans" => security_main(args),
        "retention" => retention_main(args),
        "native-bootstrap" | "native-root" | "native-daemon" => {
            match bootstrap::main(&command, &args) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("busbar-ci {command}: {error}");
                    1
                }
            }
        }
        _ => {
            eprintln!("{COMMANDS}");
            2
        }
    };
    std::process::exit(code);
}
