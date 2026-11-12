//! Busbar CI controller. Not a product crate: it never enters the shipping graph.
mod isotime;
mod json;
mod security;
mod sha256;

use std::path::{Component, Path, PathBuf};

const USAGE: &str = "usage: busbar-ci security-scans --trusted TRUSTED --checkout CHECKOUT --work WORK --output OUTPUT";
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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Report parsing recurses to CPython's json nesting bound (~10k levels);
    // a dedicated large stack keeps that a bounded refusal, not an overflow.
    let worker = std::thread::Builder::new()
        .stack_size(512 << 20)
        .spawn(move || match args.first().map(String::as_str) {
            Some("security-scans") => security_scans(&args[1..]),
            _ => {
                eprintln!("{USAGE}");
                2
            }
        });
    let code = match worker.map(|handle| handle.join()) {
        Ok(Ok(code)) => code,
        _ => {
            eprintln!("{}", security::SAFE_FAILURE);
            1
        }
    };
    std::process::exit(code);
}
