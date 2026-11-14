mod bootstrap;
mod confine;
mod confined;
mod fetch;
mod images;
mod inflate;
mod inputs;
mod isolation;
mod isotime;
mod json;
mod pathx;
mod policy;
mod proc;
mod product;
mod py;
mod retention;
mod security;
mod sha256;
mod tar;
mod toml;
mod zip;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (command, rest) = arguments
        .split_first()
        .map(|(c, r)| (c.as_str(), r))
        .unwrap_or(("", &[]));
    let result = match command {
        "native-bootstrap" | "native-root" | "native-daemon" => bootstrap::main(command, rest),
        _ => Err("expected native-bootstrap, native-root or native-daemon".to_owned()),
    };
    if let Err(error) = result {
        eprintln!("busbar-ci {command}: {error}");
        std::process::exit(1);
    }
}
