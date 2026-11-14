//! A memory-safe, pure-Rust port of the parts of libyaml 0.2.5 that serde_yaml_ng 0.10 drove
//! through unsafe-libyaml 0.2.11: the UTF-8 reader, the scanner, the parser and the emitter. Module
//! and type names keep serde_yaml_ng's (`libyaml::parser::Parser`, `libyaml::emitter::Emitter`,
//! ...) so the serde layer above is serde_yaml_ng's own code.

pub mod emitter;
pub mod error;
pub mod parser;
mod scanner;
pub mod tag;
