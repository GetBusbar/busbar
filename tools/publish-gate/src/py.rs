// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The value model, JSON reader/writer and string rules the gate's checks and messages are written
//! in. The gate was first written in Python, and its refusal lines, its evidence bytes and the
//! documents it must re-render byte for byte (the plugin index, the conformance manifest the
//! candidate writes) follow Python's `json`, `str`, `repr` and `splitlines` rules. They are kept
//! here exactly, so a message never changes meaning and a re-render never changes a byte.

use std::fmt::Write as _;
use std::path::Path;

// ── errors ──────────────────────────────────────────────────────────────────────────────────────

/// The class of a failure. The gate's `except` clauses catch by class, and the CLI prints the
/// class name for a failure it reports as "could not run".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An operating-system error, by its Python name (`FileNotFoundError`, `OSError`, ...).
    Os(&'static str),
    Value,
    /// A `ValueError` subclass known by its own name (`binascii.Error` is `Error`).
    ValueNamed(&'static str),
    JsonDecode,
    UnicodeDecode,
    Key,
    Type,
    Attribute,
    Index,
    /// A tar archive could not be read (`ReadError`, `CompressionError`, ...).
    Tar(&'static str),
    BadZip,
    NotImplemented,
    Runtime,
    /// The conformance renderer refused its inputs.
    SyncRefused,
    /// A conformance invocation archive proves nothing.
    InvRefused,
    /// A rule could not run: exit 3, never a pass.
    CannotRun,
    /// A conformance lookup could not run.
    CgCannotRun,
    /// A subprocess failed or timed out (`CalledProcessError`, `TimeoutExpired`).
    Subprocess(&'static str),
}

#[derive(Clone, Debug)]
pub struct PyErr {
    pub kind: Kind,
    pub msg: String,
}

pub type R<T> = Result<T, PyErr>;

impl PyErr {
    pub fn new(kind: Kind, msg: impl Into<String>) -> Self {
        PyErr {
            kind,
            msg: msg.into(),
        }
    }
    pub fn value(msg: impl Into<String>) -> Self {
        Self::new(Kind::Value, msg)
    }
    pub fn cannot_run(msg: impl Into<String>) -> Self {
        Self::new(Kind::CannotRun, msg)
    }
    pub fn type_err(msg: impl Into<String>) -> Self {
        Self::new(Kind::Type, msg)
    }
    /// `KeyError(k)`: its text is the key's repr.
    pub fn key(k: &str) -> Self {
        Self::new(Kind::Key, repr_str(k))
    }
    pub fn name(&self) -> &str {
        match &self.kind {
            Kind::Os(n) | Kind::Tar(n) | Kind::Subprocess(n) | Kind::ValueNamed(n) => n,
            Kind::Value => "ValueError",
            Kind::JsonDecode => "JSONDecodeError",
            Kind::UnicodeDecode => "UnicodeDecodeError",
            Kind::Key => "KeyError",
            Kind::Type => "TypeError",
            Kind::Attribute => "AttributeError",
            Kind::Index => "IndexError",
            Kind::BadZip => "BadZipFile",
            Kind::NotImplemented => "NotImplementedError",
            Kind::Runtime => "RuntimeError",
            Kind::SyncRefused | Kind::InvRefused => "Refused",
            Kind::CannotRun | Kind::CgCannotRun => "CannotRun",
        }
    }
    pub fn is_os(&self) -> bool {
        matches!(self.kind, Kind::Os(_))
    }
    /// `ValueError` and its subclasses.
    pub fn is_value(&self) -> bool {
        matches!(
            self.kind,
            Kind::Value
                | Kind::ValueNamed(_)
                | Kind::JsonDecode
                | Kind::UnicodeDecode
                | Kind::InvRefused
        )
    }
    pub fn is_key(&self) -> bool {
        self.kind == Kind::Key
    }
    pub fn is_tar(&self) -> bool {
        matches!(self.kind, Kind::Tar(_))
    }
    pub fn is_type(&self) -> bool {
        self.kind == Kind::Type
    }
    pub fn is_attr(&self) -> bool {
        self.kind == Kind::Attribute
    }
    pub fn is_subprocess(&self) -> bool {
        matches!(self.kind, Kind::Subprocess(_))
    }
}

impl std::fmt::Display for PyErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

/// An I/O error as Python words it: `[Errno 2] No such file or directory: '<path>'`.
pub fn os_err(e: &std::io::Error, path: Option<&Path>) -> PyErr {
    let code = e.raw_os_error();
    let name = match code {
        Some(libc::ENOENT) => "FileNotFoundError",
        Some(libc::EISDIR) => "IsADirectoryError",
        Some(libc::ENOTDIR) => "NotADirectoryError",
        Some(libc::EACCES) | Some(libc::EPERM) => "PermissionError",
        Some(libc::EEXIST) => "FileExistsError",
        _ => "OSError",
    };
    let msg = match code {
        Some(n) => {
            let text = std::io::Error::from_raw_os_error(n).to_string();
            let text = text
                .strip_suffix(&format!(" (os error {n})"))
                .unwrap_or(&text)
                .to_string();
            match path {
                Some(p) => format!("[Errno {n}] {text}: {}", repr_str(&disp(p))),
                None => format!("[Errno {n}] {text}"),
            }
        }
        None => e.to_string(),
    };
    PyErr::new(Kind::Os(name), msg)
}

// ── paths ───────────────────────────────────────────────────────────────────────────────────────

/// A path as Python's `str(Path(...))` writes it: no `.` parts, no empty parts, no trailing `/`.
pub fn disp(p: &Path) -> String {
    norm(&p.to_string_lossy())
}

pub fn norm(s: &str) -> String {
    let abs = s.starts_with('/');
    let lead = if s.starts_with("//") && !s.starts_with("///") {
        "//"
    } else if abs {
        "/"
    } else {
        ""
    };
    let parts: Vec<&str> = s
        .split('/')
        .filter(|x| !x.is_empty() && *x != ".")
        .collect();
    let body = parts.join("/");
    if lead.is_empty() && body.is_empty() {
        ".".to_string()
    } else {
        format!("{lead}{body}")
    }
}

/// `Path.name`.
pub fn name(p: &Path) -> String {
    let s = disp(p);
    match s.rsplit_once('/') {
        Some((_, n)) => n.to_string(),
        None if s == "." => String::new(),
        None => s,
    }
}

pub fn read_bytes(p: &Path) -> R<Vec<u8>> {
    std::fs::read(p).map_err(|e| os_err(&e, Some(p)))
}

/// `Path.read_text()`: UTF-8, with universal newlines (`\r\n` and `\r` read as `\n`).
pub fn read_text(p: &Path) -> R<String> {
    let b = read_bytes(p)?;
    let s = decode_utf8(&b)?;
    Ok(universal_newlines(&s))
}

pub fn universal_newlines(s: &str) -> String {
    if !s.contains('\r') {
        return s.to_string();
    }
    s.replace("\r\n", "\n").replace('\r', "\n")
}

pub fn decode_utf8(b: &[u8]) -> R<String> {
    match std::str::from_utf8(b) {
        Ok(s) => Ok(s.to_string()),
        Err(e) => {
            let at = e.valid_up_to();
            let byte = b[at];
            let (span, why) = match e.error_len() {
                None => (b.len() - at, "unexpected end of data"),
                Some(n) if (0xc2..=0xf4).contains(&byte) => (n, "invalid continuation byte"),
                Some(_) => (1, "invalid start byte"),
            };
            let what = if span > 1 {
                format!("bytes in position {at}-{}", at + span - 1)
            } else {
                format!("byte 0x{byte:02x} in position {at}")
            };
            Err(PyErr::new(
                Kind::UnicodeDecode,
                format!("'utf-8' codec can't decode {what}: {why}"),
            ))
        }
    }
}

pub fn write_text(p: &Path, s: &str) -> R<()> {
    std::fs::write(p, s.as_bytes()).map_err(|e| os_err(&e, Some(p)))
}

pub fn write_bytes(p: &Path, b: &[u8]) -> R<()> {
    std::fs::write(p, b).map_err(|e| os_err(&e, Some(p)))
}

pub fn is_file(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

pub fn is_dir(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

pub fn exists(p: &Path) -> bool {
    std::fs::metadata(p).is_ok()
}

pub fn is_symlink(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// The entries of a directory (`Path.iterdir()`), in directory order.
pub fn iterdir(p: &Path) -> R<Vec<std::path::PathBuf>> {
    let rd = std::fs::read_dir(p).map_err(|e| os_err(&e, Some(p)))?;
    let mut out = Vec::new();
    for e in rd {
        out.push(e.map_err(|e| os_err(&e, Some(p)))?.path());
    }
    Ok(out)
}

pub fn mkdir_p(p: &Path) -> R<()> {
    std::fs::create_dir_all(p).map_err(|e| os_err(&e, Some(p)))
}

// ── strings ─────────────────────────────────────────────────────────────────────────────────────

/// `str.isspace()` for one character.
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// `str.strip()`.
pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `str.split()`.
pub fn split_ws(s: &str) -> Vec<&str> {
    s.split(is_space).filter(|x| !x.is_empty()).collect()
}

/// `str.splitlines()`.
pub fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let brk = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if brk {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' {
                if let Some(&(j, '\n')) = it.peek() {
                    it.next();
                    end = j + 1;
                }
            }
            start = end;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// `s[:n]` by characters.
pub fn head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// `s[n:]` by characters.
pub fn tail_from(s: &str, n: usize) -> String {
    s.chars().skip(n).collect()
}

pub fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    hex(&sha2::Sha256::digest(b))
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

pub fn sha256_file(p: &Path) -> R<String> {
    use sha2::Digest;
    use std::io::Read;
    let mut f = std::fs::File::open(p).map_err(|e| os_err(&e, Some(p)))?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(|e| os_err(&e, Some(p)))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

fn printable(c: char) -> bool {
    let u = c as u32;
    if u < 0x20 || u == 0x7f {
        return false;
    }
    if u < 0x7f {
        return true;
    }
    !matches!(u,
        0x80..=0xa0 | 0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x890..=0x891 | 0x8e2
        | 0x1680 | 0x180e | 0x2000..=0x200f | 0x2028..=0x202f | 0x205f..=0x2064
        | 0x2066..=0x206f | 0x3000 | 0xd800..=0xf8ff | 0xfeff | 0xfff9..=0xfffb
        | 0xfffe..=0xffff | 0x110bd | 0x110cd | 0x13430..=0x1343f | 0x1bca0..=0x1bca3
        | 0x1d173..=0x1d17a | 0xe0001 | 0xe0020..=0xe007f | 0xf0000..=0x10ffff)
}

/// `repr(str)`.
pub fn repr_str(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            _ if c == quote || c == '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if printable(c) => out.push(c),
            _ => {
                let u = c as u32;
                if u <= 0xff {
                    let _ = write!(out, "\\x{u:02x}");
                } else if u <= 0xffff {
                    let _ = write!(out, "\\u{u:04x}");
                } else {
                    let _ = write!(out, "\\U{u:08x}");
                }
            }
        }
    }
    out.push(quote);
    out
}

/// `repr(list_of_str)`.
pub fn repr_list<S: AsRef<str>>(v: &[S]) -> String {
    let items: Vec<String> = v.iter().map(|s| repr_str(s.as_ref())).collect();
    format!("[{}]", items.join(", "))
}

// ── values ──────────────────────────────────────────────────────────────────────────────────────

/// A JSON value with Python's semantics: objects keep their key order, integers are unbounded.
#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    /// Decimal digits, normalised (`-0` is `0`).
    Int(String),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    Dict(Dict),
}

#[derive(Clone, Debug, Default)]
pub struct Dict(pub Vec<(String, Value)>);

impl Dict {
    pub fn new() -> Self {
        Dict(Vec::new())
    }
    pub fn get(&self, k: &str) -> Option<&Value> {
        self.0.iter().find(|(x, _)| x == k).map(|(_, v)| v)
    }
    pub fn contains(&self, k: &str) -> bool {
        self.get(k).is_some()
    }
    /// `d[k] = v`: a new key goes last, an existing key keeps its place.
    pub fn insert(&mut self, k: impl Into<String>, v: Value) {
        let k = k.into();
        if let Some(slot) = self.0.iter_mut().find(|(x, _)| *x == k) {
            slot.1 = v;
        } else {
            self.0.push((k, v));
        }
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.iter().map(|(k, _)| k)
    }
    pub fn values(&self) -> impl Iterator<Item = &Value> {
        self.0.iter().map(|(_, v)| v)
    }
    /// `d.get(k)` with Python's `str()` of the result (`None` when absent).
    pub fn get_str(&self, k: &str) -> String {
        self.get(k).map(py_str).unwrap_or_else(|| "None".into())
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Str(s.to_string())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Str(s)
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::Int(n.to_string())
    }
}
impl From<usize> for Value {
    fn from(n: usize) -> Self {
        Value::Int(n.to_string())
    }
}
impl From<Dict> for Value {
    fn from(d: Dict) -> Self {
        Value::Dict(d)
    }
}
impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Self {
        Value::List(v)
    }
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "NoneType",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "str",
            Value::List(_) => "list",
            Value::Dict(_) => "dict",
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_dict(&self) -> Option<&Dict> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }
    pub fn as_list(&self) -> Option<&Vec<Value>> {
        match self {
            Value::List(v) => Some(v),
            _ => None,
        }
    }
    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Int(s) => s != "0",
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::List(v) => !v.is_empty(),
            Value::Dict(d) => !d.is_empty(),
        }
    }
    /// `x.get(k)`: `None` when absent; `AttributeError` on a value that is not a dict.
    pub fn get(&self, k: &str) -> R<Option<&Value>> {
        match self {
            Value::Dict(d) => Ok(d.get(k)),
            v => Err(PyErr::new(
                Kind::Attribute,
                format!("'{}' object has no attribute 'get'", v.type_name()),
            )),
        }
    }
    /// `x.get(k)` returning Python `None` as `Value::Null`.
    pub fn getv(&self, k: &str) -> R<Value> {
        Ok(self.get(k)?.cloned().unwrap_or(Value::Null))
    }
    /// `x[k]` with a string key.
    pub fn item(&self, k: &str) -> R<&Value> {
        match self {
            Value::Dict(d) => d.get(k).ok_or_else(|| PyErr::key(k)),
            Value::List(_) => Err(PyErr::type_err(
                "list indices must be integers or slices, not str",
            )),
            Value::Str(_) => Err(PyErr::type_err(
                "string indices must be integers, not 'str'",
            )),
            v => Err(PyErr::type_err(format!(
                "'{}' object is not subscriptable",
                v.type_name()
            ))),
        }
    }
    /// `x[k]` that must be a `str` for what the caller does with it next.
    pub fn item_str(&self, k: &str) -> R<&str> {
        let v = self.item(k)?;
        v.as_str().ok_or_else(|| {
            PyErr::type_err(format!(
                "expected str for {}, found {}",
                repr_str(k),
                v.type_name()
            ))
        })
    }
    /// Iteration (`for x in v`): a list's items or a dict's keys.
    pub fn iter_items(&self) -> R<Vec<Value>> {
        match self {
            Value::List(v) => Ok(v.clone()),
            Value::Dict(d) => Ok(d.keys().map(|k| Value::Str(k.clone())).collect()),
            Value::Str(s) => Ok(s.chars().map(|c| Value::Str(c.to_string())).collect()),
            v => Err(PyErr::type_err(format!(
                "'{}' object is not iterable",
                v.type_name()
            ))),
        }
    }
    fn num(&self) -> Option<f64> {
        match self {
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Int(s) => s.parse::<f64>().ok(),
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }
    /// An exact integer (bool counts, as in Python).
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Bool(b) => Some(*b as i128),
            Value::Int(s) => s.parse::<i128>().ok(),
            _ => None,
        }
    }
}

/// `a == b` with Python's rules (`1 == 1.0 == True`; dicts compare without order).
pub fn py_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Str(x), Value::Str(y)) => x == y,
        (Value::List(x), Value::List(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q))
        }
        (Value::Dict(x), Value::Dict(y)) => {
            x.len() == y.len()
                && x.0
                    .iter()
                    .all(|(k, v)| y.get(k).map(|w| py_eq(v, w)).unwrap_or(false))
        }
        (Value::Int(x), Value::Int(y)) => x == y,
        _ => match (a.num(), b.num()) {
            (Some(x), Some(y)) => {
                if let (Some(i), Some(j)) = (a.as_int(), b.as_int()) {
                    i == j
                } else {
                    x == y
                }
            }
            _ => false,
        },
    }
}

/// `a == "literal"`.
pub fn eq_str(a: Option<&Value>, s: &str) -> bool {
    matches!(a, Some(Value::Str(x)) if x == s)
}

/// `repr(float)`.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if f == 0.0 {
        return if f.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    let e = format!("{:e}", f.abs());
    let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let sign = if f < 0.0 { "-" } else { "" };
    let decpt = exp + 1;
    let n = digits.len() as i32;
    let body = if decpt > 16 || decpt <= -4 {
        let rest = &digits[1..];
        let mut s = digits[..1].to_string();
        if !rest.is_empty() {
            s.push('.');
            s.push_str(rest);
        }
        let x = decpt - 1;
        let _ = write!(s, "e{}{:02}", if x < 0 { '-' } else { '+' }, x.abs());
        s
    } else if decpt <= 0 {
        format!("0.{}{}", "0".repeat((-decpt) as usize), digits)
    } else if decpt >= n {
        format!("{}{}.0", digits, "0".repeat((decpt - n) as usize))
    } else {
        format!(
            "{}.{}",
            &digits[..decpt as usize],
            &digits[decpt as usize..]
        )
    };
    format!("{sign}{body}")
}

/// `str(v)`.
pub fn py_str(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        _ => py_repr(v),
    }
}

/// `repr(v)`.
pub fn py_repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Int(s) => s.clone(),
        Value::Float(f) => float_repr(*f),
        Value::Str(s) => repr_str(s),
        Value::List(items) => {
            let parts: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Dict(d) => {
            let parts: Vec<String> =
                d.0.iter()
                    .map(|(k, v)| format!("{}: {}", repr_str(k), py_repr(v)))
                    .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

/// `str(x)` of an optional dict lookup (`None` when absent).
pub fn opt_str(v: Option<&Value>) -> String {
    v.map(py_str).unwrap_or_else(|| "None".into())
}

/// `repr(x)` of an optional dict lookup.
pub fn opt_repr(v: Option<&Value>) -> String {
    v.map(py_repr).unwrap_or_else(|| "None".into())
}

// ── JSON: reading ───────────────────────────────────────────────────────────────────────────────

fn jerr(msg: &str, doc: &[char], pos: usize) -> PyErr {
    let before = &doc[..pos.min(doc.len())];
    let lineno = before.iter().filter(|c| **c == '\n').count() + 1;
    let colno = match before.iter().rposition(|c| *c == '\n') {
        Some(i) => pos - i,
        None => pos + 1,
    };
    PyErr::new(
        Kind::JsonDecode,
        format!("{msg}: line {lineno} column {colno} (char {pos})"),
    )
}

enum Scan {
    Stop(usize),
    Err(PyErr),
}

struct Parser<'a> {
    s: &'a [char],
}

fn ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

impl Parser<'_> {
    fn skip(&self, mut i: usize) -> usize {
        while i < self.s.len() && ws(self.s[i]) {
            i += 1;
        }
        i
    }
    fn lit(&self, i: usize, word: &str) -> bool {
        let w: Vec<char> = word.chars().collect();
        i + w.len() <= self.s.len() && self.s[i..i + w.len()] == w[..]
    }
    fn scan(&self, idx: usize, depth: usize) -> Result<(Value, usize), Scan> {
        let s = self.s;
        if idx >= s.len() {
            return Err(Scan::Stop(idx));
        }
        if depth > 900 {
            return Err(Scan::Err(PyErr::new(
                Kind::Runtime,
                "maximum recursion depth exceeded while decoding a JSON document",
            )));
        }
        match s[idx] {
            '"' => self
                .string(idx + 1)
                .map_err(Scan::Err)
                .map(|(v, e)| (Value::Str(v), e)),
            '{' => self.object(idx + 1, depth + 1),
            '[' => self.array(idx + 1, depth + 1),
            'n' if self.lit(idx, "null") => Ok((Value::Null, idx + 4)),
            't' if self.lit(idx, "true") => Ok((Value::Bool(true), idx + 4)),
            'f' if self.lit(idx, "false") => Ok((Value::Bool(false), idx + 5)),
            'N' if self.lit(idx, "NaN") => Ok((Value::Float(f64::NAN), idx + 3)),
            'I' if self.lit(idx, "Infinity") => Ok((Value::Float(f64::INFINITY), idx + 8)),
            '-' if self.lit(idx, "-Infinity") => Ok((Value::Float(f64::NEG_INFINITY), idx + 9)),
            _ => self.number(idx),
        }
    }
    fn number(&self, start: usize) -> Result<(Value, usize), Scan> {
        let s = self.s;
        let mut i = start;
        if i < s.len() && s[i] == '-' {
            i += 1;
        }
        if i < s.len() && s[i] == '0' {
            i += 1;
        } else if i < s.len() && ('1'..='9').contains(&s[i]) {
            while i < s.len() && s[i].is_ascii_digit() {
                i += 1;
            }
        } else {
            return Err(Scan::Stop(start));
        }
        let int_end = i;
        let mut float = false;
        if i + 1 < s.len() && s[i] == '.' && s[i + 1].is_ascii_digit() {
            i += 2;
            while i < s.len() && s[i].is_ascii_digit() {
                i += 1;
            }
            float = true;
        }
        if i < s.len() && (s[i] == 'e' || s[i] == 'E') {
            let save = i;
            i += 1;
            if i < s.len() && (s[i] == '+' || s[i] == '-') {
                i += 1;
            }
            let d0 = i;
            while i < s.len() && s[i].is_ascii_digit() {
                i += 1;
            }
            if i == d0 {
                i = save;
            } else {
                float = true;
            }
        }
        let text: String = s[start..i].iter().collect();
        if float {
            Ok((Value::Float(text.parse().unwrap_or(f64::NAN)), i))
        } else {
            let t: String = s[start..int_end].iter().collect();
            let t = if t == "-0" { "0".to_string() } else { t };
            Ok((Value::Int(t), i))
        }
    }
    fn string(&self, end: usize) -> R<(String, usize)> {
        let s = self.s;
        let begin = end - 1;
        let mut out = String::new();
        let mut i = end;
        loop {
            let mut j = i;
            while j < s.len() && s[j] != '"' && s[j] != '\\' && (s[j] as u32) > 0x1f {
                j += 1;
            }
            if j >= s.len() {
                return Err(jerr("Unterminated string starting at", s, begin));
            }
            out.extend(&s[i..j]);
            let c = s[j];
            if c == '"' {
                return Ok((out, j + 1));
            }
            if c != '\\' {
                return Err(jerr("Invalid control character at", s, j));
            }
            let mut next = j + 1;
            if next >= s.len() {
                return Err(jerr("Unterminated string starting at", s, begin));
            }
            let e = s[next];
            if e != 'u' {
                let end2 = next + 1;
                let ch = match e {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    _ => return Err(jerr("Invalid \\escape", s, end2 - 2)),
                };
                out.push(ch);
                i = end2;
                continue;
            }
            next += 1;
            let mut end2 = next + 4;
            if end2 >= s.len() {
                return Err(jerr("Invalid \\uXXXX escape", s, next - 1));
            }
            let hex4 = |from: usize, to: usize| -> R<u32> {
                let mut c = 0u32;
                for k in from..to {
                    let d = s[k]
                        .to_digit(16)
                        .ok_or_else(|| jerr("Invalid \\uXXXX escape", s, to - 5))?;
                    c = (c << 4) | d;
                }
                Ok(c)
            };
            let mut c = hex4(next, end2)?;
            next = end2;
            if (0xd800..=0xdbff).contains(&c)
                && end2 + 6 < s.len()
                && s[next] == '\\'
                && s[next + 1] == 'u'
            {
                let c2 = hex4(next + 2, end2 + 6)?;
                end2 += 6;
                if (0xdc00..=0xdfff).contains(&c2) {
                    c = 0x10000 + (((c - 0xd800) << 10) | (c2 - 0xdc00));
                } else {
                    end2 -= 6;
                }
            }
            match char::from_u32(c) {
                Some(ch) => out.push(ch),
                None => {
                    return Err(PyErr::new(
                        Kind::JsonDecode,
                        format!("lone surrogate \\u{c:04x} at char {}", end2 - 6),
                    ))
                }
            }
            i = end2;
        }
    }
    fn object(&self, start: usize, depth: usize) -> Result<(Value, usize), Scan> {
        let s = self.s;
        let mut d = Dict::new();
        let mut idx = self.skip(start);
        if idx >= s.len() || s[idx] != '}' {
            loop {
                if idx >= s.len() || s[idx] != '"' {
                    return Err(Scan::Err(jerr(
                        "Expecting property name enclosed in double quotes",
                        s,
                        idx,
                    )));
                }
                let (key, next) = self.string(idx + 1).map_err(Scan::Err)?;
                idx = self.skip(next);
                if idx >= s.len() || s[idx] != ':' {
                    return Err(Scan::Err(jerr("Expecting ':' delimiter", s, idx)));
                }
                idx = self.skip(idx + 1);
                let (val, next) = self.scan(idx, depth)?;
                d.insert(key, val);
                idx = self.skip(next);
                if idx < s.len() && s[idx] == '}' {
                    break;
                }
                if idx >= s.len() || s[idx] != ',' {
                    return Err(Scan::Err(jerr("Expecting ',' delimiter", s, idx)));
                }
                let comma = idx;
                idx = self.skip(idx + 1);
                if idx < s.len() && s[idx] == '}' {
                    return Err(Scan::Err(jerr(
                        "Illegal trailing comma before end of object",
                        s,
                        comma,
                    )));
                }
            }
        }
        Ok((Value::Dict(d), idx + 1))
    }
    fn array(&self, start: usize, depth: usize) -> Result<(Value, usize), Scan> {
        let s = self.s;
        let mut v = Vec::new();
        let mut idx = self.skip(start);
        if idx >= s.len() || s[idx] != ']' {
            loop {
                let (val, next) = self.scan(idx, depth)?;
                v.push(val);
                idx = self.skip(next);
                if idx < s.len() && s[idx] == ']' {
                    break;
                }
                if idx >= s.len() || s[idx] != ',' {
                    return Err(Scan::Err(jerr("Expecting ',' delimiter", s, idx)));
                }
                let comma = idx;
                idx = self.skip(idx + 1);
                if idx < s.len() && s[idx] == ']' {
                    return Err(Scan::Err(jerr(
                        "Illegal trailing comma before end of array",
                        s,
                        comma,
                    )));
                }
            }
        }
        Ok((Value::List(v), idx + 1))
    }
}

/// `json.loads(str)`.
pub fn loads(text: &str) -> R<Value> {
    let chars: Vec<char> = text.chars().collect();
    if chars.first() == Some(&'\u{feff}') {
        return Err(jerr(
            "Unexpected UTF-8 BOM (decode using utf-8-sig)",
            &chars,
            0,
        ));
    }
    let p = Parser { s: &chars };
    let idx = p.skip(0);
    let (v, end) = match p.scan(idx, 0) {
        Ok(x) => x,
        Err(Scan::Stop(at)) => return Err(jerr("Expecting value", &chars, at)),
        Err(Scan::Err(e)) => return Err(e),
    };
    let end = p.skip(end);
    if end != chars.len() {
        return Err(jerr("Extra data", &chars, end));
    }
    Ok(v)
}

/// `json.loads(bytes)`: UTF-8, a UTF-8 BOM dropped. UTF-16/32 documents are refused.
pub fn loads_bytes(b: &[u8]) -> R<Value> {
    let b = b.strip_prefix(b"\xef\xbb\xbf").unwrap_or(b);
    let wide = b.starts_with(b"\xff\xfe")
        || b.starts_with(b"\xfe\xff")
        || (b.len() >= 4 && (b[0] == 0 || b[1] == 0 || b[2] == 0 || b[3] == 0));
    if wide {
        return Err(PyErr::new(
            Kind::UnicodeDecode,
            "a UTF-16 or UTF-32 JSON document (only UTF-8 is read)",
        ));
    }
    loads(&decode_utf8(b)?)
}

// ── JSON: writing ───────────────────────────────────────────────────────────────────────────────

fn escape(out: &mut String, s: &str, ascii: bool) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c if ascii && !(' '..='~').contains(&c) => {
                let u = c as u32;
                if u < 0x10000 {
                    let _ = write!(out, "\\u{u:04x}");
                } else {
                    let v = u - 0x10000;
                    let _ = write!(
                        out,
                        "\\u{:04x}\\u{:04x}",
                        0xd800 | ((v >> 10) & 0x3ff),
                        0xdc00 | (v & 0x3ff)
                    );
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `json.dumps` options.
#[derive(Clone, Copy)]
pub struct Dump {
    pub indent: Option<usize>,
    pub sort_keys: bool,
    pub ensure_ascii: bool,
}

impl Dump {
    /// `json.dumps(v)`.
    pub const PLAIN: Dump = Dump {
        indent: None,
        sort_keys: false,
        ensure_ascii: true,
    };
    /// `json.dumps(v, indent=2)`.
    pub const INDENT: Dump = Dump {
        indent: Some(2),
        sort_keys: false,
        ensure_ascii: true,
    };
    /// `json.dumps(v, indent=2, sort_keys=True)`.
    pub const SORTED: Dump = Dump {
        indent: Some(2),
        sort_keys: true,
        ensure_ascii: true,
    };
}

pub fn dumps(v: &Value, o: Dump) -> String {
    let mut out = String::new();
    enc(&mut out, v, o, 0);
    out
}

fn enc(out: &mut String, v: &Value, o: Dump, level: usize) {
    let (item_sep, nl) = match o.indent {
        Some(n) => (",".to_string(), Some(n)),
        None => (", ".to_string(), None),
    };
    let newline = |out: &mut String, lvl: usize| {
        if let Some(n) = nl {
            out.push('\n');
            out.push_str(&" ".repeat(n * lvl));
        }
    };
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(s) => out.push_str(s),
        Value::Float(f) => {
            if f.is_nan() {
                out.push_str("NaN")
            } else if f.is_infinite() {
                out.push_str(if *f > 0.0 { "Infinity" } else { "-Infinity" })
            } else {
                out.push_str(&float_repr(*f))
            }
        }
        Value::Str(s) => escape(out, s, o.ensure_ascii),
        Value::List(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, x) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(&item_sep);
                }
                newline(out, level + 1);
                enc(out, x, o, level + 1);
            }
            newline(out, level);
            out.push(']');
        }
        Value::Dict(d) => {
            if d.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut pairs: Vec<&(String, Value)> = d.0.iter().collect();
            if o.sort_keys {
                pairs.sort_by(|a, b| a.0.cmp(&b.0));
            }
            out.push('{');
            for (i, (k, x)) in pairs.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(&item_sep);
                }
                newline(out, level + 1);
                escape(out, k, o.ensure_ascii);
                out.push_str(": ");
                enc(out, x, o, level + 1);
            }
            newline(out, level);
            out.push('}');
        }
    }
}

/// Build a dict from pairs, in order.
pub fn dict<I, K>(pairs: I) -> Dict
where
    I: IntoIterator<Item = (K, Value)>,
    K: Into<String>,
{
    let mut d = Dict::new();
    for (k, v) in pairs {
        d.insert(k, v);
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trips_python_bytes() {
        let v = loads(r#"{"b": [1, 2.5, "é", {}], "a": null, "b": true}"#).unwrap();
        assert_eq!(dumps(&v, Dump::PLAIN), r#"{"b": true, "a": null}"#);
        let v = loads(r#"{"z": "é ", "a": [1e16, 0.0001, 1e-05, -0.0, []]}"#).unwrap();
        assert_eq!(
            dumps(&v, Dump::SORTED),
            "{\n  \"a\": [\n    1e+16,\n    0.0001,\n    1e-05,\n    -0.0,\n    []\n  ],\n  \"z\": \"\\u00e9\\u2028\"\n}"
        );
    }

    #[test]
    fn json_errors_read_as_python_words_them() {
        let e = |s: &str| loads(s).unwrap_err().msg;
        assert_eq!(e(""), "Expecting value: line 1 column 1 (char 0)");
        assert_eq!(
            e("{\"a\": 1,}"),
            "Illegal trailing comma before end of object: line 1 column 8 (char 7)"
        );
        assert_eq!(e("{} x"), "Extra data: line 1 column 4 (char 3)");
        assert_eq!(
            e("[1 2]"),
            "Expecting ',' delimiter: line 1 column 4 (char 3)"
        );
        assert_eq!(
            e("{\n\"a\" 1}"),
            "Expecting ':' delimiter: line 2 column 5 (char 6)"
        );
        assert_eq!(
            e("\"abc"),
            "Unterminated string starting at: line 1 column 1 (char 0)"
        );
    }

    #[test]
    fn repr_and_lines_follow_python() {
        assert_eq!(repr_str("it's"), "\"it's\"");
        assert_eq!(repr_str("a\nb\u{a0}"), "'a\\nb\\xa0'");
        assert_eq!(splitlines("a\r\nb\rc\n\nd\n"), vec!["a", "b", "c", "", "d"]);
        assert_eq!(norm("./cand/"), "cand");
        assert_eq!(norm(""), ".");
        assert_eq!(float_repr(1.5), "1.5");
        assert_eq!(float_repr(1e15), "1000000000000000.0");
    }
}
