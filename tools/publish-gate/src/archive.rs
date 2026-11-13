// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Read-only tar (plain or gzip) and zip readers. They select members the way the gate's rules
//! were first written against (Python's `tarfile` and `zipfile`): the same member names, the same
//! "is a regular file" test, the same last-wins name lookup, and an unreadable archive is an error
//! the rule refuses, never a pass. Compressions they do not read (bzip2, xz, zstd; zip methods
//! other than stored and deflate) are errors.

use crate::py::{repr_str, Kind, PyErr, R};
use std::io::Read;
use std::path::Path;

const BLOCK: usize = 512;

fn tar_err(msg: impl Into<String>) -> PyErr {
    PyErr::new(Kind::Tar("ReadError"), msg)
}

#[derive(Clone, Debug)]
pub struct Member {
    pub name: String,
    pub typ: u8,
    pub linkname: String,
    pub size: u64,
    offset_data: usize,
}

const REGULAR: &[u8] = b"0\x007S";
const SUPPORTED: &[u8] = b"0\x007S123456LK";

impl Member {
    /// `TarInfo.isfile()`.
    pub fn isfile(&self) -> bool {
        REGULAR.contains(&self.typ)
    }
    pub fn isdir(&self) -> bool {
        self.typ == b'5'
    }
    fn islnk(&self) -> bool {
        self.typ == b'1'
    }
    fn issym(&self) -> bool {
        self.typ == b'2'
    }
}

pub struct Tar {
    data: Vec<u8>,
    pub members: Vec<Member>,
}

fn nts(b: &[u8]) -> String {
    let end = b.iter().position(|x| *x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn nti(b: &[u8]) -> Result<u64, ()> {
    if b[0] == 0o200 || b[0] == 0o377 {
        let mut n: i128 = 0;
        for x in &b[1..] {
            n = (n << 8) + *x as i128;
        }
        if b[0] == 0o377 {
            n -= 1i128 << (8 * (b.len() - 1));
        }
        return u64::try_from(n).map_err(|_| ());
    }
    let s = nts(b);
    let t = crate::py::strip(&s);
    let t = if t.is_empty() { "0" } else { t };
    u64::from_str_radix(t, 8).map_err(|_| ())
}

enum HeaderErr {
    Empty,
    Truncated,
    Eof,
    Invalid(&'static str),
}

fn header(buf: &[u8]) -> Result<Member, HeaderErr> {
    if buf.is_empty() {
        return Err(HeaderErr::Empty);
    }
    if buf.len() != BLOCK {
        return Err(HeaderErr::Truncated);
    }
    if buf.iter().all(|x| *x == 0) {
        return Err(HeaderErr::Eof);
    }
    let chk = nti(&buf[148..156]).map_err(|_| HeaderErr::Invalid("invalid header"))?;
    let mut unsigned: i64 = 256;
    let mut signed: i64 = 256;
    for (i, x) in buf.iter().enumerate() {
        if (148..156).contains(&i) {
            continue;
        }
        unsigned += *x as i64;
        signed += *x as i8 as i64;
    }
    if chk as i64 != unsigned && chk as i64 != signed {
        return Err(HeaderErr::Invalid("bad checksum"));
    }
    let size = nti(&buf[124..136]).map_err(|_| HeaderErr::Invalid("invalid header"))?;
    let mut typ = buf[156];
    let mut name = nts(&buf[0..100]);
    let linkname = nts(&buf[157..257]);
    let prefix = nts(&buf[345..500]);
    if typ == 0 && name.ends_with('/') {
        typ = b'5';
    }
    if typ == b'5' {
        name = name.trim_end_matches('/').to_string();
    }
    if !prefix.is_empty() && !b"LKS".contains(&typ) {
        name = format!("{prefix}/{name}");
    }
    Ok(Member {
        name,
        typ,
        linkname,
        size,
        offset_data: 0,
    })
}

fn blocks(n: u64) -> usize {
    (n as usize).div_ceil(BLOCK) * BLOCK
}

fn pax_records(b: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let Some(sp) = b[i..].iter().position(|x| *x == b' ') else {
            break;
        };
        let Ok(len) = std::str::from_utf8(&b[i..i + sp])
            .unwrap_or("")
            .parse::<usize>()
        else {
            break;
        };
        if len == 0 || i + len > b.len() {
            break;
        }
        let rec = &b[i + sp + 1..i + len];
        let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
        if let Some(eq) = rec.iter().position(|x| *x == b'=') {
            out.push((
                String::from_utf8_lossy(&rec[..eq]).into_owned(),
                String::from_utf8_lossy(&rec[eq + 1..]).into_owned(),
            ));
        }
        i += len;
    }
    out
}

fn parse_members(data: &[u8]) -> R<Vec<Member>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut global: Vec<(String, String)> = Vec::new();
    let mut pending_name: Option<String> = None;
    let mut pending_link: Option<String> = None;
    let mut pending_pax: Vec<(String, String)> = Vec::new();
    loop {
        let buf = &data[off.min(data.len())..(off + BLOCK).min(data.len())];
        let mut m = match header(buf) {
            Ok(m) => m,
            Err(HeaderErr::Eof) => break,
            Err(HeaderErr::Empty) if off == 0 => return Err(tar_err("empty file")),
            Err(HeaderErr::Truncated) if off == 0 => return Err(tar_err("truncated header")),
            Err(HeaderErr::Invalid(why)) if off == 0 => return Err(tar_err(why)),
            Err(_) => break,
        };
        off += BLOCK;
        match m.typ {
            b'L' | b'K' => {
                let end = (off + m.size as usize).min(data.len());
                let text = nts(&data[off..end]);
                if m.typ == b'L' {
                    pending_name = Some(text);
                } else {
                    pending_link = Some(text);
                }
                off += blocks(m.size);
                continue;
            }
            b'x' | b'X' | b'g' => {
                let end = (off + m.size as usize).min(data.len());
                let recs = pax_records(&data[off..end]);
                if m.typ == b'g' {
                    global.extend(recs);
                } else {
                    pending_pax.extend(recs);
                }
                off += blocks(m.size);
                continue;
            }
            _ => {}
        }
        for (k, v) in global.iter().chain(pending_pax.iter()) {
            match k.as_str() {
                "path" => m.name = v.clone(),
                "linkpath" => m.linkname = v.clone(),
                "size" => {
                    if let Ok(n) = v.parse() {
                        m.size = n
                    }
                }
                _ => {}
            }
        }
        if let Some(n) = pending_name.take() {
            m.name = n;
        }
        if let Some(l) = pending_link.take() {
            m.linkname = l;
        }
        pending_pax.clear();
        if m.isdir() {
            m.name = m.name.trim_end_matches('/').to_string();
        }
        m.offset_data = off;
        if m.isfile() || !SUPPORTED.contains(&m.typ) {
            off += blocks(m.size);
        }
        out.push(m);
    }
    Ok(out)
}

fn norm_path(s: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for p in s.split('/') {
        match p {
            "" | "." => {}
            ".." if parts.last().is_some_and(|x| *x != "..") => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    let body = parts.join("/");
    if s.starts_with('/') {
        format!("/{body}")
    } else if body.is_empty() {
        ".".into()
    } else {
        body
    }
}

impl Tar {
    /// `tarfile.open(path)`.
    pub fn open(p: &Path) -> R<Tar> {
        let b = crate::py::read_bytes(p)?;
        Tar::from_bytes(&b)
    }

    /// `tarfile.open(fileobj=..., mode="r:*")`.
    pub fn from_bytes(b: &[u8]) -> R<Tar> {
        let mut errs: Vec<String> = Vec::new();
        if b.starts_with(&[0x1f, 0x8b]) {
            let mut out = Vec::new();
            match flate2::read::MultiGzDecoder::new(b).read_to_end(&mut out) {
                Ok(_) => match parse_members(&out) {
                    Ok(members) => return Ok(Tar { data: out, members }),
                    Err(e) => errs.push(format!("- method gz: ReadError({})", repr_str(&e.msg))),
                },
                Err(_) => errs.push("- method gz: ReadError('not a gzip file')".into()),
            }
        } else if b.is_empty() {
            errs.push("- method gz: ReadError('empty file')".into());
        } else {
            errs.push("- method gz: ReadError('not a gzip file')".into());
        }
        let unsupported = [
            ("bz2", b"BZh".as_slice(), "not a bzip2 file"),
            ("xz", b"\xfd7zXZ\x00".as_slice(), "not an lzma file"),
            ("zst", b"\x28\xb5\x2f\xfd".as_slice(), "not a zstd file"),
        ];
        for (method, magic, why) in unsupported {
            if b.starts_with(magic) {
                errs.push(format!(
                    "- method {method}: CompressionError('{method} compression is not read here')"
                ));
            } else {
                errs.push(format!("- method {method}: ReadError('{why}')"));
            }
        }
        match parse_members(b) {
            Ok(members) => {
                return Ok(Tar {
                    data: b.to_vec(),
                    members,
                })
            }
            Err(e) => errs.push(format!("- method tar: ReadError({})", repr_str(&e.msg))),
        }
        Err(tar_err(format!(
            "file could not be opened successfully:\n{}",
            errs.join("\n")
        )))
    }

    fn data_of(&self, m: &Member) -> R<Vec<u8>> {
        let end = m.offset_data + m.size as usize;
        if end > self.data.len() {
            return Err(tar_err("unexpected end of data"));
        }
        Ok(self.data[m.offset_data..end].to_vec())
    }

    fn lookup(&self, name: &str, limit: Option<usize>, normalize: bool) -> Option<usize> {
        let upto = limit.unwrap_or(self.members.len());
        let want = if normalize {
            norm_path(name)
        } else {
            name.to_string()
        };
        (0..upto).rev().find(|&i| {
            let n = &self.members[i].name;
            if normalize {
                norm_path(n) == want
            } else {
                *n == want
            }
        })
    }

    fn extract_at(&self, i: usize, depth: usize) -> R<Option<Vec<u8>>> {
        let m = &self.members[i];
        if m.isfile() || !SUPPORTED.contains(&m.typ) {
            return self.data_of(m).map(Some);
        }
        if (m.islnk() || m.issym()) && depth < 32 {
            let (link, limit) = if m.issym() {
                let dir = m.name.rsplit_once('/').map(|x| x.0).unwrap_or("");
                let parts: Vec<&str> = [dir, m.linkname.as_str()]
                    .into_iter()
                    .filter(|x| !x.is_empty())
                    .collect();
                (parts.join("/"), None)
            } else {
                (m.linkname.clone(), Some(i))
            };
            return match self.lookup(&link, limit, true) {
                Some(j) => self.extract_at(j, depth + 1),
                None => Err(PyErr::new(
                    Kind::Key,
                    repr_str(&format!("linkname {} not found", repr_str(&link))),
                )),
            };
        }
        Ok(None)
    }

    /// `extractfile(member)`: `None` for a directory or a device.
    pub fn extract(&self, i: usize) -> R<Option<Vec<u8>>> {
        self.extract_at(i, 0)
    }

    /// `extractfile(name)`: `KeyError` when no member has that name (the last one wins).
    pub fn extract_name(&self, name: &str) -> R<Option<Vec<u8>>> {
        match self.lookup(name.trim_end_matches('/'), None, false) {
            Some(i) => self.extract(i),
            None => Err(PyErr::new(
                Kind::Key,
                repr_str(&format!("filename {} not found", repr_str(name))),
            )),
        }
    }
}

// ── zip ─────────────────────────────────────────────────────────────────────────────────────────

fn bad_zip(msg: impl Into<String>) -> PyErr {
    PyErr::new(Kind::BadZip, msg)
}

const CP437: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";

fn cp437(b: &[u8]) -> String {
    let high: Vec<char> = CP437.chars().collect();
    b.iter()
        .map(|x| {
            if *x < 0x80 {
                *x as char
            } else {
                high[(*x - 0x80) as usize]
            }
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct ZipEntry {
    pub filename: String,
    orig: String,
    flags: u16,
    method: u16,
    crc: u32,
    csize: u64,
    header_offset: u64,
}

impl ZipEntry {
    pub fn is_dir(&self) -> bool {
        self.filename.ends_with('/')
    }
}

pub struct Zip {
    data: Vec<u8>,
    concat: u64,
    pub entries: Vec<ZipEntry>,
}

fn u16le(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
fn u32le(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn decode_name(raw: &[u8], flags: u16) -> R<String> {
    if flags & 0x800 != 0 {
        crate::py::decode_utf8(raw)
    } else {
        Ok(cp437(raw))
    }
}

impl Zip {
    /// `zipfile.ZipFile(path)`.
    pub fn open(p: &Path) -> R<Zip> {
        let data = crate::py::read_bytes(p)?;
        let n = data.len();
        let lo = n.saturating_sub(22 + 65535);
        let eocd = (lo..n.saturating_sub(21))
            .rev()
            .find(|&i| data[i..i + 4] == *b"PK\x05\x06")
            .ok_or_else(|| bad_zip("File is not a zip file"))?;
        if eocd >= 20 && data[eocd - 20..eocd - 16] == *b"PK\x06\x07" {
            return Err(bad_zip("zip64 archives are not read here"));
        }
        let size_cd = u32le(&data, eocd + 12) as u64;
        let offset_cd = u32le(&data, eocd + 16) as u64;
        let concat = (eocd as u64)
            .checked_sub(size_cd + offset_cd)
            .ok_or_else(|| bad_zip("Bad offset for central directory"))?;
        let mut entries = Vec::new();
        let mut i = (offset_cd + concat) as usize;
        let end = i + size_cd as usize;
        while i < end {
            if i + 46 > n || data[i..i + 4] != *b"PK\x01\x02" {
                return Err(bad_zip("Bad magic number for central directory"));
            }
            let flags = u16le(&data, i + 8);
            let method = u16le(&data, i + 10);
            let crc = u32le(&data, i + 16);
            let csize = u32le(&data, i + 20) as u64;
            let nlen = u16le(&data, i + 28) as usize;
            let xlen = u16le(&data, i + 30) as usize;
            let clen = u16le(&data, i + 32) as usize;
            let header_offset = u32le(&data, i + 42) as u64;
            if i + 46 + nlen > n {
                return Err(bad_zip("Truncated central directory"));
            }
            let orig = decode_name(&data[i + 46..i + 46 + nlen], flags)?;
            let filename = match orig.find('\0') {
                Some(z) => orig[..z].to_string(),
                None => orig.clone(),
            };
            entries.push(ZipEntry {
                filename,
                orig,
                flags,
                method,
                crc,
                csize,
                header_offset,
            });
            i += 46 + nlen + xlen + clen;
        }
        Ok(Zip {
            data,
            concat,
            entries,
        })
    }

    pub fn namelist(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.filename.clone()).collect()
    }

    /// `ZipFile.read(name)`.
    pub fn read(&self, name: &str) -> R<Vec<u8>> {
        let e = self
            .entries
            .iter()
            .rev()
            .find(|e| e.filename == name)
            .ok_or_else(|| {
                PyErr::new(
                    Kind::Key,
                    repr_str(&format!(
                        "There is no item named {} in the archive",
                        repr_str(name)
                    )),
                )
            })?;
        let d = &self.data;
        let at = (e.header_offset + self.concat) as usize;
        if at + 30 > d.len() {
            return Err(bad_zip("Truncated file header"));
        }
        if d[at..at + 4] != *b"PK\x03\x04" {
            return Err(bad_zip("Bad magic number for file header"));
        }
        let nlen = u16le(d, at + 26) as usize;
        let xlen = u16le(d, at + 28) as usize;
        if at + 30 + nlen > d.len() {
            return Err(bad_zip("Truncated file header"));
        }
        let fname = decode_name(&d[at + 30..at + 30 + nlen], e.flags)?;
        if fname != e.orig {
            return Err(bad_zip(format!(
                "File name in directory {} and header {} differ.",
                repr_str(&e.orig),
                repr_str(&fname)
            )));
        }
        if e.flags & 1 != 0 {
            return Err(PyErr::new(
                Kind::Runtime,
                format!(
                    "File {} is encrypted, password required for extraction",
                    repr_str(name)
                ),
            ));
        }
        let start = at + 30 + nlen + xlen;
        let stop = start + e.csize as usize;
        if stop > d.len() {
            return Err(bad_zip("Truncated file data"));
        }
        let raw = &d[start..stop];
        let out = match e.method {
            0 => raw.to_vec(),
            8 => {
                let mut out = Vec::new();
                flate2::read::DeflateDecoder::new(raw)
                    .read_to_end(&mut out)
                    .map_err(|err| PyErr::new(Kind::Os("error"), err.to_string()))?;
                out
            }
            _ => {
                return Err(PyErr::new(
                    Kind::NotImplemented,
                    "That compression method is not supported",
                ))
            }
        };
        if crc32fast::hash(&out) != e.crc {
            return Err(bad_zip(format!(
                "Bad CRC-32 for file {}",
                repr_str(&e.filename)
            )));
        }
        Ok(out)
    }
}
