//! Bounded POSIX/GNU tar reader: ustar prefixes, PAX `path`/`size`, GNU long names.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub name: String,
    /// Raw type flag (`b'0'` regular, `b'5'` directory, ...).
    pub kind: u8,
    pub size: u64,
    pub mode: u32,
}

impl Entry {
    /// Python `TarInfo.isfile()` for the types accepted here.
    pub fn is_file(&self) -> bool {
        matches!(self.kind, b'0' | 0 | b'7')
    }
}

fn octal(field: &[u8]) -> Result<u64, String> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        // GNU base-256 for large sizes.
        let mut value: u64 = (field[0] & 0x7f) as u64;
        for byte in &field[1..] {
            value = value.checked_mul(256).ok_or("tar number overflow")? + *byte as u64;
        }
        return Ok(value);
    }
    let text: String = field
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as char)
        .collect();
    let text = text.trim_matches(' ');
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).map_err(|_| "invalid tar number".to_owned())
}

fn text(field: &[u8]) -> Result<String, String> {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8(field[..end].to_vec()).map_err(|_| "tar name is not UTF-8".to_owned())
}

fn pax(data: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let mut rest = data;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|b| *b == b' ')
            .ok_or("invalid PAX record")?;
        let length: usize = std::str::from_utf8(&rest[..space])
            .ok()
            .and_then(|v| v.parse().ok())
            .ok_or("invalid PAX record length")?;
        if length <= space + 1 || length > rest.len() || rest[length - 1] != b'\n' {
            return Err("invalid PAX record".into());
        }
        let record = &rest[space + 1..length - 1];
        let equals = record
            .iter()
            .position(|b| *b == b'=')
            .ok_or("invalid PAX record")?;
        let key = String::from_utf8(record[..equals].to_vec()).map_err(|_| "invalid PAX key")?;
        let value =
            String::from_utf8(record[equals + 1..].to_vec()).map_err(|_| "invalid PAX value")?;
        out.insert(key, value);
        rest = &rest[length..];
    }
    Ok(out)
}

fn padded(size: u64) -> u64 {
    size.div_ceil(512) * 512
}

/// Header-by-header reader. After `next`, the caller must consume exactly
/// `entry.size` bytes through `data` or call `skip`.
pub struct Reader<R: Read> {
    source: R,
    pending: u64,
    done: bool,
}

impl<R: Read> Reader<R> {
    pub fn new(source: R) -> Self {
        Reader {
            source,
            pending: 0,
            done: false,
        }
    }

    fn block(&mut self) -> Result<Option<[u8; 512]>, String> {
        let mut block = [0u8; 512];
        let mut filled = 0;
        while filled < 512 {
            let n = self
                .source
                .read(&mut block[filled..])
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return if filled == 0 {
                    Ok(None)
                } else {
                    Err("truncated tar header".into())
                };
            }
            filled += n;
        }
        Ok(Some(block))
    }

    fn discard(&mut self, mut count: u64) -> Result<(), String> {
        let mut buffer = [0u8; 65536];
        while count > 0 {
            let want = count.min(buffer.len() as u64) as usize;
            let n = self
                .source
                .read(&mut buffer[..want])
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("truncated tar member".into());
            }
            count -= n as u64;
        }
        Ok(())
    }

    fn payload(&mut self, size: u64, limit: u64) -> Result<Vec<u8>, String> {
        if size > limit {
            return Err("tar extended header exceeds bound".into());
        }
        let mut data = vec![0u8; size as usize];
        self.source
            .read_exact(&mut data)
            .map_err(|_| "truncated tar member")?;
        self.discard(padded(size) - size)?;
        Ok(data)
    }

    /// Skip whatever remains of the previous member.
    pub fn skip(&mut self) -> Result<(), String> {
        let pending = std::mem::take(&mut self.pending);
        self.discard(pending)
    }

    pub fn next(&mut self) -> Result<Option<Entry>, String> {
        self.skip()?;
        if self.done {
            return Ok(None);
        }
        let mut long_name: Option<String> = None;
        let mut extended: BTreeMap<String, String> = BTreeMap::new();
        loop {
            let Some(block) = self.block()? else {
                self.done = true;
                return Ok(None);
            };
            if block.iter().all(|b| *b == 0) {
                self.done = true;
                return Ok(None);
            }
            let stored = octal(&block[148..156])?;
            let sum: u64 = block
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    if (148..156).contains(&i) {
                        32
                    } else {
                        *b as u64
                    }
                })
                .sum();
            if stored != sum {
                return Err("invalid tar header checksum".into());
            }
            let kind = block[156];
            let size = octal(&block[124..136])?;
            match kind {
                b'x' => {
                    let data = self.payload(size, 1 << 20)?;
                    extended.extend(pax(&data)?);
                    continue;
                }
                b'g' => {
                    let data = self.payload(size, 1 << 20)?;
                    let global = pax(&data)?;
                    if global.contains_key("path") || global.contains_key("size") {
                        return Err("unsupported global tar member metadata".into());
                    }
                    continue;
                }
                b'L' => {
                    let data = self.payload(size, 1 << 16)?;
                    long_name = Some(text(&data)?);
                    continue;
                }
                b'K' => {
                    self.payload(size, 1 << 16)?;
                    continue;
                }
                _ => {}
            }
            let mut name = text(&block[0..100])?;
            if &block[257..262] == b"ustar" {
                let prefix = text(&block[345..500])?;
                if !prefix.is_empty() && block[263..265] == *b"00" {
                    name = prefix + "/" + &name;
                }
            }
            if let Some(value) = long_name.take() {
                name = value;
            }
            if let Some(value) = extended.get("path") {
                name = value.clone();
            }
            let size = match extended.get("size") {
                Some(value) => value.parse().map_err(|_| "invalid PAX size")?,
                None => size,
            };
            let mode = octal(&block[100..108])? as u32;
            // Members without data still occupy their padded size on disk for
            // regular files only; links/directories carry zero-length bodies.
            let body = if matches!(kind, b'1' | b'2' | b'3' | b'4' | b'5' | b'6') {
                0
            } else {
                size
            };
            self.pending = padded(body);
            return Ok(Some(Entry {
                name,
                kind,
                size: body,
                mode,
            }));
        }
    }

    /// Consume everything left in the source and return it.
    pub fn finish(mut self) -> Result<R, String> {
        self.skip()?;
        let mut buffer = vec![0u8; 1 << 20];
        loop {
            match self.source.read(&mut buffer) {
                Ok(0) => return Ok(self.source),
                Ok(_) => {}
                Err(error) => return Err(error.to_string()),
            }
        }
    }

    /// Reader over the current member's bytes (exactly `size`).
    pub fn data(&mut self, size: u64) -> MemberReader<'_, R> {
        let padding = self.pending - size;
        self.pending = 0;
        MemberReader {
            reader: self,
            remaining: size,
            padding,
        }
    }
}

pub struct MemberReader<'a, R: Read> {
    reader: &'a mut Reader<R>,
    remaining: u64,
    padding: u64,
}

impl<R: Read> Read for MemberReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            if self.padding > 0 {
                let padding = std::mem::take(&mut self.padding);
                self.reader
                    .discard(padding)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e))?;
            }
            return Ok(0);
        }
        let want = (buffer.len() as u64).min(self.remaining) as usize;
        let n = self.reader.source.read(&mut buffer[..want])?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

impl<R: Read> Drop for MemberReader<'_, R> {
    fn drop(&mut self) {
        // Unread bytes become pending again so the next header stays aligned.
        self.reader.pending = self.remaining + self.padding;
    }
}

/// Seeking index of an uncompressed archive: name -> (data offset, entry).
/// Later duplicates replace earlier ones, as in Python `getmember`.
pub fn index(path: &Path) -> Result<BTreeMap<String, (u64, Entry)>, String> {
    struct Counting {
        file: File,
        position: u64,
    }
    impl Read for Counting {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let n = self.file.read(buffer)?;
            self.position += n as u64;
            Ok(n)
        }
    }
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut reader = Reader::new(Counting { file, position: 0 });
    let mut out = BTreeMap::new();
    while let Some(entry) = reader.next()? {
        let offset = reader.source.position;
        let skip = std::mem::take(&mut reader.pending);
        reader.source.position = reader
            .source
            .file
            .seek(SeekFrom::Current(skip as i64))
            .map_err(|e| e.to_string())?;
        out.insert(entry.name.clone(), (offset, entry));
    }
    Ok(out)
}

/// Read one bounded regular member located by `index`.
pub fn read_member(
    path: &Path,
    members: &BTreeMap<String, (u64, Entry)>,
    name: &str,
    limit: u64,
) -> Result<Option<Vec<u8>>, String> {
    let Some((offset, entry)) = members.get(name) else {
        return Ok(None);
    };
    if !entry.is_file() || entry.size >= limit {
        return Err("invalid image archive metadata member".into());
    }
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    file.seek(SeekFrom::Start(*offset))
        .map_err(|e| e.to_string())?;
    let mut data = vec![0u8; entry.size as usize];
    file.read_exact(&mut data)
        .map_err(|_| "truncated image archive member")?;
    Ok(Some(data))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn header(name: &str, kind: u8, size: u64, mode: u32) -> Vec<u8> {
        let mut block = vec![0u8; 512];
        block[..name.len()].copy_from_slice(name.as_bytes());
        block[100..107].copy_from_slice(format!("{mode:07o}").as_bytes());
        block[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
        block[156] = kind;
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        block[148..156].copy_from_slice(b"        ");
        let sum: u64 = block.iter().map(|b| *b as u64).sum();
        block[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        block
    }

    pub fn archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in members {
            if name.len() > 100 {
                let record = format!("path={name}\n");
                let mut length = record.len() + 1;
                while format!("{length} {record}").len() != length {
                    length += 1;
                }
                let pax = format!("{length} {record}");
                out.extend(header("pax", b'x', pax.len() as u64, 0o644));
                out.extend(pax.as_bytes());
                out.resize(padded(out.len() as u64) as usize, 0);
                out.extend(header("short", b'0', data.len() as u64, 0o444));
            } else {
                out.extend(header(name, b'0', data.len() as u64, 0o444));
            }
            out.extend(*data);
            out.resize(padded(out.len() as u64) as usize, 0);
        }
        out.extend([0u8; 1024]);
        out
    }

    #[test]
    fn streams_and_indexes_members() {
        let long = "bundles/".to_owned() + &"x".repeat(120);
        let bytes = archive(&[
            ("manifest.json", b"{}"),
            (&long, b"payload"),
            ("empty", b""),
        ]);
        let mut reader = Reader::new(&bytes[..]);
        let first = reader.next().unwrap().unwrap();
        assert_eq!(
            (first.name.as_str(), first.size, first.is_file()),
            ("manifest.json", 2, true)
        );
        let second = reader.next().unwrap().unwrap();
        assert_eq!(second.name, long);
        let mut data = String::new();
        reader.data(second.size).read_to_string(&mut data).unwrap();
        assert_eq!(data, "payload");
        assert_eq!(reader.next().unwrap().unwrap().name, "empty");
        assert_eq!(reader.next().unwrap(), None);

        let directory = std::env::temp_dir().join(format!("busbar-ci-tar-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("a.tar");
        std::fs::write(&path, &bytes).unwrap();
        let members = index(&path).unwrap();
        assert_eq!(
            read_member(&path, &members, &long, 1024).unwrap().unwrap(),
            b"payload"
        );
        assert_eq!(read_member(&path, &members, "absent", 1024).unwrap(), None);
        assert!(read_member(&path, &members, &long, 7).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_corrupt_headers() {
        let mut bytes = archive(&[("a", b"1")]);
        bytes[0] = b'b';
        assert!(Reader::new(&bytes[..]).next().is_err());
        let bytes = archive(&[("a", b"12345")]);
        assert!(Reader::new(&bytes[..600]).next().unwrap().is_some());
        let mut truncated = Reader::new(&bytes[..520]);
        truncated.next().unwrap();
        assert!(truncated.next().is_err());
    }
}
