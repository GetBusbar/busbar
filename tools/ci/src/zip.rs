//! In-memory ZIP reader for GitLab artifact archives with the observable
//! behaviour of CPython's `zipfile.ZipFile(io.BytesIO(raw))` + `read(info)`:
//! end-record search (comment, ZIP64 locator/record, prepended data), central
//! directory parsing (cp437 or UTF-8 names, NUL truncation, ZIP64 and Unicode
//! path extra fields), local-header checks (magic, name agreement, overlapped
//! entries), stored and DEFLATE members with zipfile's read-loop truncation and
//! EOF rules, and CRC-32 verification. Errors carry zipfile's exception class.
use crate::inflate;

#[derive(Debug, PartialEq)]
pub enum ZipError {
    /// BadZipFile, OSError, EOFError or ValueError (incl. UnicodeDecodeError).
    Bad(String),
    /// NotImplementedError.
    NotImplemented(String),
    /// RuntimeError.
    Runtime(String),
    /// zlib.error.
    Zlib(String),
    /// bzip2 / LZMA / Zstandard: decodable by CPython, never produced by GitLab.
    Unsupported(u16),
}

type Result<T> = std::result::Result<T, ZipError>;

fn bad(message: &str) -> ZipError {
    ZipError::Bad(message.to_owned())
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub filename: String,
    pub orig_filename: String,
    pub flag_bits: u16,
    pub compress_type: u16,
    pub crc: u32,
    pub compress_size: u64,
    pub file_size: u64,
    pub header_offset: i128,
    pub external_attr: u32,
    end_offset: i128,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.filename.ends_with('/')
    }
}

const MAX_N: u64 = (1 << 31) - 1;
const CP437: &str = "\u{c7}\u{fc}\u{e9}\u{e2}\u{e4}\u{e0}\u{e5}\u{e7}\u{ea}\u{eb}\u{e8}\u{ef}\u{ee}\u{ec}\u{c4}\u{c5}\u{c9}\u{e6}\u{c6}\u{f4}\u{f6}\u{f2}\u{fb}\u{f9}\u{ff}\u{d6}\u{dc}\u{a2}\u{a3}\u{a5}\u{20a7}\u{192}\u{e1}\u{ed}\u{f3}\u{fa}\u{f1}\u{d1}\u{aa}\u{ba}\u{bf}\u{2310}\u{ac}\u{bd}\u{bc}\u{a1}\u{ab}\u{bb}\u{2591}\u{2592}\u{2593}\u{2502}\u{2524}\u{2561}\u{2562}\u{2556}\u{2555}\u{2563}\u{2551}\u{2557}\u{255d}\u{255c}\u{255b}\u{2510}\u{2514}\u{2534}\u{252c}\u{251c}\u{2500}\u{253c}\u{255e}\u{255f}\u{255a}\u{2554}\u{2569}\u{2566}\u{2560}\u{2550}\u{256c}\u{2567}\u{2568}\u{2564}\u{2565}\u{2559}\u{2558}\u{2552}\u{2553}\u{256b}\u{256a}\u{2518}\u{250c}\u{2588}\u{2584}\u{258c}\u{2590}\u{2580}\u{3b1}\u{df}\u{393}\u{3c0}\u{3a3}\u{3c3}\u{b5}\u{3c4}\u{3a6}\u{398}\u{3a9}\u{3b4}\u{221e}\u{3c6}\u{3b5}\u{2229}\u{2261}\u{b1}\u{2265}\u{2264}\u{2320}\u{2321}\u{f7}\u{2248}\u{b0}\u{2219}\u{b7}\u{221a}\u{207f}\u{b2}\u{25a0}\u{a0}";

pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0, data)
}

fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        table
    });
    let mut c = !crc;
    for &b in data {
        c = table[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

fn decode_name(raw: &[u8], utf8: bool) -> Result<String> {
    if utf8 {
        return std::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| bad("utf-8 file name"));
    }
    let table: Vec<char> = CP437.chars().collect();
    Ok(raw
        .iter()
        .map(|&b| {
            if b < 0x80 {
                b as char
            } else {
                table[(b - 0x80) as usize]
            }
        })
        .collect())
}

fn sanitize(name: &str) -> String {
    name.split('\0').next().unwrap_or("").to_owned()
}

/// `BytesIO.read(n)` at `pos` (seek past the end reads nothing).
fn read_at(raw: &[u8], pos: i128, n: u64) -> Result<&[u8]> {
    if pos < 0 {
        return Err(bad("negative seek value"));
    }
    let start = (pos as u128).min(raw.len() as u128) as usize;
    let end = (start as u128 + u128::from(n)).min(raw.len() as u128) as usize;
    Ok(&raw[start..end])
}

fn u16_at(d: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([d[i], d[i + 1]])
}
fn u32_at(d: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]])
}
fn u64_at(d: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(d[i..i + 8].try_into().unwrap())
}

struct EndRecord {
    size: u64,
    offset: u64,
    location: i128,
}

fn end_record64(raw: &[u8], location: i128, mut end: EndRecord) -> Result<EndRecord> {
    let mut offset = location - 20;
    if offset < 0 {
        return Ok(end);
    }
    let data = read_at(raw, offset, 20)?;
    if data.len() != 20 {
        return Err(bad("Unknown I/O error"));
    }
    if &data[..4] != b"PK\x06\x07" {
        return Ok(end);
    }
    let (diskno, reloff, disks) = (u32_at(data, 4), u64_at(data, 8), u32_at(data, 16));
    if diskno != 0 || disks > 1 {
        return Err(bad("zipfiles that span multiple disks are not supported"));
    }
    offset -= 56;
    if i128::from(reloff) > offset {
        return Err(bad("Corrupt zip64 end of central directory locator"));
    }
    let mut extrasz = offset - i128::from(reloff);
    let mut data = read_at(raw, i128::from(reloff), 56)?;
    if data.len() != 56 {
        return Err(bad("Unknown I/O error"));
    }
    if !data.starts_with(b"PK\x06\x06") && i128::from(reloff) != offset {
        extrasz = 0;
        data = read_at(raw, offset, 56)?;
        if data.len() != 56 {
            return Err(bad("Unknown I/O error"));
        }
    }
    if !data.starts_with(b"PK\x06\x06") {
        return Err(bad("Zip64 end of central directory record not found"));
    }
    let (sz, dirsize, diroffset) = (u64_at(data, 4), u64_at(data, 40), u64_at(data, 48));
    if u128::from(diroffset) + u128::from(dirsize) != u128::from(reloff)
        || i128::from(sz) + 12 != 56 + extrasz
    {
        return Err(bad("Corrupt zip64 end of central directory record"));
    }
    end.size = dirsize;
    end.offset = diroffset;
    end.location = offset - extrasz;
    Ok(end)
}

fn end_record(raw: &[u8]) -> Result<Option<EndRecord>> {
    let size = raw.len();
    let unpack = |d: &[u8], location: usize| EndRecord {
        size: u64::from(u32_at(d, 12)),
        offset: u64::from(u32_at(d, 16)),
        location: location as i128,
    };
    let tail = &raw[size.saturating_sub(22)..];
    if tail.len() == 22 && &tail[..4] == b"PK\x05\x06" && tail[20..] == [0, 0] {
        let end = unpack(tail, size - 22);
        return end_record64(raw, (size - 22) as i128, end).map(Some);
    }
    let start = size.saturating_sub(65535 + 22);
    let data = &raw[start..];
    let Some(found) = data.windows(4).rposition(|w| w == b"PK\x05\x06") else {
        return Ok(None);
    };
    if data.len() - found < 22 {
        return Ok(None);
    }
    let end = unpack(&data[found..found + 22], start + found);
    end_record64(raw, (start + found) as i128, end).map(Some)
}

fn decode_extra(entry: &mut Entry, extra: &[u8], name_crc: u32) -> Result<()> {
    let mut extra = extra;
    while extra.len() >= 4 {
        let (tp, ln) = (u16_at(extra, 0), usize::from(u16_at(extra, 2)));
        if ln + 4 > extra.len() {
            return Err(ZipError::Bad(format!(
                "Corrupt extra field {tp:04x} (size={ln})"
            )));
        }
        let mut data = &extra[4..ln + 4];
        if tp == 0x0001 {
            let mut take = |field: &str| -> Result<u64> {
                if data.len() < 8 {
                    return Err(ZipError::Bad(format!(
                        "Corrupt zip64 extra field. {field} not found."
                    )));
                }
                let value = u64_at(data, 0);
                data = &data[8..];
                Ok(value)
            };
            if entry.file_size == u64::MAX || entry.file_size == 0xffff_ffff {
                entry.file_size = take("File size")?;
            }
            if entry.compress_size == 0xffff_ffff {
                entry.compress_size = take("Compress size")?;
            }
            if entry.header_offset == 0xffff_ffff {
                entry.header_offset = i128::from(take("Header offset")?);
            }
        } else if tp == 0x7075 {
            if data.len() < 5 {
                return Err(bad("Corrupt unicode path extra field (0x7075)"));
            }
            if data[0] == 1 && u32_at(data, 1) == name_crc {
                let name = std::str::from_utf8(&data[5..]).map_err(|_| {
                    bad("Corrupt unicode path extra field (0x7075): invalid utf-8 bytes")
                })?;
                if !name.is_empty() {
                    entry.filename = sanitize(name);
                }
            }
        }
        extra = &extra[ln + 4..];
    }
    Ok(())
}

/// `ZipFile(BytesIO(raw)).infolist()`.
pub fn entries(raw: &[u8]) -> Result<Vec<Entry>> {
    let end = end_record(raw)?.ok_or_else(|| bad("File is not a zip file"))?;
    let concat = end.location - i128::from(end.size) - i128::from(end.offset);
    let start_dir = i128::from(end.offset) + concat;
    if start_dir < 0 {
        return Err(bad("Bad offset for central directory"));
    }
    let data = read_at(raw, start_dir, end.size)?;
    let mut list: Vec<Entry> = Vec::new();
    let (mut total, mut pos) = (0u64, 0usize);
    let mut read = |n: usize| -> &[u8] {
        let start = pos.min(data.len());
        let stop = (pos + n).min(data.len());
        pos += n;
        &data[start..stop]
    };
    while total < end.size {
        let header = read(46);
        if header.len() != 46 {
            return Err(bad("Truncated central directory"));
        }
        let header = header.to_vec();
        if &header[..4] != b"PK\x01\x02" {
            return Err(bad("Bad magic number for central directory"));
        }
        let (name_len, extra_len, comment_len) = (
            usize::from(u16_at(&header, 28)),
            usize::from(u16_at(&header, 30)),
            usize::from(u16_at(&header, 32)),
        );
        let raw_name = read(name_len).to_vec();
        let name_crc = crc32(&raw_name);
        let flag_bits = u16_at(&header, 8);
        let orig = decode_name(&raw_name, flag_bits & 0x800 != 0)?;
        let extra = read(extra_len).to_vec();
        let _comment = read(comment_len);
        let extract_version = header[6];
        if extract_version > 63 {
            return Err(ZipError::NotImplemented(format!(
                "zip file version {}.{}",
                extract_version / 10,
                extract_version % 10
            )));
        }
        let mut entry = Entry {
            filename: sanitize(&orig),
            orig_filename: orig,
            flag_bits,
            compress_type: u16_at(&header, 10),
            crc: u32_at(&header, 16),
            compress_size: u64::from(u32_at(&header, 20)),
            file_size: u64::from(u32_at(&header, 24)),
            header_offset: i128::from(u32_at(&header, 42)),
            external_attr: u32_at(&header, 38),
            end_offset: 0,
        };
        decode_extra(&mut entry, &extra, name_crc)?;
        entry.header_offset += concat;
        list.push(entry);
        total += 46 + (name_len + extra_len + comment_len) as u64;
    }
    // zipfile: reversed(sorted(filelist, key=header_offset)) assigns end offsets.
    let mut order: Vec<usize> = (0..list.len()).collect();
    order.sort_by_key(|&i| list[i].header_offset);
    let mut end_offset = start_dir;
    for &i in order.iter().rev() {
        list[i].end_offset = end_offset;
        end_offset = list[i].header_offset;
    }
    Ok(list)
}

/// `ZipFile.read(info)`.
pub fn read(raw: &[u8], entry: &Entry) -> Result<Vec<u8>> {
    let header = read_at(raw, entry.header_offset, 30)?;
    if header.len() != 30 {
        return Err(bad("Truncated file header"));
    }
    if &header[..4] != b"PK\x03\x04" {
        return Err(bad("Bad magic number for file header"));
    }
    let local_flags = u16_at(header, 6);
    let (name_len, extra_len) = (u16_at(header, 26), u16_at(header, 28));
    let name = read_at(raw, entry.header_offset + 30, u64::from(name_len))?;
    let mut tell = entry.header_offset + 30 + name.len() as i128;
    if extra_len != 0 {
        tell += i128::from(extra_len);
    }
    if entry.flag_bits & (1 << 5) != 0 {
        return Err(ZipError::NotImplemented(
            "compressed patched data (flag bit 5)".into(),
        ));
    }
    if entry.flag_bits & (1 << 6) != 0 {
        return Err(ZipError::NotImplemented(
            "strong encryption (flag bit 6)".into(),
        ));
    }
    let local_name = decode_name(name, local_flags & 0x800 != 0)?;
    if local_name != entry.orig_filename {
        return Err(bad("File name in directory and header differ."));
    }
    if tell + i128::from(entry.compress_size) > entry.end_offset
        && entry.end_offset != entry.header_offset
    {
        return Err(bad("Overlapped entries (possible zip bomb)"));
    }
    if entry.flag_bits & 1 != 0 {
        return Err(ZipError::Runtime(
            "File is encrypted, password required for extraction".into(),
        ));
    }
    match entry.compress_type {
        0 | 8 => {}
        12 | 14 | 93 => return Err(ZipError::Unsupported(entry.compress_type)),
        _ => {
            return Err(ZipError::NotImplemented(
                "That compression method is not supported".into(),
            ));
        }
    }
    let data = read_at(raw, tell, entry.compress_size)?;
    let got = data.len() as u64;
    let compress_left = entry.compress_size - got;
    if entry.compress_size > 0 && got == 0 {
        return Err(bad("EOFError"));
    }
    let keep = usize::try_from(entry.file_size).unwrap_or(usize::MAX);
    let (out, ended) = if entry.compress_type == 0 {
        (data[..data.len().min(keep)].to_vec(), compress_left == 0)
    } else {
        let rounds = entry.file_size.div_ceil(MAX_N).max(1);
        let inflated = inflate::inflate(data, keep, rounds * MAX_N);
        if let Some(message) = inflated.error {
            return Err(ZipError::Zlib(format!(
                "Error -3 while decompressing data: {message}"
            )));
        }
        (inflated.data, inflated.end || compress_left == 0)
    };
    if (out.len() as u64) < entry.file_size && !ended {
        return Err(bad("EOFError"));
    }
    if crc32(&out) != entry.crc {
        return Err(ZipError::Bad(format!(
            "Bad CRC-32 for file {:?}",
            entry.filename
        )));
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A stored-member archive in Python's `ZipFile.writestr` layout.
    pub fn stored(members: &[(&str, &[u8])]) -> Vec<u8> {
        let (mut out, mut central) = (Vec::new(), Vec::new());
        for (name, data) in members {
            let offset = out.len() as u32;
            let crc = crc32(data);
            let mut local = b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x21\x00".to_vec();
            local.extend(crc.to_le_bytes());
            local.extend((data.len() as u32).to_le_bytes());
            local.extend((data.len() as u32).to_le_bytes());
            local.extend((name.len() as u16).to_le_bytes());
            local.extend(0u16.to_le_bytes());
            local.extend(name.as_bytes());
            out.extend(&local);
            out.extend(*data);
            let mut entry = b"PK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x00\x21\x00".to_vec();
            entry.extend(crc.to_le_bytes());
            entry.extend((data.len() as u32).to_le_bytes());
            entry.extend((data.len() as u32).to_le_bytes());
            entry.extend((name.len() as u16).to_le_bytes());
            entry.extend([0u8; 8]);
            entry.extend((0o100600u32 << 16).to_le_bytes());
            entry.extend(offset.to_le_bytes());
            entry.extend(name.as_bytes());
            central.extend(entry);
        }
        let start = out.len() as u32;
        out.extend(&central);
        out.extend(b"PK\x05\x06\x00\x00\x00\x00");
        out.extend((members.len() as u16).to_le_bytes());
        out.extend((members.len() as u16).to_le_bytes());
        out.extend((central.len() as u32).to_le_bytes());
        out.extend(start.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out
    }

    #[test]
    fn crc_and_stored_round_trip() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let raw = stored(&[("a/b.txt", b"hello"), ("a/", b"")]);
        let list = entries(&raw).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(read(&raw, &list[0]).unwrap(), b"hello");
        assert!(list[1].is_dir());
        // A flipped data byte fails its CRC; a truncated archive is not a zip.
        let mut bad = raw.clone();
        bad[30 + 7] ^= 1;
        assert!(matches!(
            read(&bad, &entries(&bad).unwrap()[0]),
            Err(ZipError::Bad(_))
        ));
        assert!(matches!(
            entries(&raw[..raw.len() - 3]),
            Err(ZipError::Bad(_))
        ));
        assert!(matches!(entries(b""), Err(ZipError::Bad(_))));
    }
}
