//! Std-only raw DEFLATE (RFC 1951) decoder with the observable behaviour of
//! CPython's `zlib.decompressobj(-15).decompress(data, max_length)` as used by
//! `zipfile` on GitLab artifact archives:
//!
//! * malformed data fails with zlib's own `Error -3 while decompressing data:
//!   <msg>` text, detected in zlib's order (inflate.c / inftrees.c rules for
//!   over-subscribed and incomplete codes, repeat codes, missing end-of-block,
//!   reserved fixed symbols and too-far-back distances);
//! * truncated input is not an error: everything decodable so far is returned;
//! * decoding stops once `stop` bytes were produced (zlib's `max_length`), and
//!   only the first `keep` bytes are retained; a 32 KiB window serves the rest.

pub struct Inflated {
    pub data: Vec<u8>,
    /// The final block ended (zlib's `eof`).
    pub end: bool,
    /// zlib error message (without the `Error -3 ...` prefix).
    pub error: Option<&'static str>,
}

const WINDOW: usize = 1 << 15;
const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Input ran out (not an error for zlib) or a data error with zlib's message.
enum Stop {
    Truncated,
    Full,
    Data(&'static str),
}

struct Bits<'a> {
    input: &'a [u8],
    pos: usize,
    bit: u64,
    count: u32,
}

impl Bits<'_> {
    fn need(&mut self, n: u32) -> Result<(), Stop> {
        while self.count < n {
            let byte = *self.input.get(self.pos).ok_or(Stop::Truncated)?;
            self.pos += 1;
            self.bit |= u64::from(byte) << self.count;
            self.count += 8;
        }
        Ok(())
    }

    fn peek(&mut self, n: u32) -> Result<u32, Stop> {
        self.need(n)?;
        Ok((self.bit & ((1u64 << n) - 1)) as u32)
    }

    fn drop_bits(&mut self, n: u32) {
        self.bit >>= n;
        self.count -= n;
    }

    fn take(&mut self, n: u32) -> Result<u32, Stop> {
        let value = self.peek(n)?;
        self.drop_bits(n);
        Ok(value)
    }
}

/// A canonical Huffman code as zlib's inflate_table accepts it.
struct Code {
    /// count[len] for len 1..=15.
    count: [u16; 16],
    /// Symbols ordered by (length, value).
    symbols: Vec<u16>,
    max: u32,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Codes,
    Lens,
    Dists,
}

impl Code {
    /// `None` where inflate_table returns -1 (over-subscribed, or an
    /// incomplete set other than a single one-bit code for lens/dists).
    fn build(lengths: &[u8], kind: Kind) -> Option<Code> {
        let mut count = [0u16; 16];
        for &len in lengths {
            count[len as usize] += 1;
        }
        let max = (1..16).rev().find(|&l| count[l] != 0).unwrap_or(0) as u32;
        let mut symbols = Vec::new();
        if max == 0 {
            return Some(Code {
                count,
                symbols,
                max,
            });
        }
        let mut left: i32 = 1;
        for &n in &count[1..] {
            left <<= 1;
            left -= i32::from(n);
            if left < 0 {
                return None;
            }
        }
        if left > 0 && (kind == Kind::Codes || max != 1) {
            return None;
        }
        for len in 1..16u8 {
            for (symbol, &l) in lengths.iter().enumerate() {
                if l == len {
                    symbols.push(symbol as u16);
                }
            }
        }
        Some(Code {
            count,
            symbols,
            max,
        })
    }

    /// Decode one symbol; `None` for an invalid (unassigned) code.
    fn decode(&self, bits: &mut Bits) -> Result<Option<u16>, Stop> {
        if self.max == 0 {
            // zlib's empty table: one-bit invalid entries with value 0.
            bits.need(1)?;
            bits.drop_bits(1);
            return Ok(None);
        }
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=self.max {
            bits.need(len)?;
            code |= ((bits.bit >> (len - 1)) & 1) as i32;
            let count = i32::from(self.count[len as usize]);
            if code - first < count {
                bits.drop_bits(len);
                return Ok(Some(self.symbols[(index + code - first) as usize]));
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        // Only the single incomplete one-bit code reaches here.
        bits.need(self.max)?;
        bits.drop_bits(self.max);
        Ok(None)
    }
}

struct Out {
    data: Vec<u8>,
    keep: usize,
    stop: u64,
    total: u64,
    window: Vec<u8>,
}

impl Out {
    fn push(&mut self, byte: u8) -> Result<(), Stop> {
        if self.total >= self.stop {
            return Err(Stop::Full);
        }
        if self.data.len() < self.keep {
            self.data.push(byte);
        }
        let at = (self.total as usize) & (WINDOW - 1);
        self.window[at] = byte;
        self.total += 1;
        Ok(())
    }

    fn copy(&mut self, distance: usize, length: usize) -> Result<(), Stop> {
        if distance as u64 > self.total {
            return Err(Stop::Data("invalid distance too far back"));
        }
        for _ in 0..length {
            let at = (self.total as usize).wrapping_sub(distance) & (WINDOW - 1);
            let byte = self.window[at];
            self.push(byte)?;
        }
        Ok(())
    }
}

fn fixed() -> (Code, Code) {
    let mut lengths = [0u8; 288];
    for (i, l) in lengths.iter_mut().enumerate() {
        *l = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let lens = Code::build(&lengths, Kind::Lens).expect("fixed literal code");
    let dists = Code::build(&[5u8; 32], Kind::Dists).expect("fixed distance code");
    (lens, dists)
}

fn codes(bits: &mut Bits, lens: &Code, dists: &Code, out: &mut Out) -> Result<(), Stop> {
    loop {
        let symbol = lens
            .decode(bits)?
            .ok_or(Stop::Data("invalid literal/length code"))?;
        match symbol {
            0..=255 => out.push(symbol as u8)?,
            256 => return Ok(()),
            257..=285 => {
                let i = usize::from(symbol - 257);
                let length = usize::from(LBASE[i]) + bits.take(u32::from(LEXT[i]))? as usize;
                let d = dists
                    .decode(bits)?
                    .filter(|d| *d < 30)
                    .ok_or(Stop::Data("invalid distance code"))?;
                let d = usize::from(d);
                let distance = usize::from(DBASE[d]) + bits.take(u32::from(DEXT[d]))? as usize;
                out.copy(distance, length)?;
            }
            _ => return Err(Stop::Data("invalid literal/length code")),
        }
    }
}

fn dynamic(bits: &mut Bits) -> Result<(Code, Code), Stop> {
    let nlen = bits.take(5)? as usize + 257;
    let ndist = bits.take(5)? as usize + 1;
    let ncode = bits.take(4)? as usize + 4;
    if nlen > 286 || ndist > 30 {
        return Err(Stop::Data("too many length or distance symbols"));
    }
    let mut lengths = [0u8; 19];
    for &slot in &ORDER[..ncode] {
        lengths[slot] = bits.take(3)? as u8;
    }
    let code = Code::build(&lengths, Kind::Codes).ok_or(Stop::Data("invalid code lengths set"))?;
    let mut lens = vec![0u8; nlen + ndist];
    let mut have = 0;
    while have < nlen + ndist {
        let symbol = code.decode(bits)?.unwrap_or(0);
        if symbol < 16 {
            lens[have] = symbol as u8;
            have += 1;
            continue;
        }
        let (value, copy) = match symbol {
            16 => {
                bits.need(2)?;
                if have == 0 {
                    return Err(Stop::Data("invalid bit length repeat"));
                }
                (lens[have - 1], 3 + bits.take(2)? as usize)
            }
            17 => (0, 3 + bits.take(3)? as usize),
            _ => (0, 11 + bits.take(7)? as usize),
        };
        if have + copy > nlen + ndist {
            return Err(Stop::Data("invalid bit length repeat"));
        }
        lens[have..have + copy].fill(value);
        have += copy;
    }
    if lens[256] == 0 {
        return Err(Stop::Data("invalid code -- missing end-of-block"));
    }
    let literal =
        Code::build(&lens[..nlen], Kind::Lens).ok_or(Stop::Data("invalid literal/lengths set"))?;
    let distance =
        Code::build(&lens[nlen..], Kind::Dists).ok_or(Stop::Data("invalid distances set"))?;
    Ok((literal, distance))
}

fn blocks(bits: &mut Bits, out: &mut Out) -> Result<(), Stop> {
    loop {
        let last = bits.take(1)? == 1;
        match bits.take(2)? {
            0 => {
                let skip = bits.count % 8;
                bits.drop_bits(skip);
                let length = bits.take(16)?;
                let check = bits.take(16)?;
                if length != !check & 0xffff {
                    return Err(Stop::Data("invalid stored block lengths"));
                }
                // The bit buffer is byte-aligned and empty here (32 bits read).
                for _ in 0..length {
                    let byte = bits.take(8)? as u8;
                    out.push(byte)?;
                }
            }
            1 => {
                let (lens, dists) = fixed();
                codes(bits, &lens, &dists, out)?;
            }
            2 => {
                let (lens, dists) = dynamic(bits)?;
                codes(bits, &lens, &dists, out)?;
            }
            _ => return Err(Stop::Data("invalid block type")),
        }
        if last {
            return Ok(());
        }
    }
}

/// Inflate raw DEFLATE `input`, producing at most `stop` bytes and keeping
/// the first `keep` of them.
pub fn inflate(input: &[u8], keep: usize, stop: u64) -> Inflated {
    let mut bits = Bits {
        input,
        pos: 0,
        bit: 0,
        count: 0,
    };
    let mut out = Out {
        data: Vec::new(),
        keep,
        stop,
        total: 0,
        window: vec![0; WINDOW],
    };
    let result = blocks(&mut bits, &mut out);
    let (end, error) = match result {
        Ok(()) => (true, None),
        Err(Stop::Truncated) | Err(Stop::Full) => (false, None),
        Err(Stop::Data(message)) => (false, Some(message)),
    };
    Inflated {
        data: out.data,
        end,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(input: &[u8]) -> Inflated {
        inflate(input, usize::MAX, u64::MAX)
    }

    #[test]
    fn stored_fixed_and_dynamic_blocks_decode() {
        // Stored "hello" (final).
        let stored = [0x01, 0x05, 0x00, 0xfa, 0xff, b'h', b'e', b'l', b'l', b'o'];
        let out = all(&stored);
        assert_eq!(
            (out.data.as_slice(), out.end, out.error),
            (&b"hello"[..], true, None)
        );
        // Fixed Huffman "a" from zlib.compress(b'a')[2:-4] (raw).
        let out = all(&[0x4b, 0x04, 0x00]);
        assert_eq!((out.data.as_slice(), out.end), (&b"a"[..], true));
        // Fixed with a back reference: b'abcabcabcabc'.
        let out = all(&[0x4b, 0x4c, 0x4a, 0x4e, 0x84, 0x21, 0x00]);
        assert_eq!(out.data, b"abcabcabcabc");
    }

    #[test]
    fn errors_use_zlib_messages_and_truncation_is_partial() {
        assert_eq!(all(&[0x07]).error, Some("invalid block type"));
        assert_eq!(
            all(&[0x01, 0x00, 0x00, 0x00, 0x00]).error,
            Some("invalid stored block lengths")
        );
        let truncated = all(&[0x01, 0x05, 0x00, 0xfa, 0xff, b'h', b'e']);
        assert_eq!(
            (truncated.data.as_slice(), truncated.end, truncated.error),
            (&b"he"[..], false, None)
        );
        // keep/stop bounds.
        let bounded = inflate(
            &[0x01, 0x05, 0x00, 0xfa, 0xff, b'h', b'e', b'l', b'l', b'o'],
            2,
            4,
        );
        assert_eq!((bounded.data.as_slice(), bounded.end), (&b"he"[..], false));
    }
}
