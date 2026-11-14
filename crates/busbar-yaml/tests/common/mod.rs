//! `indoc!` for the inherited serde_yaml_ng tests, without the `indoc` crate: the same unindent
//! rules (indoc 2's `unindent`), applied at run time.

pub fn unindent(s: &str) -> &'static str {
    let bytes = s.as_bytes();
    let ignore_first_line = bytes.starts_with(b"\n") || bytes.starts_with(b"\r\n");
    let lines = || {
        let b = if bytes.starts_with(b"\r\n") {
            &bytes[1..]
        } else {
            bytes
        };
        b.split(|c| *c == b'\n')
    };
    let spaces = lines()
        .skip(1)
        .filter_map(|line| line.iter().position(|c| *c != b' ' && *c != b'\t'))
        .min()
        .unwrap_or(0);
    let mut result = Vec::with_capacity(bytes.len());
    for (i, line) in lines().enumerate() {
        if i > 1 || (i == 1 && !ignore_first_line) {
            result.push(b'\n');
        }
        if i == 0 {
            result.extend_from_slice(line);
        } else if line.len() > spaces {
            result.extend_from_slice(&line[spaces..]);
        }
    }
    Box::leak(
        String::from_utf8(result)
            .expect("unindenting keeps UTF-8")
            .into_boxed_str(),
    )
}

macro_rules! indoc {
    ($s:expr) => {
        $crate::common::unindent($s)
    };
}
