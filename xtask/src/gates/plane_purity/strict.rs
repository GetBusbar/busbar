//! THE STRICT RATCHET — the `--strict` half of `scripts/plane-purity-lint.sh`, decided against
//! `qa/plane-purity-strict.toml`.
//!
//! `--check` only ever looked at PRODUCTION code. A plane's own TEST code can quietly accumulate
//! the same side channels — most visibly a plane crate's tests reaching into `busbar_core::`
//! internals, which pins the plane to core's private shape just as surely as production code would.
//! Strict makes that visible and ratchets it down, using the SAME scanner with its scope FLIPPED.
//!
//! Two refusals come across from the shell, and neither is decoration:
//!
//! * **A ceiling that is not a bare integer is REFUSED, not compared.** TOML is perfectly happy
//!   with `SYMBOL = "5"`, and `[ "$n" -gt '"5"' ]` is not a false comparison — it is a shell ERROR
//!   that an `if` reads as "not over the ceiling". One stray pair of quotes and the row silently
//!   stopped being enforced. Here it is a named FAIL.
//! * **A short ledger is RED.** The decision was two `while read` loops over files written with
//!   `cp … || true`: over an empty file each body ran zero times, no ceiling was compared, and the
//!   verdict printed was "every category and every plane crate's test-reach is within its ceiling".
//!   The measurement here is a returned value rather than a file, so the loops cannot run zero
//!   times by accident — but "Rust cannot have that bug" is not the same claim as "the check is
//!   still there", so the row set is reconciled against the required names and a missing one is a
//!   FAIL with its own selftest case.
//!
//! And one refusal the shell never had: **a ceiling raised in the change under judgement is RED**
//! ([`against_base`]). The ceilings were compared only with the committed file, so a rise and the
//! hit it forgives landed together green. Law 9: a ceiling "refuses every rise from that moment".

use std::collections::BTreeMap;

use crate::ctx::Ctx;
use crate::gates::construction::ceilings;

/// The ceilings file. Owner-tightened data, never rewritten by the gate: lowering a number is a
/// reviewable one-line diff and that is the whole point of it being data.
pub const STRICT_TOML: &str = "qa/plane-purity-strict.toml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ceiling {
    At(u64),
    /// Present but not a bare non-negative integer.
    NotAnInteger(String),
    /// No key for this name at all.
    Absent,
}

/// The shell's `ceiling_of`: a `key = value` line reader, deliberately not a TOML parser (section
/// headers carry no `=`, so they never match). A value that is not a bare integer is carried
/// through AS-IS rather than coerced, so the caller can refuse it BY NAME.
pub fn parse_ceilings(text: &str) -> BTreeMap<String, Ceiling> {
    let mut out: BTreeMap<String, Ceiling> = BTreeMap::new();
    for line in text.lines() {
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let val = val.split('#').next().unwrap_or("").trim();
        // FIRST match wins, exactly as the awk's `print val; exit` does.
        if out.contains_key(key) {
            continue;
        }
        let ceiling = if !val.is_empty() && val.chars().all(|c| c.is_ascii_digit()) {
            match val.parse::<u64>() {
                Ok(n) => Ceiling::At(n),
                Err(_) => Ceiling::NotAnInteger(val.to_string()),
            }
        } else {
            Ceiling::NotAnInteger(val.to_string())
        };
        out.insert(key.to_string(), ceiling);
    }
    out
}

/// Look one up. An ABSENT key is `Absent`, which the caller defaults to zero and says so — the
/// shell printed the same note. An EMPTY value is not absent: it is a malformed ceiling.
pub fn ceiling_of(table: &BTreeMap<String, Ceiling>, name: &str) -> Ceiling {
    table.get(name).cloned().unwrap_or(Ceiling::Absent)
}

/// One decided row: the measured count against its ceiling, and what that means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Measured at or under the ceiling.
    Within { measured: u64, ceiling: u64 },
    /// Measured above it. RED.
    Over { measured: u64, ceiling: u64 },
    /// The ceiling could not be compared, so the row is UNPROVEN — never "under".
    Uncomparable { measured: u64, raw: String },
}

impl Decision {
    pub fn red(&self) -> bool {
        !matches!(self, Decision::Within { .. })
    }

    pub fn detail(&self) -> String {
        match self {
            Decision::Within { measured, ceiling } => format!("{measured} <= {ceiling}"),
            Decision::Over { measured, ceiling } => format!("{measured} > ceiling {ceiling}"),
            Decision::Uncomparable { measured, raw } => format!(
                "{measured} vs ceiling `{raw}`, which is not a bare integer — a comparison that \
                 ERRORS is read as 'not over the ceiling', so the row stops enforcing in silence"
            ),
        }
    }
}

pub fn decide(table: &BTreeMap<String, Ceiling>, name: &str, measured: u64) -> Decision {
    match ceiling_of(table, name) {
        Ceiling::At(c) => {
            if measured > c {
                Decision::Over {
                    measured,
                    ceiling: c,
                }
            } else {
                Decision::Within {
                    measured,
                    ceiling: c,
                }
            }
        }
        // No ceiling means zero, the shell's default — and zero is a real ceiling, so a measured
        // count above it is RED rather than a note nobody acts on.
        Ceiling::Absent => {
            if measured > 0 {
                Decision::Over {
                    measured,
                    ceiling: 0,
                }
            } else {
                Decision::Within {
                    measured,
                    ceiling: 0,
                }
            }
        }
        Ceiling::NotAnInteger(raw) => Decision::Uncomparable { measured, raw },
    }
}

/// One ceiling this change raised over the base's copy of the file. A key the base does not carry
/// was zero there ([`decide`]'s default), so a new non-zero key is a raise from zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raise {
    pub key: String,
    pub now: u64,
    pub was: u64,
}

/// Every key of `now` whose ceiling sits above the same key in `was` (absent or malformed there:
/// zero).
pub fn raised(now: &BTreeMap<String, Ceiling>, was: &BTreeMap<String, Ceiling>) -> Vec<Raise> {
    now.iter()
        .filter_map(|(key, c)| {
            let Ceiling::At(n) = c else {
                return None;
            };
            let m = match was.get(key) {
                Some(Ceiling::At(m)) => *m,
                _ => 0,
            };
            (*n > m).then(|| Raise {
                key: key.clone(),
                now: *n,
                was: m,
            })
        })
        .collect()
}

/// THE CEILINGS AGAINST THEIR BASE: `(the base's short sha, every raise)`. The base is the one
/// `ceiling-census` and kind-isolation's minted rows use ([`ceilings::base_ref`]). A base that
/// carries no ceilings file is the file's own landing, so nothing in it is a raise. A base that
/// cannot be established or read is an `Err`, which every strict row reports RED: a ceiling
/// compared with nothing is not a ceiling that held.
pub fn against_base(cx: &Ctx, now: &str) -> Result<(String, Vec<Raise>), String> {
    let base = ceilings::base_ref(cx).map_err(|e| {
        format!("no base to hold {STRICT_TOML} against, so no ceiling can be shown not to have risen: {e}")
    })?;
    let short = base.short().to_string();
    let was = match cx.git_show(&base.sha, STRICT_TOML) {
        Ok(text) => text,
        Err(e) => {
            let synthetic = cx
                .overlay_command(&format!("git-ref:{}", base.sha))
                .is_some();
            let absent = synthetic
                || (cx
                    .git(&["cat-file", "-e", &format!("{}^{{commit}}", base.sha)])
                    .is_ok()
                    && cx
                        .git(&["cat-file", "-e", &format!("{}:{STRICT_TOML}", base.sha)])
                        .is_err());
            if absent {
                return Ok((short, Vec::new()));
            }
            return Err(format!(
                "the base {short} ({}) could not be read for {STRICT_TOML}: {e}",
                base.how
            ));
        }
    };
    Ok((short, raised(&parse_ceilings(now), &parse_ceilings(&was))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_raise_and_a_new_key_are_raises_and_a_cut_is_not() {
        let was = parse_ceilings("A = 5\nB = 3\n");
        let now = parse_ceilings("A = 6\nB = 2\nC = 1\nD = 0\n");
        let keys: Vec<(String, u64, u64)> = raised(&now, &was)
            .into_iter()
            .map(|r| (r.key, r.now, r.was))
            .collect();
        assert_eq!(keys, vec![("A".to_string(), 6, 5), ("C".to_string(), 1, 0)]);
    }
}
