// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The loader's one refusal type (IF §4.3) and its one line (r10 §4.1).
//!
//! W1-L1: the frozen `Refusal` carries no version, file or publisher, so the line is r10 §4.1's with those three
//! left to the caller that knows them (boot, `--validate` and the admin API print the file beside it), and the
//! log level (`[error]`) is the logger's. Every text in a refusal has passed its field's rule before it is
//! stored: stamp strings are checked by `scan` (step 3) before any refusal names them, manifest strings by
//! `valid_name`/the version rule, and a dynamic loader's reason by `stage::loader_reason`.

use busbar_plugin_abi::versions::ENGINE;

/// One refusal, printed as r10 §4.1, audited as `plugin.compat` rejected (r10 §4.3), diagnostic BUSBAR-6013
/// unless the code says otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: RefusalCode,
    /// The field or check that failed ("kind_abi", "layout", "crypto", "manifest.version", ...).
    pub field: &'static str,
    /// The verified stamp name once decoded, else the manifest name if it passes valid_name, else None.
    pub plugin: Option<Box<str>>,
    pub have: String,
    pub want: String,
    /// https://getbusbar.com/plugins/n/<name>?engine=<x.y.z>&target=<target>, when a name is known.
    pub link: Option<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    Integrity,
    Signature,
    StampMissing,
    StampAmbiguous,
    StampMalformed {
        byte: u32,
        rule: &'static str,
    },
    KindUnknown,
    KindAbi,
    Mechanism,
    Layout,
    Semantic,
    Target,
    EngineRange,
    Crypto,
    ManifestMismatch,
    DoorStampMismatch,
    ImageBounds,
    DescribeInvalid,
    CapUnknown,
    OutOfProcessUnavailable,
    LocalBuild,
    Superseded,
    /// Round 9: a `former_names` word equals another admitted plugin's identity or word (`Registry::add`;
    /// field "former_names", have = the word, want = a word no other admitted plugin answers to).
    NameConflict,
    // Round 28: the publisher-check variant and its 10 codes are deleted (AGREED 118): admit has no such check,
    // and a plugin that refuses on its own terms does so inside its own `open` (§16.183).
}

/// The download page base (PLUGIN-DISTRIBUTION §2.5): `<base>/<name>?engine=<x.y.z>&target=<target>`.
pub const LINK_BASE: &str = "https://getbusbar.com/plugins/n";

impl Refusal {
    // "BUSBAR-6013" for every code (round 28)
    pub fn diagnostic(&self) -> &'static str {
        "BUSBAR-6013"
    }

    /// A refusal naming no plugin yet; [`Refusal::named`] adds the name and its link.
    pub fn new(
        code: RefusalCode,
        field: &'static str,
        have: impl Into<String>,
        want: impl Into<String>,
    ) -> Self {
        Refusal {
            code,
            field,
            plugin: None,
            have: have.into(),
            want: want.into(),
            link: None,
        }
    }

    /// This refusal naming `name` (a verified stamp name, or a manifest name that passed `valid_name`), with the
    /// download link for this busbar's engine and target. A name that fails `valid_name` is not printed.
    #[must_use]
    pub fn named(mut self, name: &str) -> Self {
        if crate::sign::valid_name(name) && name.len() <= 64 {
            self.link = Some(link(name).into_boxed_str());
            self.plugin = Some(Box::from(name));
        }
        self
    }
}

/// The download link for `name` on this busbar's engine and target.
fn link(name: &str) -> String {
    let target = busbar_plugin_abi::stamp::target_now();
    let end = target.iter().position(|&b| b == 0).unwrap_or(target.len());
    format!(
        "{LINK_BASE}/{name}?engine={}.{}.{}&target={}",
        ENGINE.major,
        ENGINE.minor,
        ENGINE.patch,
        String::from_utf8_lossy(&target[..end])
    )
}

/// The codes a rebuild against this busbar's SDK (or a download for it) cures.
fn rebuild_cures(code: RefusalCode) -> bool {
    matches!(
        code,
        RefusalCode::StampMissing
            | RefusalCode::StampAmbiguous
            | RefusalCode::StampMalformed { .. }
            | RefusalCode::KindUnknown
            | RefusalCode::KindAbi
            | RefusalCode::Mechanism
            | RefusalCode::Layout
            | RefusalCode::Semantic
            | RefusalCode::Target
            | RefusalCode::EngineRange
            | RefusalCode::Crypto
            | RefusalCode::DoorStampMismatch
            | RefusalCode::ImageBounds
            | RefusalCode::LocalBuild
    )
}

impl core::fmt::Display for Refusal {
    // the r10 §4.1 line, byte for byte
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (have, want, field) = (&self.have, &self.want, self.field);
        write!(f, "{} plugin refused: ", self.diagnostic())?;
        match &self.plugin {
            Some(name) => write!(f, "'{name}' ")?,
            None => f.write_str("the image ")?,
        }
        match self.code {
            RefusalCode::Integrity => {
                write!(f, "failed its integrity check ({field}: {have}; expected {want})")
            }
            RefusalCode::Signature => write!(f, "is not trusted: {have}"),
            RefusalCode::StampMissing => f.write_str(
                "carries no busbar compatibility stamp — a 1.5.x plugin or a library not built with the busbar SDK",
            ),
            RefusalCode::StampAmbiguous => write!(
                f,
                "carries {have} stamps; exactly one is required (universal binaries are not supported)"
            ),
            RefusalCode::StampMalformed { byte, rule } => {
                write!(f, "carries a malformed stamp (byte {byte}: {rule})")
            }
            RefusalCode::KindUnknown => {
                write!(f, "names plugin kind {have}; this busbar knows {want}")
            }
            RefusalCode::KindAbi => write!(
                f,
                "is built for {have}; this busbar {}.{}.{} requires {want} exactly",
                ENGINE.major, ENGINE.minor, ENGINE.patch
            ),
            RefusalCode::Mechanism => write!(
                f,
                "is built for plugin mechanism {have}; this busbar requires {want} exactly"
            ),
            RefusalCode::Layout | RefusalCode::Semantic => write!(
                f,
                "is built against a different ABI ({field} {have}, expected {want}) at the same version — a mismatched SDK build"
            ),
            RefusalCode::Target => write!(f, "is built for {have}; this busbar runs on {want}"),
            RefusalCode::EngineRange => {
                write!(f, "declares busbar {have}; this busbar is {want}")
            }
            RefusalCode::Crypto if have == "external" => write!(
                f,
                "is a non-Rust plugin (crypto: external), which this crypto backend ({want}) does not load"
            ),
            RefusalCode::Crypto => write!(
                f,
                "was built against crypto backend {have}; this busbar uses {want}"
            ),
            RefusalCode::ManifestMismatch => {
                let field = field.strip_prefix("manifest.").unwrap_or(field);
                if have.is_empty() {
                    write!(
                        f,
                        "its signed manifest's {field} does not match its binary ({want})"
                    )
                } else {
                    write!(
                        f,
                        "its signed manifest states {field} {have}; its binary states {want}"
                    )
                }
            }
            RefusalCode::DoorStampMismatch => write!(
                f,
                "its door does not present the stamp it was admitted with ({field}: {have})"
            ),
            RefusalCode::ImageBounds => write!(
                f,
                "presents a header part outside its own image ({field})"
            ),
            RefusalCode::DescribeInvalid => {
                write!(f, "answered an invalid describe ({field}: {have})")
            }
            RefusalCode::CapUnknown => write!(f, "declares an unknown {field} {have}"),
            RefusalCode::OutOfProcessUnavailable => f.write_str(
                "runs only out of process, and this busbar has no out-of-process plugin host",
            ),
            RefusalCode::LocalBuild => {
                f.write_str("is a first-party release artifact without a CI build id")
            }
            RefusalCode::Superseded => write!(f, "is an older build superseded by {have}"),
            RefusalCode::NameConflict => write!(
                f,
                "answers to the former name {have}, which another admitted plugin already answers to"
            ),
        }?;
        if rebuild_cures(self.code) {
            write!(
                f,
                ". Rebuild it against the busbar {}.{} SDK",
                ENGINE.major, ENGINE.minor
            )?;
            if let Some(link) = &self.link {
                write!(f, ", or download a build for this busbar: {link}")?;
            }
        }
        Ok(())
    }
}
