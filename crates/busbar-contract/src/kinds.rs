//! The shapes the plugin kinds share outside `abi/`: the auth kind's challenge round, the store kind's record shapes and error, an export
//! sink's acknowledgement, and the envelope-field bound.

use crate::bounded::MAX_RECORD_BYTES;
use core::fmt;

/// The opaque state one round of a challenge-response exchange hands to the next.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChallengeState(pub Vec<u8>);

/// A challenge an auth scheme wants delivered to the client.
///
/// The proof of round n arrives carrying the state of round n minus one, which is what lets the
/// scheme stay stateless across rounds. Rounds and bytes are both bounded by configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The bytes to deliver.
    pub bytes: Vec<u8>,
    /// The state the next round's proof will carry back.
    pub state: ChallengeState,
    /// How many rounds remain before the exchange is refused.
    pub rounds_left: u8,
}

// ── store ────────────────────────────────────────────────────────────────────────────────────

/// One fixed-size record's bytes.
///
/// The size ceiling is the design's, and it is a ceiling on the *record*, not on the batch: a
/// journal of fixed-size records is a journal whose replay cost is arithmetic rather than a scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordBytes {
    bytes: Vec<u8>,
}

impl RecordBytes {
    /// Take bytes as a record.
    ///
    /// # Errors
    /// Returns the length back when the bytes exceed the record ceiling.
    pub fn new(bytes: Vec<u8>) -> Result<Self, usize> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(bytes.len());
        }
        Ok(Self { bytes })
    }

    /// The bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// Where one stream of the journal has reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Head {
    /// The stream's sequence number.
    pub seq: u64,
    /// The epoch that sequence belongs to.
    pub epoch: u64,
}

/// Something went wrong under the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The backend could not be reached.
    Unavailable,
    /// The call did not return within its deadline.
    Timeout,
    /// The write lost a fencing race and this node's epoch is stale.
    Fenced,
    /// A gap was detected between what was written and what read back.
    Gap,
    /// The backend rejected the value.
    Rejected(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for StoreError {}

// ── secret ───────────────────────────────────────────────────────────────────────────────────

/// A reference to a secret: `{ module, settings }`, where `settings` is the resolving plugin's own
/// reference grammar. There is ONE `SecretRef` (DECISIONS #83 merge, fold F1): the config reference
/// type defined in [`crate::secret_ref`], re-exported here under the kind ABI's spelling.
pub use crate::secret_ref::SecretRef;

// ── export ───────────────────────────────────────────────────────────────────────────────────

// ── the shapes the loop passes around that no one kind owns ───────────────────────────────────
