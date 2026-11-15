// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's one redactor: per-instance scrub sets and the URL/FAIL-text helpers (IF §12.16). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-H0 fills it.

use core::marker::PhantomData;
use std::borrow::Cow;

/// One instance's scrub set. Lock-free reads (ArcSwap of an aho-corasick automaton). Keyed by **slot**: one
/// entry per bound secret handle (≤ `MAX_BINDINGS` = 1,024 per instance, §12.7) plus the kernel's own slots for
/// that instance (`slot >= 0x1_0000`: upstream client identities, stdio env secrets; ≤ 64), so its size is
/// bounded by config, never by how often secrets rotate (round 18: each slot holds at most two generations, the
/// current values and the ones they replaced, so ≤ 2 × (MAX_BINDINGS + 64) value sets per instance). Round 8 correction: the **pattern map** holds only
/// Zeroizing copies; the **automaton** does not (see the residual below the block).
/// Round 16: `live` holds one immutable snapshot per version, the automaton **and** the flat list of the needles it
/// was built from (the same `Zeroizing` bytes the rebuild already collected for `AhoCorasick::new`, kept instead of
/// dropped), so every reader, the FAIL tail check included, is one `ArcSwap::load` (round 17: = 2 RMWs on the
/// reader's own debt slot, I5's fourth stated exception) and takes no lock. `state` is the writers' lock only.
/// **Round 17, writer-side retirement (I5: no free on a reader thread).** A reader's guard never frees a `Snap`:
/// every `store` goes through `ArcSwap::swap`, and the writer pushes the returned old `Arc<Snap>` onto
/// `ScrubState::retired` before releasing `state`. So after the swap the writer's copy keeps every replaced
/// snapshot alive; a reader whose debt the swap paid (arc-swap `wait_for_readers`) drops its now-owned `Arc` to a
/// count ≥ 1, never 0. Old snapshots are freed (needles zeroed, automaton freed) **only on a writer thread**:
/// at the start of every `register`/`forget` (under `state`, `retired.retain(|s| Arc::strong_count(s) > 1)`) and
/// on `reclaim`, which the loader's watchdog thread calls every scan tick (100 ms, §10.6) for each live slot
/// record with `state.try_lock()` (skips the instance if a writer holds it; never blocks). `Drop for Scrub` (after
/// close, cold) frees the rest. `retired` holds at most the snapshots replaced in the last 100 ms plus those a
/// reader still holds.
#[derive(Default)]
pub struct Scrub {
    // W0-ABI: private fields (live: arc_swap::ArcSwap<Snap>, state: Mutex<ScrubState> (writers only)) and the
    // private `Snap`/`ScrubState` types land with W1-H0 (arc-swap, aho-corasick and zeroize are not wave-0
    // dependencies); so does `Drop for Scrub`.
    _stub: PhantomData<()>,
}
impl Scrub {
    pub fn new() -> Self {
        todo!()
    }
    /// Custody calls this **only on a per-instance custody cache miss** (§12.2 steps 4-5; the cache is keyed by
    /// `(instance, handle)`, round 7, so every instance's first resolve registers here), never on a hit. It hashes the value
    /// (SHA-256 through `busbar-crypto`) and compares with the slot's stored digest: equal => return at once
    /// (no lock held beyond the compare, no allocation, no rebuild). Otherwise it **shifts** the slot (round 18,
    /// I14): the current patterns become the slot's previous generation (the generation they displace is dropped and
    /// zeroized, never appended), and the new value's patterns become current: for **each** of
    /// `values` (round 17: a plain SecretRef passes one value; a template passes the rendered text first, then
    /// every fill value, §12.2 step 5), `scrub::needles(value)` (each ≥ 4 bytes; a value shorter than that is not
    /// matched, and custody audits `secret_too_short_to_scrub`), deduplicated across values; then rebuilds the
    /// automaton once, over every slot's current **and** previous patterns, and swaps it in (the snapshot's `needles`
    /// list is the same union, so `text_tail` covers both). The digest is SHA-256 over the length-prefixed values in order. Rebuilds are
    /// therefore bounded by value changes, not by resolves.
    /// **Round 8, normative (linearizable)**: the digest compare, the map update, the automaton rebuild **from the
    /// whole map** and the `ArcSwap::store` all happen while holding `state`'s Mutex, in that order; the lock is
    /// released only after the store. The digest of the needles is computed before taking the lock (so the
    /// critical section does no hashing), and the equal-digest early return also happens under the lock. Two
    /// concurrent misses of one instance (two chains, or open plus a request) are therefore serialized: the
    /// second rebuild always sees the first's patterns, and no store can overwrite a newer automaton with an
    /// older one. Readers (`text`, `text_tail`, `scrub::fail_text`) never take the lock: one `ArcSwap::load` of
    /// the current `Snap` (round 16: `text_tail` included). `forget` follows the same rule.
    /// C-SCRUB-RACE (§14) pins it. Round 19: custody publishes a resolved value only after this call returns
    /// (§12.2 step 5, register-then-publish); `register` itself adds no lock and no wait for it. C-SCRUB-HIT's
    /// publish-order arm pins the order.
    pub fn register(&self, slot: u32, values: &[&[u8]]) {
        let _ = (slot, values);
        todo!()
    }
    /// Drops a slot's patterns, both generations (unbind, reconfigure removed the handle). Same lock rule as `register`.
    pub fn forget(&self, slot: u32) {
        let _ = slot;
        todo!()
    }
    /// Round 17: frees retired snapshots no reader holds (`strong_count == 1`), if `state` is free
    /// (`try_lock`; returns at once otherwise). Called only by the loader's watchdog thread each scan tick.
    pub fn reclaim(&self) {
        todo!()
    }

    /// Every match -> `***`; then URL userinfo (`scheme://user:pass@` -> `scheme://***@`), credential-named
    /// query parameters (`token, access_token, refresh_token, id_token, key, api_key, apikey, sig, signature,
    /// password, secret, client_secret, code` -> `=***`) and `Authorization:`/`Proxy-Authorization:` values.
    /// Borrowed when nothing matched (no allocation on the common path).
    pub fn text<'t>(&self, text: &'t str) -> Cow<'t, str> {
        let _ = text;
        todo!()
    }
    /// A scrub set from explicit needles, not bound to an instance (config_validate's per-credential redaction).
    pub fn from_needles<'n>(needles: impl IntoIterator<Item = &'n [u8]>) -> Self {
        let _ = needles;
        todo!()
    }
    /// Round 15 (I14, C-SCRUB-CUT): `text` first; then, if the result ends in a run of ≥ `MIN_NEEDLE` bytes that
    /// is a proper prefix of any registered needle (a secret or encoding the plugin's wire cut split), that run
    /// becomes `***`. Over-masks a benign tail that happens to match a needle prefix; never under-masks one.
    /// **Round 16 (I5, speed):** lock-free: both passes read the one `Snap` loaded once (the tail walk goes over
    /// `Snap::needles`, never `state`), so a `register` rebuild never blocks it and it never queues behind one;
    /// and the tail walk (O(total needle bytes)) runs **only when `text.len() ≥ FAIL_TEXT_WIRE_MAX − 3`**, i.e.
    /// when the text can be the shim's char-boundary cut (§4.1, §7.8 `bb_fail`: a cut lands in
    /// `[FAIL_TEXT_WIRE_MAX − 3, FAIL_TEXT_WIRE_MAX]`). Only a cut text can end in a split needle: a plugin passes
    /// upstream text whole and never slices it (§4.1). Every shorter text costs exactly `text`. An auth `verify`
    /// REFUSED on every request of a credential-stuffing flood is therefore one load plus one automaton scan of
    /// its (short) text on the worker, with no lock (B-SYNC's REFUSED arm).
    pub fn text_tail<'t>(&self, text: &'t str) -> Cow<'t, str> {
        let _ = text;
        todo!()
    }
}

// The free functions every core redactor uses (round 6; the one implementation).
// W0-ABI: the IF writes these inside `pub mod scrub { .. }`; this file *is* the `scrub` module, so they sit at
// its top level and are reached as `abi::host::scrub::{needles, mask_url, strip_userinfo, fail_text}`, the
// paths §12.16 names.
// W0-ABI: `pub fn needles(value: &[u8]) -> Vec<zeroize::Zeroizing<Vec<u8>>>` (every pattern one secret value
// is matched as, each ≥ MIN_NEEDLE bytes, longest first, deduplicated) is omitted: its return type needs the
// `zeroize` crate, which is not a wave-0 dependency. It lands with W1-H0.

pub const MIN_NEEDLE: usize = 4;
/// `scheme://user:pass@host` -> `scheme://***@host`; borrowed when there is no userinfo.
pub fn mask_url(url: &str) -> Cow<'_, str> {
    let _ = url;
    todo!()
}
/// `scheme://user:pass@host` -> `scheme://host` (for building a dial URL, not for display).
pub fn strip_userinfo(url: &str) -> Cow<'_, str> {
    let _ = url;
    todo!()
}
/// Round 15: the most plugin FAIL text core shows, logs or audits.
pub const FAIL_TEXT_SHOWN: usize = 512;
/// Round 15 (I14): the one way core turns `Answer::fail` text into shown text, in this order and no other:
/// `scrub.text_tail(text)` (whole needles, URL userinfo, credential parameters, then a trailing partial
/// needle when the text is wire-cut length), then cut to `FAIL_TEXT_SHOWN` bytes at a char boundary. Round 16:
/// lock-free, as `text_tail`. Every adapter (§11.3), the refusal map
/// (§12.15) and the boot-migration report (§12.10) call it; C-SCRUB-CUT pins the order. The general rule it
/// applies, for every plugin text core shortens (FAIL, hook MESSAGE, FACT_TEXT tails): **scrub first, cut
/// after**, never the reverse.
pub fn fail_text<'t>(scrub: &Scrub, text: &'t str) -> Cow<'t, str> {
    let _ = (scrub, text);
    todo!()
}

#[cfg(test)]
mod tests {
    //! The H0 arms of C-SCRUB, C-SCRUB-HIT, C-SCRUB-RACE, C-SCRUB-ONE and C-SCRUB-CUT (IF §12.16, §14), over
    //! the scrub set alone. The encodings are literals, so a wrong encoder cannot agree with itself.

    use super::*;
    use crate::fail::FAIL_TEXT_WIRE_MAX;
    use std::sync::{Arc, Barrier};

    const SECRET: &str = "s3cr3t-T0ken!42?";
    /// SECRET's standard base64 (padded, unpadded), percent (NON_ALPHANUMERIC) and lowercase hex forms.
    const ENCODED: [&str; 4] = [
        "czNjcjN0LVQwa2VuITQyPw==",
        "czNjcjN0LVQwa2VuITQyPw",
        "s3cr3t%2DT0ken%2142%3F",
        "7333637233742d54306b656e2134323f",
    ];
    /// A value whose base64 holds a `+`: standard `UGE1NXcwcmR+eA==`, URL-safe `UGE1NXcwcmR-eA`.
    const PLUS: &str = "Pa55w0rd~x";

    /// Whether any run of `MIN_NEEDLE` bytes of `secret` survives in `out`.
    fn leaks(out: &str, secret: &str) -> bool {
        secret
            .as_bytes()
            .windows(MIN_NEEDLE)
            .any(|w| out.as_bytes().windows(MIN_NEEDLE).any(|o| o == w))
    }

    #[test]
    fn c_scrub_masks_a_value_and_every_encoding() {
        let s = Scrub::new();
        s.register(1, &[SECRET.as_bytes()]);
        let mut text = format!("raw {SECRET} trimmed-free");
        for form in ENCODED {
            text.push_str(" | ");
            text.push_str(form);
        }
        let out = s.text(&text);
        assert!(!leaks(&out, SECRET), "{out}");
        for form in ENCODED {
            assert!(!out.contains(form), "{form} survived: {out}");
        }
        assert_eq!(out.matches("***").count(), 5, "{out}");

        let p = Scrub::new();
        p.register(7, &[PLUS.as_bytes()]);
        let out = p.text("std UGE1NXcwcmR+eA== url UGE1NXcwcmR-eA== bare UGE1NXcwcmR-eA end");
        assert_eq!(out, "std *** url *** bare *** end");
    }

    #[test]
    fn c_scrub_masks_the_secret_after_a_colon_and_a_trimmed_value() {
        let s = Scrub::new();
        s.register(3, &[b"  alice:Pa55w0rd~x\n"]);
        let out = s.text("login alice:Pa55w0rd~x then Pa55w0rd~x alone");
        assert!(!out.contains("Pa55w0rd~x"), "{out}");
        assert!(!leaks(&out, PLUS), "{out}");
    }

    #[test]
    fn c_scrub_masks_url_userinfo_credential_params_and_authorization() {
        let s = Scrub::new();
        let out = s.text(
            "GET https://alice:pw@example.com/x?token=abc&b=1&API_KEY=k1;sig=zz#f code=9 \
             Authorization: Bearer xyz\nProxy-Authorization: Basic qqq\r\nnext",
        );
        assert_eq!(
            out,
            "GET https://***@example.com/x?token=***&b=1&API_KEY=***;sig=***#f code=9 \
             Authorization: ***\nProxy-Authorization: ***\r\nnext"
        );
    }

    #[test]
    fn c_scrub_nothing_matched_borrows() {
        let s = Scrub::new();
        s.register(1, &[SECRET.as_bytes()]);
        assert!(matches!(
            s.text("a plain line with https://example.com/?b=1"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(s.text_tail("short"), Cow::Borrowed(_)));
        assert!(matches!(
            mask_url("https://example.com/a@b"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            strip_userinfo("https://example.com"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn c_scrub_short_values_are_not_needles() {
        let s = Scrub::new();
        s.register(1, &[b"abc"]);
        assert_eq!(s.text("abc abcd"), "abc abcd");
    }

    #[test]
    fn c_scrub_template_registers_every_value() {
        let s = Scrub::new();
        s.register(9, &[b"Bearer abcdef12", b"abcdef12"]);
        let out = s.text("token abcdef12 rejected; base64 YWJjZGVmMTI=; Bearer abcdef12");
        assert_eq!(out, "token *** rejected; base64 ***; ***");
    }

    #[test]
    fn c_scrub_hit_rotation_keeps_two_generations() {
        let s = Scrub::new();
        s.register(1, &[b"value-one-1"]);
        s.register(1, &[b"value-one-1"]);
        s.register(1, &[b"value-two-2"]);
        let both = "v1 value-one-1 v2 value-two-2";
        assert_eq!(s.text(both), "v1 *** v2 ***");
        s.register(1, &[b"value-three-3"]);
        assert_eq!(
            s.text("v1 value-one-1 v2 value-two-2 v3 value-three-3"),
            "v1 value-one-1 v2 *** v3 ***"
        );
    }

    #[test]
    fn c_scrub_forget_drops_both_generations() {
        let s = Scrub::new();
        s.register(1, &[b"first-value"]);
        s.register(1, &[b"second-value"]);
        s.register(2, &[b"other-slot"]);
        s.forget(1);
        assert_eq!(
            s.text("first-value second-value other-slot"),
            "first-value second-value ***"
        );
        s.reclaim();
    }

    #[test]
    fn c_scrub_race_both_slots_masked_after_every_round() {
        const ROUNDS: usize = 2_000;
        let s = Arc::new(Scrub::new());
        let barrier = Arc::new(Barrier::new(2));
        let run = |slot: u32| {
            let (s, barrier) = (Arc::clone(&s), Arc::clone(&barrier));
            std::thread::spawn(move || {
                // Misses are counted, not asserted here: a panic on one side would park the other at the barrier.
                let mut misses = 0_usize;
                let last = format!("slot1-round{:05} slot2-round{:05}", ROUNDS - 1, ROUNDS - 1);
                for round in 0..ROUNDS {
                    let mine = format!("slot{slot}-round{round:05}");
                    s.register(slot, &[mine.as_bytes()]);
                    barrier.wait();
                    let other = format!("slot{}-round{round:05}", 3 - slot);
                    let text = format!("{mine} and {other}");
                    misses += usize::from(s.text(&text) != "*** and ***");
                    barrier.wait();
                }
                // The forget race: both slots dropped at once leave nothing masked.
                s.forget(slot);
                barrier.wait();
                misses += usize::from(s.text(&last) != last);
                misses
            })
        };
        let (a, b) = (run(1), run(2));
        assert_eq!(a.join().expect("slot 1 thread"), 0);
        assert_eq!(b.join().expect("slot 2 thread"), 0);
    }

    #[test]
    fn c_scrub_one_url_helpers() {
        assert_eq!(mask_url("https://u:p@h:1/x?y"), "https://***@h:1/x?y");
        assert_eq!(mask_url("https://tok@h"), "https://***@h");
        assert_eq!(mask_url("https://u:p@w@h/a@b"), "https://***@h/a@b");
        assert_eq!(mask_url("postgres://u:p@h\\x@y"), "postgres://***@h\\x@y");
        assert_eq!(strip_userinfo("https://u:p@h:1/x"), "https://h:1/x");
        assert_eq!(strip_userinfo("https://u@w@h/a@b"), "https://h/a@b");
        assert_eq!(strip_userinfo("no scheme u:p@h"), "no scheme u:p@h");
        let s = Scrub::new();
        assert_eq!(
            s.text("dial https://u:p@h:1/x now"),
            "dial https://***@h:1/x now"
        );
    }

    #[test]
    fn c_scrub_from_needles_masks_what_it_is_given() {
        let s = Scrub::from_needles([b"hunter22".as_slice(), b"abc".as_slice()]);
        assert_eq!(s.text("pw hunter22 abc"), "pw *** abc");
    }

    #[test]
    fn c_scrub_cut_scrub_first_then_cut() {
        let secret = "S3CRETVALUE-0123456789-abcdefghijklmnopq";
        assert_eq!(secret.len(), 40);
        let s = Scrub::new();
        s.register(4, &[secret.as_bytes()]);

        // A secret at bytes 500..540: scrubbed whole, then the cut.
        let text = format!("{}{secret}{}", "a".repeat(500), "b".repeat(60));
        let shown = fail_text(&s, &text);
        assert!(shown.len() <= FAIL_TEXT_SHOWN, "{}", shown.len());
        assert!(!leaks(&shown, secret), "{shown}");

        // A secret starting at byte 3,060 and cut by the wire bound at 3,072: the partial tail is masked.
        let cut = format!(
            "{}{}",
            "c".repeat(3_060),
            &secret[..FAIL_TEXT_WIRE_MAX - 3_060]
        );
        assert_eq!(cut.len(), FAIL_TEXT_WIRE_MAX);
        let tail = s.text_tail(&cut);
        assert!(tail.ends_with("***"), "{}", &tail[tail.len() - 20..]);
        assert!(!leaks(&tail, secret));

        // A text shorter than the cut length never pays the tail walk: an ending that is a needle prefix stays.
        assert_eq!(s.text_tail("ends S3CRETVAL"), "ends S3CRETVAL");

        // A benign 600-byte text is shown cut to 512 bytes, at a char boundary.
        let benign = "z".repeat(600);
        assert_eq!(fail_text(&s, &benign), benign[..FAIL_TEXT_SHOWN]);
        let wide = format!("{}é{}", "y".repeat(511), "y".repeat(50));
        let shown = fail_text(&s, &wide);
        assert_eq!(shown.len(), 511);
    }
}
