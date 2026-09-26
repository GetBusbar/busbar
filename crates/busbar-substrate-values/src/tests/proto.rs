//! Tests for `proto.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

static ROOTED: ProtocolDecl = ProtocolDecl::named("rooted");
static TEST_ONLY: ProtocolDecl = ProtocolDecl::named("test-only");
static ROOT: ProtocolDecl = ProtocolDecl::named("root");

/// `Registry::decl`'s interned-name fast path compares data POINTERS. A pointer alone does not
/// identify a string: a subslice of an interned `&'static str` (e.g. a caller stripping a suffix
/// off an already-resolved name) starts at the SAME address as the string it was sliced from, so
/// comparing pointers without also comparing LENGTHS treats "root" (the first four bytes of
/// "rooted"'s own interned storage) as if it were "rooted" itself. With both "root" and "rooted"
/// declared — "rooted" first, so it is the one the buggy short-circuit hits — resolving the
/// four-byte slice must come back with root's OWN declaration, not rooted's codec/auth/verbs.
#[test]
fn a_prefix_slice_of_an_interned_name_resolves_its_own_declaration() {
    let reg = Registry::new([&ROOTED, &ROOT]);

    // Not a fresh "root" literal: a slice INTO "rooted"'s own interned storage, so it shares
    // rooted's data pointer while being four bytes long instead of six — exactly what a caller
    // gets back from slicing (not reallocating) an already-interned protocol name.
    let prefix: &str = &ROOTED.name[..4];
    assert_eq!(
        prefix, "root",
        "sanity: the slice reads as the string \"root\""
    );
    assert_eq!(
        prefix.as_ptr(),
        ROOTED.name.as_ptr(),
        "sanity: the slice shares rooted's data pointer rather than being a separate allocation"
    );

    let resolved = reg
        .decl(prefix)
        .expect("\"root\" is a declared protocol name and must resolve to SOME declaration");
    assert_eq!(
        resolved.name, "root",
        "a prefix slice of the interned name \"rooted\" resolved to the \"{}\" declaration \
         instead of \"root\"'s own — wrong codec, wrong auth, wrong verbs",
        resolved.name
    );
}

/// The one test in this binary that installs a root: `install_protocols` is once per process.
/// A test-built binary with a real composition root must fold to the same declaration list
/// as the shipped one, with no re-declaration for the boot fold to skip audibly.
#[test]
fn the_test_seam_does_not_redeclare_what_the_root_installed() {
    install_protocols(vec![&ROOTED]);
    register_test_protocol(&ROOTED);
    register_test_protocol(&TEST_ONLY);
    let names: Vec<&str> = test_registered_protocols().iter().map(|d| d.name).collect();
    assert_eq!(
        names,
        ["test-only"],
        "a root-installed name must not enter the test set"
    );
    let folded: Vec<&str> = registry().decls().iter().map(|d| d.name).collect();
    assert_eq!(
        folded,
        ["rooted", "test-only"],
        "installed first, each name once"
    );
}

/// THE USAGE-TAP COUNT, HOST STEP (#83a SD-3, architect ruling R-USAGE): the host services the
/// protocol registration arms count every usage-tap fault a codec reports — through the latch (a
/// codec's own reason) or through the decode reporter (a cell's default tap) — as ONE increment of
/// `busbar_billing_tap_decode_fail_total{protocol,reason}`, and warn once per `(protocol, reason)`.
/// The LLM plane's suite pins which reports each tap path makes; this pins what one report counts.
#[test]
fn an_armed_usage_tap_report_counts_one_increment_under_its_reason() {
    use metrics::{
        Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    type Counts = Arc<Mutex<BTreeMap<String, u64>>>;
    struct Cell(Counts, String);
    impl CounterFn for Cell {
        fn increment(&self, value: u64) {
            *self.0.lock().unwrap().entry(self.1.clone()).or_insert(0) += value;
        }
        fn absolute(&self, value: u64) {
            self.0.lock().unwrap().insert(self.1.clone(), value);
        }
    }
    struct Local(Counts);
    impl Recorder for Local {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            let series = format!("{}{{{}}}", key.name(), labels.join(","));
            Counter::from_arc(Arc::new(Cell(Arc::clone(&self.0), series)))
        }
        fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::noop()
        }
        fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
            Histogram::noop()
        }
    }
    // What registration and `install_protocols` run to arm the host's services.
    arm_host_services();
    let counts = Counts::default();
    let proto = "sd3-armed-tap-protocol";
    let (first, second) = metrics::with_local_recorder(&Local(Arc::clone(&counts)), || {
        let first = busbar_contract::codec::usage_tap_fault_should_warn(proto, "bad_json");
        let second = busbar_contract::codec::usage_tap_fault_should_warn(proto, "bad_json");
        busbar_contract::codec::report_usage_tap_decode_failure(
            proto,
            &busbar_contract::codec::CodecError::Malformed("x".into()),
        );
        (first, second)
    });
    assert!(
        first && !second,
        "the first fault of a (protocol, reason) warns; later ones do not"
    );
    let series = |reason: &str| {
        format!("busbar_billing_tap_decode_fail_total{{protocol={proto},reason={reason}}}")
    };
    let counts = counts.lock().unwrap().clone();
    assert_eq!(counts.get(&series("bad_json")), Some(&2));
    assert_eq!(counts.get(&series("decode")), Some(&1));
}
