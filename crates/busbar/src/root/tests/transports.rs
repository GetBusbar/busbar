//! Tests for `transports.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

/// THE LISTENER TLS IS RESOLVED ONCE, BY THE PATH THAT SERVES IT.
///
/// The book step is where a root unit is bound to the book it settles onto, and that is all it is
/// for. A unit that opens no book has nothing to bind there — the one that had a book step without
/// one resolved the data and admin listeners' TLS material a second time and journaled the reads,
/// for a transport slot nothing served through. So every root unit with a book step is one that
/// opens the book, and a unit that does not open it has none: a second resolution has nowhere to
/// run.
#[test]
fn only_a_unit_that_opens_the_book_has_a_book_step() {
    for unit in crate::ROOT_UNITS {
        assert!(
            unit.on_book.is_none() || unit.opens_book,
            "a root unit that opens no book carries a book step: nothing it settles is on the book, \
             so what it does there is a second boot-time read the serving path already makes"
        );
    }
}
