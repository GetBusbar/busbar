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
