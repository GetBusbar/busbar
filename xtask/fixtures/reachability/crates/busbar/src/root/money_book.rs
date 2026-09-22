// Declared by root/mod.rs and named by nothing else. The real crate's money_book.rs is exactly
// this shape, and its own doc calls it dormant; vocabulary.rs is the same shape with a doc that
// calls it live. The gate believes neither doc — it believes the graph.
pub struct MoneyBook {
    pub nanos: u64,
}

pub fn build() -> MoneyBook {
    MoneyBook { nanos: 0 }
}
