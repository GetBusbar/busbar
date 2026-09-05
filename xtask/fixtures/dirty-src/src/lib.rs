//! Fixture: a pure crate whose own production code reaches a banned std path directly.
pub fn read_it(path: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(path)
}

#[cfg(test)]
mod tests {
    // This is test code and must NOT be reported by the own-src scan.
    #[test]
    fn reads_an_env_var() {
        let _ = std::env::var("XTASK_FIXTURE_TEST_ONLY");
    }
}
