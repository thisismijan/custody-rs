pub fn answer() -> u32 {
    42
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliberately_failing_test() {
        assert_eq!(answer(), 43);
    }
}
