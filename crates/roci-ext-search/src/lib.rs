//! Search extension: GraphQL query surface over a maintained index.
#![forbid(unsafe_code)]

/// Extension identifier used when assembling enabled features.
pub const EXTENSION: &str = "search";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_is_stable() {
        assert_eq!(EXTENSION, "search");
    }
}
