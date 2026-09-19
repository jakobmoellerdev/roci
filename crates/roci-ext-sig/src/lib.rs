//! Signature extension: cosign / notation verification.
#![forbid(unsafe_code)]

/// Extension identifier used when assembling enabled features.
pub const EXTENSION: &str = "sig";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_is_stable() {
        assert_eq!(EXTENSION, "sig");
    }
}
