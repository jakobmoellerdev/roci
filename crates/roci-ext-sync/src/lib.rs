//! Registry-mirroring / sync extension.
#![forbid(unsafe_code)]

/// Extension identifier used when assembling enabled features.
pub const EXTENSION: &str = "sync";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_is_stable() {
        assert_eq!(EXTENSION, "sync");
    }
}
