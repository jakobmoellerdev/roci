//! Scale-out extension: consistent-hash ring, repo sharding, peer proxy.
#![forbid(unsafe_code)]

/// Extension identifier used when assembling enabled features.
pub const EXTENSION: &str = "cluster";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_is_stable() {
        assert_eq!(EXTENSION, "cluster");
    }
}
