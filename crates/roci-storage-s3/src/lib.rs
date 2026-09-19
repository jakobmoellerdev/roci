//! Remote object-storage backend for roci (S3-compatible).
//!
//! Feature-gated behind `roci-cli`'s `s3` feature. This is the backend seam;
//! the concrete client is wired in a later phase.
#![forbid(unsafe_code)]

/// Marker for the S3 backend module, kept minimal until the client lands.
pub const BACKEND: &str = "s3";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_is_stable() {
        assert_eq!(BACKEND, "s3");
    }
}
