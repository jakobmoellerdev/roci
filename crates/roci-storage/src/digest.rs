//! Content digests (`algorithm:hex`) and the hashers used to compute and verify them.

use crate::StorageError;
use sha2::{Sha256, Sha512};
use std::io;
use tokio::io::AsyncReadExt;

/// A parsed `algorithm:hex` content digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    algorithm: String,
    hex: String,
}

impl Digest {
    /// Parse a digest string of the form `sha256:<64 hex>`. Only sha256 and
    /// sha512 are accepted (the algorithms the OCI spec registers).
    pub fn parse(s: &str) -> Result<Self, StorageError> {
        let (algorithm, hex) = s
            .split_once(':')
            .ok_or_else(|| StorageError::BadDigest(s.to_string()))?;
        let ok_len = match algorithm {
            "sha256" => 64,
            "sha512" => 128,
            _ => return Err(StorageError::BadDigest(s.to_string())),
        };
        if hex.len() != ok_len || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(StorageError::BadDigest(s.to_string()));
        }
        Ok(Self {
            algorithm: algorithm.to_string(),
            hex: hex.to_ascii_lowercase(),
        })
    }

    /// The canonical `algorithm:hex` string.
    pub fn as_string(&self) -> String {
        self.to_string()
    }

    /// The digest's lowercase hex encoding (the part after `algorithm:`).
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// The digest's wire algorithm (`sha256` or `sha512`).
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Constant-time equality: compares the algorithm, then the hex bytes with
    /// a branch-free accumulator so digest verification leaks no timing signal
    /// (SECURITY.md §Storage boundary).
    pub fn ct_eq(&self, other: &Digest) -> bool {
        if self.algorithm != other.algorithm || self.hex.len() != other.hex.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (a, b) in self.hex.bytes().zip(other.hex.bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.hex)
    }
}

/// Hash `data` with `H` (the concrete SHA family), tagged with its wire `algorithm`.
fn hash_bytes<H: sha2::Digest>(algorithm: &str, data: &[u8]) -> Digest {
    Digest {
        algorithm: algorithm.to_owned(),
        hex: hex::encode(H::digest(data)),
    }
}

/// Stream `f` through `H` in 64 KiB reads without buffering the whole file,
/// tagging the result with its wire `algorithm`; the same single pass also
/// folds every byte into a CRC32C (the scrub's fast checksum).
async fn hash_file<H: sha2::Digest>(
    algorithm: &str,
    mut f: tokio::fs::File,
) -> io::Result<(Digest, u32)> {
    let mut h = H::new();
    let mut crc = 0u32;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        crc = crc32c::crc32c_append(crc, &buf[..n]);
    }
    Ok((
        Digest {
            algorithm: algorithm.to_owned(),
            hex: hex::encode(h.finalize()),
        },
        crc,
    ))
}

/// The sha256 [`Digest`] of an incrementally fed hasher.
pub(crate) fn finish_sha256(h: Sha256) -> Digest {
    Digest {
        algorithm: "sha256".to_owned(),
        hex: hex::encode(sha2::Digest::finalize(h)),
    }
}

/// Compute the sha256 digest of `data`.
pub fn sha256_of(data: &[u8]) -> Digest {
    hash_bytes::<Sha256>("sha256", data)
}

/// Compute the digest of `data` using the given wire algorithm (sha256 or
/// sha512 — the values [`Digest::parse`] accepts). Verification hashes with the
/// *expected* algorithm so a sha512 digest is honored, not silently rejected.
pub fn digest_of(data: &[u8], algorithm: &str) -> Digest {
    match algorithm {
        "sha512" => hash_bytes::<Sha512>("sha512", data),
        // Default to sha256 for the only other allowlisted algorithm.
        _ => sha256_of(data),
    }
}

/// Stream `f` through the hasher selected by `algorithm` (sha256/sha512),
/// returning its [`Digest`] and CRC32C without buffering the whole file. `f`
/// is an already-opened, no-follow-validated regular-file handle (the caller
/// opens it beneath the store root). Used to verify a staged upload before
/// promoting it, and by the scrub's full re-hash.
pub(crate) async fn hash_reader(f: tokio::fs::File, algorithm: &str) -> io::Result<(Digest, u32)> {
    if algorithm == "sha512" {
        hash_file::<Sha512>("sha512", f).await
    } else {
        hash_file::<Sha256>("sha256", f).await
    }
}
