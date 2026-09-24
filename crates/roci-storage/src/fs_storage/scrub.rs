//! Background data scrubbing for the filesystem backend: staggered, adaptive
//! CRC32C verification escalating to a full digest re-hash on mismatch.
