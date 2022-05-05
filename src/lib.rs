//! Generate authentication for devices in a [Ditto mesh](https://ditto.live).
//!
//! Currently this provides a cross-platform way to generate a suitable P-256 private key for use in
//! Ditto [shared key authentication](https://docs.ditto.live/security/shared-key).
//!
//! This crate may be used directly as a library or via the included CLI binary.

pub mod shared_key;
