//! Shared key authentication

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use thiserror::Error;

/// Generate a key string suitable for use in a "Shared Key" identity in the Ditto SDK.
///
/// This is a P-256 ECDSA private key encoded as base64 PKCS#8 document, however you should treat it
/// as an opaque string.
pub fn generate_key() -> Result<String, SharedKeyError> {
    let rand = SystemRandom::new();
    let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rand)
        .map_err(|_| SharedKeyError::Generate)?;
    let b64 = base64::encode(key.as_ref());
    Ok(b64)
}

#[derive(Error, Debug)]
pub enum SharedKeyError {
    #[error("failed to generate new shared key")]
    Generate,
}

#[cfg(test)]
mod tests {
    use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    use crate::shared_key::generate_key;

    #[test]
    fn key_round_trip() {
        let key = generate_key().unwrap();
        let pkcs = base64::decode(&key).unwrap();

        // Test round trip in ring
        let parsed = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs);
        assert!(parsed.is_ok());

        // Also that it can be read by rcgen for certificate signing
        let rc_key = rcgen::KeyPair::from_der(&pkcs);
        assert!(rc_key.is_ok());
    }
}
