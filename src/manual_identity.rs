use std::collections::HashMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DITTO_IDENTITY_TAG: &str = "DITTO IDENTITY";

pub const IN_BAND_CERTIFICATE_VERSION: u32 = 1;

/// Information which is verified by the signature inside the `InBandCertificate`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Payload {
    /// Application for which this certificate is granted
    #[serde(rename = "a")]
    pub app_id: String,

    /// Seconds since unix epoch that this certificate became valid, i.e. now() >= not_before
    #[serde(rename = "n")]
    pub not_before: i64,

    /// Seconds since unix epoch until which this certificate remains valid, i.e. now() < expiry
    #[serde(rename = "e")]
    pub expiry: i64,

    /// Hash of the serialised `IdentityData`, as it was issued for this peer upon authentication.
    /// This is also a serialised Ditto TLV.
    #[serde(rename = "h", with = "serde_bytes")]
    pub identity_data_hash: Vec<u8>,
}

/// An assertion that a certain `IdentityData` is valid. The `IdentityData` contains a mapping from
/// information about the peer to their Peer Key.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct InBandCertificate {
    /// Version of certificate format. See [IN_BAND_CERTIFICATE_VERSION].
    #[serde(rename = "v")]
    pub version: u32,

    /// Signed content: a TLV-serialised form of [Payload].
    ///
    /// Stored as opaque binary to ensure the signature can be verified without decoding ambiguity.
    #[serde(rename = "p", with = "serde_bytes")]
    pub payload: Vec<u8>,

    /// Public key of the signer. Should be 33 bytes.
    #[serde(rename = "k", with = "serde_bytes")]
    pub ecdsa_verifying_key: Vec<u8>,

    /// ECDSA signature. Should be 64 bytes.
    #[serde(rename = "s", with = "serde_bytes")]
    pub ecdsa_signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct InBandAuthV1 {
    /// This peer's InBandCertificate
    inband_certificate: InBandCertificate,
    /// CA public keys to verify the in band certificate
    inband_ca_pubkey_keys: Vec<Vec<u8>>,
    sub_authority_certificate: Option<Vec<u8>>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct X509AuthV1 {
    /// This peer's private key
    private_key: Vec<u8>,
    /// This peer's certificate
    my_certificate: Vec<u8>,
    /// CA certificates to verify my own certificate
    ca_certificates: Vec<Vec<u8>>,

    sub_authority_certificate: Option<Vec<u8>>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum JwtAuthV1 {
    OnlineAuth {
        url: String,
        provider: String,
        token_credential: String,
    },
    Static {
        jwt: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(try_from = "ManualIdentityStoredFormat")]
#[serde(into = "ManualIdentityStoredFormat")]
pub enum ManualIdentity {
    V1(ManualIdentityV1),
}

impl ManualIdentity {
    pub fn new_v1(identity: ManualIdentityV1) -> Self {
        Self::V1(identity)
    }

    pub fn to_string(&self) -> String {
        let cbor = serde_cbor::to_vec(&self).unwrap();
        let pem = pem::Pem {
            tag: DITTO_IDENTITY_TAG.to_string(),
            contents: cbor,
        };
        let pem_string = pem::encode(&pem);
        pem_string
    }

    pub fn from_string(input: &str) -> Result<Self, anyhow::Error> {
        let p = pem::parse(input)?;

        if p.tag != DITTO_IDENTITY_TAG {
            return Err(anyhow::anyhow!("Wrong tag"));
        }
        let ret: ManualIdentity = serde_cbor::from_slice(&p.contents)?;
        Ok(ret)
    }
}

// Helper struct to help serialize/deserialize `ManualIdentity`
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ManualIdentityStoredFormat {
    version: u16,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    v1: Option<ManualIdentityV1>,
}

#[derive(Error, Debug)]
pub enum ManualIdentitySerializationError {
    #[error("Data stored does not match version tag")]
    VersionMismatched,
    #[error("Unrecognized version tag")]
    UnrecognizedVersion,
}

impl TryFrom<ManualIdentityStoredFormat> for ManualIdentity {
    type Error = ManualIdentitySerializationError;

    fn try_from(value: ManualIdentityStoredFormat) -> Result<Self, Self::Error> {
        if value.version == 1 {
            let Some(v1) = value.v1 else {
                return Err(ManualIdentitySerializationError::VersionMismatched);
            };
            return Ok(Self::V1(v1));
        }

        Err(ManualIdentitySerializationError::UnrecognizedVersion)
    }
}

impl From<ManualIdentity> for ManualIdentityStoredFormat {
    fn from(input: ManualIdentity) -> Self {
        match input {
            ManualIdentity::V1(v1) => Self {
                version: 1,
                v1: Some(v1),
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ManualIdentityV1 {
    /// The application id
    app_id: String,
    /// This peer private key
    private_key: Vec<u8>,
    /// Exipry date time
    expiry: chrono::DateTime<chrono::Utc>,
    /// Identity data issued by auth server
    identity_data: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    inband_auth: Option<InBandAuthV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x509_auth: Option<X509AuthV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwt_auth: Option<JwtAuthV1>,
}

impl ManualIdentityV1 {
    pub fn new(
        app_id: &str,
        private_key: Vec<u8>,
        expiry: chrono::DateTime<Utc>,
        identity_data: Vec<u8>,
        inband_auth: Option<InBandAuthV1>,
        x509_auth: Option<X509AuthV1>,
        jwt_auth: Option<JwtAuthV1>,
    ) -> Self {
        Self {
            app_id: app_id.to_string(),
            private_key,
            expiry,
            identity_data,
            inband_auth,
            x509_auth,
            jwt_auth,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, NaiveDate};

    use super::*;

    #[test]
    fn test_encoding_decoding() {
        let v1 = ManualIdentityV1::new(
            "test_app_id",
            vec![],
            chrono::Utc::now(),
            vec![],
            None,
            None,
            None,
        );
        let identity = ManualIdentity::new_v1(v1);

        let pem_string = identity.to_string();
        let lines = pem_string.lines().collect::<Vec<_>>();

        assert_eq!(lines[0], "-----BEGIN DITTO IDENTITY-----");
        assert_eq!(lines.last().unwrap(), &"-----END DITTO IDENTITY-----");

        let parsed_identity = ManualIdentity::from_string(&pem_string).unwrap();

        assert_eq!(parsed_identity, identity);
    }

    #[test]
    fn test_encoding() {
        let dt = DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd_opt(2023, 2, 27)
                .unwrap()
                .and_hms_micro_opt(0, 0, 0, 0)
                .unwrap(),
            Utc,
        );
        let v1 = ManualIdentityV1::new(
            "test_app_id",
            vec![1, 2, 3],
            dt,
            vec![4, 5, 6],
            None,
            None,
            None,
        );
        let identity = ManualIdentity::new_v1(v1);

        let pem_string = identity.to_string();
        assert_eq!(pem_string, "-----BEGIN DITTO IDENTITY-----\r\nv2d2ZXJzaW9uAWZhcHBfaWRrdGVzdF9hcHBfaWRrcHJpdmF0ZV9rZXmDAQIDZmV4\r\ncGlyeXQyMDIzLTAyLTI3VDAwOjAwOjAwWm1pZGVudGl0eV9kYXRhgwQFBv8=\r\n-----END DITTO IDENTITY-----\r\n");
        let lines = pem_string.lines().collect::<Vec<_>>();

        assert_eq!(lines[0], "-----BEGIN DITTO IDENTITY-----");
        assert_eq!(lines.last().unwrap(), &"-----END DITTO IDENTITY-----");

        let parsed_identity = ManualIdentity::from_string(&pem_string).unwrap();

        assert_eq!(parsed_identity, identity);
    }

    #[test]
    fn fields_flatten() {
        let v1 = ManualIdentityV1::new(
            "test_app_id",
            vec![],
            chrono::Utc::now(),
            vec![],
            None,
            None,
            None,
        );
        let identity = ManualIdentity::new_v1(v1);

        let json = serde_json::to_value(&identity).unwrap();
        // Ensure the v1 identity fields has been flatten
        let json_app_id = json["app_id"].as_str().unwrap();
        assert_eq!(json_app_id, "test_app_id");
    }
}
