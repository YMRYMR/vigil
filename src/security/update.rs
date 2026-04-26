//! Signed update-manifest helpers.
//!
//! Vigil publishes a signed release manifest alongside each release asset set.
//! The app can verify that manifest offline with an embedded Ed25519 public key
//! before trusting any update metadata.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const UPDATE_PUBLIC_KEY_HEX: &str =
    "20e838c609b7c01cf642dfbb48a1f40e57e1f9aba78c030ce818b3dfabce3be0";
const UPDATE_PUBLIC_KEY_LEN: usize = 32;
const UPDATE_SIGNATURE_LEN: usize = 64;
const UPDATE_SCHEMA_VERSION: u32 = 1;
const UPDATE_CHANNEL: &str = "stable";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub schema_version: u32,
    pub channel: String,
    pub tag: String,
    pub version: String,
    pub assets: Vec<UpdateAsset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateAsset {
    pub name: String,
    pub sha256: String,
}

impl UpdateManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != UPDATE_SCHEMA_VERSION {
            return Err(format!(
                "unsupported update manifest schema version {}",
                self.schema_version
            ));
        }
        if self.channel != UPDATE_CHANNEL {
            return Err(format!(
                "unsupported update channel {} (expected {UPDATE_CHANNEL})",
                self.channel
            ));
        }
        if self.tag.is_empty() || !self.tag.starts_with('v') {
            return Err("update manifest tag must start with 'v'".into());
        }
        if self.version.is_empty() {
            return Err("update manifest version must not be empty".into());
        }
        if self.tag != format!("v{}", self.version) {
            return Err(format!(
                "update manifest tag {} does not match version {}",
                self.tag, self.version
            ));
        }
        if self.assets.is_empty() {
            return Err("update manifest must list at least one asset".into());
        }

        let mut seen_names = BTreeSet::new();
        for asset in &self.assets {
            if asset.name.trim().is_empty() {
                return Err("update manifest contains an empty asset name".into());
            }
            if !is_hex_sha256(&asset.sha256) {
                return Err(format!(
                    "asset {} does not have a valid SHA-256 digest",
                    asset.name
                ));
            }
            if !seen_names.insert(asset.name.clone()) {
                return Err(format!(
                    "update manifest lists asset {} more than once",
                    asset.name
                ));
            }
        }
        Ok(())
    }
}

pub fn verify_update_manifest(
    manifest_path: &Path,
    signature_path: &Path,
) -> Result<UpdateManifest, String> {
    let manifest_bytes = fs::read(manifest_path)
        .map_err(|e| format!("failed to read {}: {e}", manifest_path.display()))?;
    let signature_bytes = fs::read(signature_path)
        .map_err(|e| format!("failed to read {}: {e}", signature_path.display()))?;
    verify_update_manifest_bytes(&manifest_bytes, &signature_bytes)
}

pub fn verify_update_manifest_bytes(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<UpdateManifest, String> {
    let manifest: UpdateManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| format!("failed to parse update manifest: {e}"))?;
    manifest.validate()?;
    let signature = parse_signature(signature_bytes)?;
    verify_update_manifest_with_key(
        &manifest,
        manifest_bytes,
        &signature,
        &embedded_verifying_key()?,
    )?;
    Ok(manifest)
}

pub fn run_cli(manifest_path: &Path, signature_path: &Path) -> Result<(), String> {
    let manifest = verify_update_manifest(manifest_path, signature_path)?;
    println!(
        "Verified Vigil update manifest for {} (channel: {}, {} assets).",
        manifest.tag,
        manifest.channel,
        manifest.assets.len()
    );
    for asset in &manifest.assets {
        println!("  {}  {}", asset.sha256, asset.name);
    }
    Ok(())
}

pub fn embedded_public_key_hex() -> &'static str {
    UPDATE_PUBLIC_KEY_HEX
}

fn verify_update_manifest_with_key(
    manifest: &UpdateManifest,
    manifest_bytes: &[u8],
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    verifying_key
        .verify(manifest_bytes, signature)
        .map_err(|e| format!("update manifest signature did not verify: {e}"))?;
    manifest.validate()
}

fn embedded_verifying_key() -> Result<VerifyingKey, String> {
    let bytes = decode_hex(UPDATE_PUBLIC_KEY_HEX)?;
    let bytes: [u8; UPDATE_PUBLIC_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| "embedded update public key had an invalid length".to_string())?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| format!("failed to load embedded update public key: {e}"))
}

fn parse_signature(signature_bytes: &[u8]) -> Result<Signature, String> {
    let text = std::str::from_utf8(signature_bytes)
        .map_err(|e| format!("update signature is not valid UTF-8: {e}"))?;
    let decoded = STANDARD
        .decode(text.trim())
        .map_err(|e| format!("failed to decode base64 update signature: {e}"))?;
    let bytes: [u8; UPDATE_SIGNATURE_LEN] = decoded
        .try_into()
        .map_err(|_| "update signature had an invalid length".to_string())?;
    Ok(Signature::from_bytes(&bytes))
}

fn is_hex_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("hex string must have an even length".into());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        out.push((hex_value(chunk[0])? << 4) | hex_value(chunk[1])?);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex digit '{}'", byte as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_manifest() -> UpdateManifest {
        UpdateManifest {
            schema_version: UPDATE_SCHEMA_VERSION,
            channel: UPDATE_CHANNEL.to_string(),
            tag: "v1.3.5".to_string(),
            version: "1.3.5".to_string(),
            assets: vec![
                UpdateAsset {
                    name: "Vigil-Setup-1.3.5-x86_64.exe".to_string(),
                    sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                },
                UpdateAsset {
                    name: "Vigil-1.3.5-x86_64.AppImage".to_string(),
                    sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                        .to_string(),
                },
            ],
        }
    }

    #[test]
    fn manifest_validation_accepts_expected_release_shape() {
        sample_manifest().validate().unwrap();
    }

    #[test]
    fn signed_manifest_verifies_and_detects_tamper() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let manifest = sample_manifest();
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let signature = signing_key.sign(&manifest_bytes);
        let signature_bytes = STANDARD.encode(signature.to_bytes());

        let verified_manifest: UpdateManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        verify_update_manifest_with_key(
            &verified_manifest,
            &manifest_bytes,
            &signature,
            &signing_key.verifying_key(),
        )
        .unwrap();
        assert_eq!(verified_manifest, manifest);

        let mut tampered = manifest_bytes.clone();
        tampered[0] ^= 0x01;
        assert!(verify_update_manifest_bytes(&tampered, signature_bytes.as_bytes()).is_err());
    }

    #[test]
    fn validation_rejects_bad_hashes_and_duplicates() {
        let mut manifest = sample_manifest();
        manifest.assets[0].sha256 = "not-a-sha256".to_string();
        assert!(manifest.validate().is_err());

        let mut manifest = sample_manifest();
        manifest.assets.push(manifest.assets[0].clone());
        assert!(manifest.validate().is_err());
    }
}
