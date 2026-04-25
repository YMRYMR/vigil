//! File integrity helpers for operator-managed inputs.
//!
//! Phase 15 extends Vigil's tamper-evidence beyond `vigil.json` by letting
//! security-sensitive companion files carry a simple SHA-256 sidecar.  The
//! sidecar format is intentionally compatible with common `sha256sum` output:
//!
//! ```text
//! <64 hex chars>  optional-filename
//! ```
//!
//! Operator-managed inputs must now carry a sidecar. Missing, malformed, or
//! mismatched sidecars are treated as untrusted input and fail closed.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const HASH_HEX_LEN: usize = 64;
const SIDECAR_SUFFIX: &str = "sha256";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStatus {
    Verified { sidecar: PathBuf },
}

/// Read a file and verify it against `<filename>.sha256` when that sidecar is
/// present. Missing sidecars, malformed sidecars, or digest mismatches are
/// hard failures.
pub fn read_verified(path: &Path, purpose: &str) -> Result<(Vec<u8>, VerificationStatus), String> {
    let data =
        fs::read(path).map_err(|e| format!("failed to read {purpose} {}: {e}", path.display()))?;
    let sidecar = sidecar_path(path);
    match fs::symlink_metadata(&sidecar) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "{purpose} {} is missing required SHA-256 sidecar {}",
                path.display(),
                sidecar.display()
            ));
        }
        Err(e) => {
            return Err(format!(
                "failed to access integrity sidecar {}: {e}",
                sidecar.display()
            ));
        }
    }

    let expected = read_sidecar_hash(&sidecar)?;
    let actual = sha256_hex(&data);
    if !actual.eq_ignore_ascii_case(&expected) {
        return Err(format!(
            "{purpose} {} failed SHA-256 verification: expected {expected}, got {actual}",
            path.display()
        ));
    }

    Ok((data, VerificationStatus::Verified { sidecar }))
}

pub fn read_verified_to_string(
    path: &Path,
    purpose: &str,
) -> Result<(String, VerificationStatus), String> {
    let (data, status) = read_verified(path, purpose)?;
    let text = String::from_utf8(data).map_err(|e| {
        format!(
            "failed to decode {purpose} {} as UTF-8: {e}",
            path.display()
        )
    })?;
    Ok((text, status))
}

pub fn sidecar_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("integrity");
    path.with_file_name(format!("{file_name}.{SIDECAR_SUFFIX}"))
}

fn read_sidecar_hash(path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(path)
        .map_err(|e| format!("failed to stat integrity sidecar {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "integrity sidecar {} is not a regular file",
            path.display()
        ));
    }
    let text = fs::read_to_string(path)
        .map_err(|e| format!("failed to read integrity sidecar {}: {e}", path.display()))?;
    let candidate = text
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("integrity sidecar {} is empty", path.display()))?;
    if candidate.len() != HASH_HEX_LEN || !candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "integrity sidecar {} does not start with a 64-character SHA-256 hex digest",
            path.display()
        ));
    }
    Ok(candidate.to_ascii_lowercase())
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    encode_hex(&digest)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    #[test]
    fn verified_sidecar_allows_matching_file() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.yaml");
        fs::write(&path, b"rules: []\n").unwrap();
        fs::write(
            sidecar_path(&path),
            format!("{}  rules.yaml\n", sha256_hex(b"rules: []\n")),
        )
        .unwrap();

        let (text, status) = read_verified_to_string(&path, "rules").unwrap();
        assert_eq!(text, "rules: []\n");
        assert!(matches!(status, VerificationStatus::Verified { .. }));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sidecar_mismatch_fails_closed() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blocklist.txt");
        fs::write(&path, b"1.2.3.4\n").unwrap();
        fs::write(
            sidecar_path(&path),
            format!("{}  blocklist.txt\n", sha256_hex(b"5.6.7.8\n")),
        )
        .unwrap();

        let err = read_verified(&path, "blocklist").unwrap_err();
        assert!(err.contains("failed SHA-256 verification"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_sidecar_fails_closed() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("strict.txt");
        fs::write(&path, b"strict\n").unwrap();

        let err = read_verified(&path, "strict").unwrap_err();
        assert!(err.contains("missing required SHA-256 sidecar"));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_metadata_errors_fail_closed() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.yaml");
        let sidecar = sidecar_path(&path);
        fs::write(&path, b"rules: []\n").unwrap();
        symlink(&sidecar, &sidecar).unwrap();

        let err = read_verified(&path, "rules").unwrap_err();
        assert!(err.contains("integrity sidecar"));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn dangling_sidecar_symlink_fails_closed() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.yaml");
        let sidecar = sidecar_path(&path);
        let missing = dir.join("missing.sha256");
        fs::write(&path, b"rules: []\n").unwrap();
        symlink(&missing, &sidecar).unwrap();

        let err = read_verified(&path, "rules").unwrap_err();
        assert!(err.contains("integrity sidecar"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn directory_sidecar_fails_closed() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.yaml");
        let sidecar = sidecar_path(&path);
        fs::write(&path, b"rules: []\n").unwrap();
        fs::create_dir(&sidecar).unwrap();

        let err = read_verified(&path, "rules").unwrap_err();
        assert!(err.contains("is not a regular file"));
        let _ = fs::remove_dir_all(dir);
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-integrity-test-{nanos}"))
    }
}
