//! Provenance manifests for forensic artifacts.
//!
//! Phase 15 requires artifacts produced by Vigil to carry enough metadata for
//! later integrity checks. This module writes a small JSON sidecar next to each
//! PCAP, TLS extraction, or process dump containing the artifact checksum,
//! size, alert context, and capture-specific metadata.

use crate::types::ConnInfo;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactManifest {
    version: u8,
    artifact_kind: String,
    artifact_path: String,
    artifact_name: String,
    size_bytes: u64,
    sha256: String,
    manifest_created_unix: u64,
    alert: AlertProvenance,
    extra: Value,
}

#[derive(Debug, Clone, Serialize)]
struct AlertProvenance {
    pid: u32,
    proc_name: String,
    proc_path: String,
    proc_user: String,
    parent_name: String,
    parent_pid: u32,
    service_name: String,
    publisher: String,
    command_line: String,
    score: u8,
    reasons: Vec<String>,
    attack_tags: Vec<String>,
    local_addr: String,
    remote_addr: String,
    status: String,
    hostname: Option<String>,
    country: Option<String>,
    asn: Option<u32>,
    asn_org: Option<String>,
    tls_sni: Option<String>,
    tls_ja3: Option<String>,
}

pub fn write_manifest(
    artifact_path: &Path,
    artifact_kind: &str,
    info: &ConnInfo,
    extra: Value,
) -> Result<PathBuf, String> {
    let manifest = build_manifest(artifact_path, artifact_kind, info, extra)?;
    let manifest_path = manifest_path_for(artifact_path);
    write_json_atomic(&manifest_path, &manifest)?;
    Ok(manifest_path)
}

fn build_manifest(
    artifact_path: &Path,
    artifact_kind: &str,
    info: &ConnInfo,
    extra: Value,
) -> Result<ArtifactManifest, String> {
    let metadata = fs::metadata(artifact_path)
        .map_err(|e| format!("failed to stat artifact {}: {e}", artifact_path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "artifact {} is not a regular file",
            artifact_path.display()
        ));
    }
    Ok(ArtifactManifest {
        version: 1,
        artifact_kind: artifact_kind.to_string(),
        artifact_path: artifact_path.display().to_string(),
        artifact_name: artifact_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("artifact")
            .to_string(),
        size_bytes: metadata.len(),
        sha256: sha256_file(artifact_path)?,
        manifest_created_unix: unix_now(),
        alert: AlertProvenance {
            pid: info.pid,
            proc_name: info.proc_name.clone(),
            proc_path: info.proc_path.clone(),
            proc_user: info.proc_user.clone(),
            parent_name: info.parent_name.clone(),
            parent_pid: info.parent_pid,
            service_name: info.service_name.clone(),
            publisher: info.publisher.clone(),
            command_line: info.command_line.clone(),
            score: info.score,
            reasons: info.reasons.clone(),
            attack_tags: info.attack_tags.clone(),
            local_addr: info.local_addr.clone(),
            remote_addr: info.remote_addr.clone(),
            status: info.status.clone(),
            hostname: info.hostname.clone(),
            country: info.country.clone(),
            asn: info.asn,
            asn_org: info.asn_org.clone(),
            tls_sni: info.tls_sni.clone(),
            tls_ja3: info.tls_ja3.clone(),
        },
        extra,
    })
}

fn manifest_path_for(artifact_path: &Path) -> PathBuf {
    let mut path = artifact_path.as_os_str().to_os_string();
    path.push(".manifest.json");
    PathBuf::from(path)
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(encode_hex(&hasher.finalize()))
}

fn write_json_atomic(path: &Path, manifest: &ArtifactManifest) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("cannot determine parent directory for {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    let tmp_path = path.with_extension("manifest.json.tmp");
    let data = serde_json::to_vec_pretty(manifest)
        .map_err(|e| format!("failed to serialize artifact manifest: {e}"))?;
    {
        let mut file = fs::File::create(&tmp_path)
            .map_err(|e| format!("failed to create {}: {e}", tmp_path.display()))?;
        file.write_all(&data)
            .map_err(|e| format!("failed to write {}: {e}", tmp_path.display()))?;
        file.write_all(b"\n")
            .map_err(|e| format!("failed to write {}: {e}", tmp_path.display()))?;
        file.sync_all()
            .map_err(|e| format!("failed to sync {}: {e}", tmp_path.display()))?;
    }
    if path.exists() {
        fs::remove_file(path).map_err(|e| format!("failed to replace {}: {e}", path.display()))?;
    }
    fs::rename(&tmp_path, path)
        .map_err(|e| format!("failed to move {} into place: {e}", path.display()))?;
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    use crate::types::ConnInfo;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn writes_manifest_with_checksum_and_alert_context() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("capture.pcapng");
        fs::write(&artifact, b"abc").unwrap();

        let info = ConnInfo {
            timestamp: "2026-04-24T00:00:00Z".into(),
            proc_name: "evil.exe".into(),
            pid: 42,
            proc_path: "C:/tmp/evil.exe".into(),
            proc_user: "user".into(),
            parent_user: "user".into(),
            parent_name: "cmd.exe".into(),
            parent_pid: 7,
            service_name: String::new(),
            publisher: "Unknown".into(),
            command_line: "evil.exe --connect".into(),
            local_addr: "127.0.0.1:1234".into(),
            remote_addr: "203.0.113.10:443".into(),
            status: "ESTABLISHED".into(),
            score: 12,
            reasons: vec!["test reason".into()],
            attack_tags: vec!["T1105".into()],
            ancestor_chain: vec![("cmd.exe".into(), 7)],
            pre_login: false,
            hostname: Some("example.test".into()),
            country: Some("ZZ".into()),
            asn: Some(64500),
            asn_org: Some("Example ASN".into()),
            reputation_hit: None,
            recently_dropped: false,
            long_lived: false,
            dga_like: false,
            baseline_deviation: false,
            script_host_suspicious: false,
            tls_sni: Some("example.test".into()),
            tls_ja3: Some("ja3".into()),
        };

        let manifest = write_manifest(&artifact, "pcap", &info, json!({ "seconds": 5 })).unwrap();
        let text = fs::read_to_string(&manifest).unwrap();
        assert!(text.contains("\"artifact_kind\": \"pcap\""));
        assert!(text.contains("\"pid\": 42"));
        assert!(text.contains("\"score\": 12"));
        assert!(text.contains("\"proc_path\": \"C:/tmp/evil.exe\""));
        assert!(text.contains("\"sha256\": \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\""));

        let _ = fs::remove_dir_all(dir);
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-artifact-manifest-test-{nanos}"))
    }
}
