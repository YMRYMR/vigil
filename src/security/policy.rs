//! Protected policy-store helpers.
//!
//! Vigil keeps the authoritative user policy in `vigil.json`, but the file is
//! wrapped with an integrity sidecar and a signed backup so casual tampering or
//! corruption can be detected and repaired on load.

use hmac::{Hmac, KeyInit, Mac};
use serde::{de::DeserializeOwned, Serialize};
use sha2::Sha256;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

const SECRET_FILE: &str = "vigil-policy.key";
const SIGNATURE_SUFFIX: &str = "sig";
const BACKUP_SUFFIX: &str = "bak";
const SECRET_LEN: usize = 32;

pub fn load_json_with_integrity(path: &Path) -> Result<Option<Vec<u8>>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let secret_path = secret_path(path);
    let had_secret = secret_path.exists();
    let current = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let sig_path = signature_path(path);
    if let Some(signature) = read_signature(&sig_path)? {
        let secret = load_or_create_secret(path)?;
        if verify_signature(&secret, &current, &signature) {
            return Ok(Some(current));
        }
        tracing::warn!(
            "policy integrity check failed for {} — attempting backup restore",
            path.display()
        );
        if let Some(restored) = restore_from_backup(path, &secret)? {
            return Ok(Some(restored));
        }
        return Ok(None);
    }

    if had_secret || backup_data_path(path).exists() || backup_sig_path(path).exists() {
        let secret = load_or_create_secret(path)?;
        tracing::warn!(
            "policy signature missing for existing store {}; attempting backup restore",
            path.display()
        );
        if let Some(restored) = restore_from_backup(path, &secret)? {
            return Ok(Some(restored));
        }
        return Ok(None);
    }

    tracing::warn!(
        "policy signature missing for existing store {}; refusing unsigned policy",
        path.display()
    );
    Ok(None)
}

pub fn save_json_with_integrity(path: &Path, data: &[u8]) -> Result<(), String> {
    let secret = load_or_create_secret(path)?;
    save_current_and_backup(path, &secret, data)
}

pub fn load_struct_with_integrity<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    let Some(bytes) = load_json_with_integrity(path)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| format!("failed to parse protected JSON {}: {e}", path.display()))
}

pub fn save_struct_with_integrity<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(value)
        .map_err(|e| format!("failed to serialize protected JSON {}: {e}", path.display()))?;
    save_json_with_integrity(path, &data)
}

pub fn remove_json_with_integrity(path: &Path) -> Result<(), String> {
    for target in [
        path.to_path_buf(),
        signature_path(path),
        backup_data_path(path),
        backup_sig_path(path),
    ] {
        if !target.exists() {
            continue;
        }
        fs::remove_file(&target)
            .map_err(|e| format!("failed to remove {}: {e}", target.display()))?;
    }
    Ok(())
}

fn restore_from_backup(path: &Path, secret: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let backup_path = backup_data_path(path);
    let backup_sig_path = backup_sig_path(path);
    let Some(backup) = read_signed_artifact(&backup_path, &backup_sig_path, secret)? else {
        return Ok(None);
    };
    save_current_and_backup(path, secret, &backup)?;
    Ok(Some(backup))
}

fn save_current_and_backup(path: &Path, secret: &[u8], data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let sig_path = signature_path(path);
    let backup_path = backup_data_path(path);
    let backup_sig_path = backup_sig_path(path);
    write_atomic(path, data)?;
    write_atomic(&sig_path, signature_hex(secret, data).as_bytes())?;
    fs::copy(path, &backup_path).map_err(|e| {
        format!(
            "failed to copy {} to {}: {e}",
            path.display(),
            backup_path.display()
        )
    })?;
    fs::copy(&sig_path, &backup_sig_path).map_err(|e| {
        format!(
            "failed to copy {} to {}: {e}",
            sig_path.display(),
            backup_sig_path.display()
        )
    })?;
    protect_secret_file(&secret_path(path))?;
    Ok(())
}

fn read_signed_artifact(
    data_path: &Path,
    sig_path: &Path,
    secret: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    if !data_path.exists() || !sig_path.exists() {
        return Ok(None);
    }
    let data =
        fs::read(data_path).map_err(|e| format!("failed to read {}: {e}", data_path.display()))?;
    let signature = match read_signature(sig_path)? {
        Some(sig) => sig,
        None => return Ok(None),
    };
    if verify_signature(secret, &data, &signature) {
        Ok(Some(data))
    } else {
        Ok(None)
    }
}

fn load_or_create_secret(path: &Path) -> Result<Vec<u8>, String> {
    let path = secret_path(path);
    if path.exists() {
        let bytes =
            fs::read(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if bytes.len() == SECRET_LEN {
            return Ok(bytes);
        }
        tracing::warn!(
            "policy secret had unexpected length ({} bytes); regenerating",
            bytes.len()
        );
    }
    let mut secret = vec![0u8; SECRET_LEN];
    getrandom::fill(&mut secret).map_err(|e| format!("failed to generate policy secret: {e}"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    write_atomic(&path, &secret)?;
    protect_secret_file(&path)?;
    Ok(secret)
}

fn protect_secret_file(_path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(_path)
            .map_err(|e| format!("failed to stat {}: {e}", _path.display()))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(_path, perms)
            .map_err(|e| format!("failed to restrict {}: {e}", _path.display()))?;
    }
    Ok(())
}

fn signature_path(path: &Path) -> PathBuf {
    path.with_extension(format!("json.{SIGNATURE_SUFFIX}"))
}

fn backup_data_path(path: &Path) -> PathBuf {
    path.with_extension(format!("json.{BACKUP_SUFFIX}"))
}

fn backup_sig_path(path: &Path) -> PathBuf {
    path.with_extension(format!("json.{BACKUP_SUFFIX}.{SIGNATURE_SUFFIX}"))
}

fn secret_path(path: &Path) -> PathBuf {
    path.parent()
        .map(|parent| parent.join(SECRET_FILE))
        .unwrap_or_else(|| PathBuf::from(SECRET_FILE))
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("cannot determine parent directory for {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    let tmp_path = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp_path)
            .map_err(|e| format!("failed to create {}: {e}", tmp_path.display()))?;
        file.write_all(data)
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

fn read_signature(path: &Path) -> Result<Option<Vec<u8>>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    decode_hex(text.trim())
        .map(Some)
        .map_err(|e| format!("failed to decode signature {}: {e}", path.display()))
}

fn signature_hex(secret: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key length");
    mac.update(data);
    encode_hex(&mac.finalize().into_bytes())
}

fn verify_signature(secret: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key length");
    mac.update(data);
    mac.verify_slice(expected).is_ok()
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
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn hex_round_trip_works() {
        let bytes = [0x00, 0x7f, 0x80, 0xff];
        let encoded = encode_hex(&bytes);
        assert_eq!(encoded, "007f80ff");
        assert_eq!(decode_hex(&encoded).unwrap(), bytes);
    }

    #[test]
    fn hmac_verification_detects_tampering() {
        let key = [7u8; SECRET_LEN];
        let data = b"{\"hello\":\"world\"}";
        let sig = decode_hex(&signature_hex(&key, data)).unwrap();
        assert!(verify_signature(&key, data, &sig));
        assert!(!verify_signature(&key, b"{\"hello\":\"evil\"}", &sig));
    }

    #[test]
    fn unsigned_existing_store_is_rejected() {
        let base = unique_temp_dir();
        fs::create_dir_all(&base).unwrap();
        let path = base.join("vigil.json");
        let json = br#"{"poll_interval_secs":5,"alert_threshold":3,"log_all_connections":false,"autostart":false,"first_run_done":false,"trusted_processes":[],"common_ports":[],"malware_ports":[],"suspicious_path_fragments":[],"lolbins":[],"activity_history_cap":2048,"alerts_history_cap":1024,"geoip_city_db":"","geoip_asn_db":"","allowed_countries":[],"blocklist_paths":[],"fswatch_enabled":true,"fswatch_window_secs":600,"long_lived_secs":3600,"reverse_dns_enabled":false,"dga_entropy_threshold":3.2,"auto_response_enabled":false,"auto_response_dry_run":false,"auto_kill_connection":false,"auto_block_remote":false,"auto_block_process":false,"auto_isolate_machine":false,"auto_response_min_score":10,"auto_response_cooldown_secs":300,"allowlist_mode_enabled":false,"allowlist_mode_dry_run":false,"allowlist_processes":[],"response_rules_enabled":false,"response_rules_dry_run":true,"response_rules_path":"","scheduled_lockdown_enabled":false,"scheduled_lockdown_start_hour":23,"scheduled_lockdown_start_minute":0,"scheduled_lockdown_end_hour":6,"scheduled_lockdown_end_minute":0,"process_dump_on_alert":false,"process_dump_min_score":12,"process_dump_cooldown_secs":600,"process_dump_dir":"","pcap_on_alert":false,"pcap_min_score":12,"pcap_duration_secs":15,"pcap_cooldown_secs":300,"pcap_packet_size_bytes":0,"pcap_dir":"","honeypot_decoys_enabled":false,"honeypot_auto_isolate":false,"honeypot_poll_secs":10,"honeypot_decoy_names":[],"break_glass_enabled":true,"break_glass_timeout_mins":10,"break_glass_heartbeat_secs":30,"ui_scale":1.0}"#;
        fs::write(&path, json).unwrap();
        let loaded = load_json_with_integrity(&path).unwrap();
        assert!(loaded.is_none());
        assert!(!secret_path(&path).exists());
        assert!(!signature_path(&path).exists());
        assert!(!backup_data_path(&path).exists());
        assert!(!backup_sig_path(&path).exists());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn unsigned_existing_store_remains_rejected_across_reloads() {
        let base = unique_temp_dir();
        fs::create_dir_all(&base).unwrap();
        let path = base.join("vigil.json");
        fs::write(&path, br#"{"version":1}"#).unwrap();

        let first = load_json_with_integrity(&path).unwrap();
        assert!(first.is_none());
        assert!(!secret_path(&path).exists());
        assert!(!signature_path(&path).exists());

        let second = load_json_with_integrity(&path).unwrap();
        assert!(second.is_none());
        assert!(!secret_path(&path).exists());

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn tampered_load_restores_signed_backup() {
        let base = unique_temp_dir();
        fs::create_dir_all(&base).unwrap();
        let path = base.join("vigil.json");
        let original = br#"{"version":1,"enabled":true}"#;
        let tampered = br#"{"version":1,"enabled":false}"#;
        save_json_with_integrity(&path, original).unwrap();
        fs::write(&path, tampered).unwrap();

        let restored = load_json_with_integrity(&path).unwrap().unwrap();
        assert_eq!(restored, original);
        assert_eq!(fs::read(&path).unwrap(), original);

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn missing_signature_on_existing_store_does_not_bypass_integrity() {
        let base = unique_temp_dir();
        fs::create_dir_all(&base).unwrap();
        let path = base.join("vigil.json");
        let original = br#"{"version":1,"enabled":true}"#;
        let tampered = br#"{"version":1,"enabled":false}"#;
        save_json_with_integrity(&path, original).unwrap();
        fs::remove_file(signature_path(&path)).unwrap();
        fs::write(&path, tampered).unwrap();

        let restored = load_json_with_integrity(&path).unwrap().unwrap();
        assert_eq!(restored, original);
        assert_eq!(fs::read(&path).unwrap(), original);

        let _ = fs::remove_dir_all(base);
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-policy-test-{nanos}"))
    }
}
