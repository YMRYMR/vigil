//! Quarantine helpers for corrupted or untrusted Vigil-owned files.
//!
//! This module is intentionally scoped to files Vigil generates itself. It is
//! not used for operator-managed blocklists or response-rule YAML because those
//! files are expected to change through normal local editing.

use crate::audit;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn quarantine_integrity_failure(
    primary: &Path,
    related: &[PathBuf],
    reason: &str,
) -> Result<PathBuf, String> {
    let dest_dir = crate::config::data_dir()
        .join("quarantine")
        .join("integrity")
        .join(format!("{}-{}", unix_now(), safe_name(primary)));
    fs::create_dir_all(&dest_dir).map_err(|e| {
        format!(
            "failed to create quarantine dir {}: {e}",
            dest_dir.display()
        )
    })?;

    let mut moved = Vec::new();
    move_if_present(primary, &dest_dir, &mut moved)?;
    for path in related {
        if path != primary {
            move_if_present(path, &dest_dir, &mut moved)?;
        }
    }

    audit::record(
        "integrity_quarantine",
        "success",
        json!({
            "reason": reason,
            "primary": primary.display().to_string(),
            "quarantine_dir": dest_dir.display().to_string(),
            "moved": moved,
        }),
    );
    Ok(dest_dir)
}

fn move_if_present(path: &Path, dest_dir: &Path, moved: &mut Vec<String>) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::metadata(path)
        .map_err(|e| format!("failed to stat {} before quarantine: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "refusing to quarantine non-regular file {}",
            path.display()
        ));
    }
    let dest = unique_destination(dest_dir, path);
    fs::rename(path, &dest)
        .or_else(|_| {
            fs::copy(path, &dest)
                .and_then(|_| fs::remove_file(path))
                .map(|_| ())
        })
        .map_err(|e| {
            format!(
                "failed to move {} to {}: {e}",
                path.display(),
                dest.display()
            )
        })?;
    moved.push(dest.display().to_string());
    Ok(())
}

fn unique_destination(dest_dir: &Path, source: &Path) -> PathBuf {
    let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vigil-file");
    let candidate = dest_dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    for n in 1..1000 {
        let candidate = dest_dir.join(format!("{n}-{name}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    dest_dir.join(format!("{}-{name}", unix_now()))
}

fn safe_name(path: &Path) -> String {
    let cleaned = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    let trimmed = cleaned.trim_matches('_');
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed.chars().take(80).collect::<String>()
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn unique_destination_keeps_original_filename_when_available() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("sample.manifest.json");
        let dest = unique_destination(&dir, &source);
        assert_eq!(
            dest.file_name().and_then(|n| n.to_str()),
            Some("sample.manifest.json")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn safe_name_strips_path_separators() {
        let path = PathBuf::from("bad/name:with*chars.json");
        assert!(!safe_name(&path).contains('/'));
        assert!(!safe_name(&path).contains(':'));
        assert!(safe_name(&path).contains("name_with_chars.json"));
    }

    #[test]
    fn refuses_to_move_directories() {
        let dir = unique_temp_dir();
        let source_dir = dir.join("source-dir");
        let dest_dir = dir.join("dest");
        fs::create_dir_all(&source_dir).unwrap();
        fs::create_dir_all(&dest_dir).unwrap();
        let mut moved = Vec::new();
        let err = move_if_present(&source_dir, &dest_dir, &mut moved).unwrap_err();
        assert!(err.contains("refusing to quarantine non-regular file"));
        assert!(source_dir.exists());
        assert!(moved.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-file-quarantine-test-{nanos}"))
    }
}
