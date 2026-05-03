//! Minimal local software inventory foundations for advisory relevance.
//!
//! Phase 16 Task 1 starts with a conservative, low-risk inventory source:
//! currently-running processes. This avoids package-manager-specific parsing
//! while still giving the advisory pipeline stable product candidates.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledSoftware {
    pub product_key: String,
    pub display_name: String,
    pub executable_path: String,
    pub publisher_hint: Option<String>,
    pub source: InventorySource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InventorySource {
    RunningProcess,
}

pub fn collect_installed_software() -> Vec<InstalledSoftware> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut by_key: BTreeMap<String, InstalledSoftware> = BTreeMap::new();

    for process in sys.processes().values() {
        let display_name = process.name().to_string_lossy().trim().to_string();

        let executable_path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        if display_name.is_empty() && executable_path.is_empty() {
            continue;
        }

        let product_key = derive_product_key(&display_name, &executable_path);
        let entry = InstalledSoftware {
            product_key: product_key.clone(),
            display_name,
            executable_path,
            publisher_hint: None,
            source: InventorySource::RunningProcess,
        };

        match by_key.get_mut(&product_key) {
            Some(existing) if should_replace_existing(existing, &entry) => *existing = entry,
            Some(_) => {}
            None => {
                by_key.insert(product_key, entry);
            }
        }
    }

    by_key.into_values().collect()
}

fn should_replace_existing(existing: &InstalledSoftware, candidate: &InstalledSoftware) -> bool {
    entry_rank(candidate) > entry_rank(existing)
}

fn entry_rank(entry: &InstalledSoftware) -> (bool, bool, &str, &str) {
    (
        !entry.executable_path.is_empty(),
        !entry.display_name.is_empty(),
        entry.executable_path.as_str(),
        entry.display_name.as_str(),
    )
}

fn derive_product_key(display_name: &str, executable_path: &str) -> String {
    if let Some(file_name) = std::path::Path::new(executable_path).file_name() {
        let candidate = normalize_name(&file_name.to_string_lossy());
        if !candidate.is_empty() {
            return candidate;
        }
    }

    let normalized_name = normalize_name(display_name);
    if !normalized_name.is_empty() {
        return normalized_name;
    }

    "unknown-product".to_string()
}

fn normalize_name(input: &str) -> String {
    let lower = input.trim().to_lowercase();
    let no_ext = lower.strip_suffix(".exe").unwrap_or(&lower);
    no_ext
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_name_strips_case_and_extension() {
        assert_eq!(normalize_name("PowerShell.EXE"), "powershell");
    }

    #[test]
    fn normalize_name_preserves_unicode_letters() {
        assert_eq!(normalize_name("Программа.EXE"), "программа");
        assert_eq!(normalize_name("監視ツール.exe"), "監視ツール");
    }

    #[test]
    fn prefers_richer_duplicate_entry() {
        let mut existing = InstalledSoftware {
            product_key: "curl".into(),
            display_name: "curl".into(),
            executable_path: String::new(),
            publisher_hint: None,
            source: InventorySource::RunningProcess,
        };
        let candidate = InstalledSoftware {
            product_key: "curl".into(),
            display_name: "curl".into(),
            executable_path: "/usr/bin/curl".into(),
            publisher_hint: None,
            source: InventorySource::RunningProcess,
        };

        if should_replace_existing(&existing, &candidate) {
            existing = candidate;
        }

        assert_eq!(existing.executable_path, "/usr/bin/curl");
    }

    #[test]
    fn derive_product_key_prefers_executable_basename() {
        let key = derive_product_key("google-chrome-sta", "/opt/google/chrome/google-chrome-stable");
        assert_eq!(key, "google-chrome-stable");
    }

    #[test]
    fn derive_product_key_uses_display_name_when_path_missing() {
        let key = derive_product_key("Google Chrome", "");
        assert_eq!(key, "google-chrome");
    }

    #[test]
    fn derive_product_key_unknown_when_name_and_path_missing() {
        let key = derive_product_key("", "");
        assert_eq!(key, "unknown-product");
    }
}
