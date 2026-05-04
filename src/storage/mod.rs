use crate::software_inventory::InstalledSoftware;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const SOFTWARE_INVENTORY_FILE: &str = "vigil-software-inventory.json";
const SOFTWARE_INVENTORY_SCHEMA_VERSION: u32 = 1;

pub trait InventoryStore {
    fn replace_inventory(&self, entries: &[InstalledSoftware]) -> Result<(), String>;
    fn load_inventory(&self) -> Result<Vec<InstalledSoftware>, String>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SoftwareInventoryState {
    schema_version: u32,
    generated_unix: u64,
    entries: Vec<InstalledSoftware>,
}

pub struct ProtectedJsonInventoryStore {
    path: PathBuf,
}

impl ProtectedJsonInventoryStore {
    pub fn new_default() -> Self {
        Self::from_path(crate::config::data_dir().join(SOFTWARE_INVENTORY_FILE))
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl InventoryStore for ProtectedJsonInventoryStore {
    fn replace_inventory(&self, entries: &[InstalledSoftware]) -> Result<(), String> {
        let state = SoftwareInventoryState {
            schema_version: SOFTWARE_INVENTORY_SCHEMA_VERSION,
            generated_unix: chrono::Utc::now().timestamp().max(0) as u64,
            entries: entries.to_vec(),
        };
        crate::security::policy::save_struct_with_integrity(self.path(), &state).map_err(|e| {
            format!(
                "failed to persist protected software inventory {}: {e}",
                self.path().display()
            )
        })
    }

    fn load_inventory(&self) -> Result<Vec<InstalledSoftware>, String> {
        let loaded: Option<SoftwareInventoryState> =
            crate::security::policy::load_struct_with_integrity(self.path()).map_err(|e| {
                format!(
                    "failed to load protected software inventory {}: {e}",
                    self.path().display()
                )
            })?;
        let Some(state) = loaded else {
            return Ok(Vec::new());
        };
        if state.schema_version != SOFTWARE_INVENTORY_SCHEMA_VERSION {
            return Err(format!(
                "unsupported software inventory schema {} in {}",
                state.schema_version,
                self.path().display()
            ));
        }
        Ok(state.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_inventory_store() -> (ProtectedJsonInventoryStore, PathBuf) {
        let unique = format!(
            "vigil-storage-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        (
            ProtectedJsonInventoryStore::from_path(dir.join(SOFTWARE_INVENTORY_FILE)),
            dir,
        )
    }

    #[test]
    fn protected_store_round_trip() {
        let (store, dir) = test_inventory_store();
        let rows = vec![InstalledSoftware {
            product_key: "curl".into(),
            display_name: "curl".into(),
            executable_path: "/usr/bin/curl".into(),
            publisher_hint: Some("curl project".into()),
            version_hint: Some("8.8.0".into()),
            source: crate::software_inventory::InventorySource::RunningProcess,
        }];
        store.replace_inventory(&rows).unwrap();
        let loaded = store.load_inventory().unwrap();
        assert!(loaded.iter().any(|r| r.product_key == "curl"));
        assert_eq!(loaded[0].publisher_hint.as_deref(), Some("curl project"));
        assert_eq!(loaded[0].version_hint.as_deref(), Some("8.8.0"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
