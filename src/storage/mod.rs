use crate::software_inventory::InstalledSoftware;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
        Self {
            path: crate::config::data_dir().join(SOFTWARE_INVENTORY_FILE),
        }
    }
}

impl InventoryStore for ProtectedJsonInventoryStore {
    fn replace_inventory(&self, entries: &[InstalledSoftware]) -> Result<(), String> {
        let state = SoftwareInventoryState {
            schema_version: SOFTWARE_INVENTORY_SCHEMA_VERSION,
            generated_unix: chrono::Utc::now().timestamp().max(0) as u64,
            entries: entries.to_vec(),
        };
        crate::security::policy::save_struct_with_integrity(&self.path, &state).map_err(|e| {
            format!(
                "failed to persist protected software inventory {}: {e}",
                self.path.display()
            )
        })
    }

    fn load_inventory(&self) -> Result<Vec<InstalledSoftware>, String> {
        let loaded: Option<SoftwareInventoryState> =
            crate::security::policy::load_struct_with_integrity(&self.path).map_err(|e| {
                format!(
                    "failed to load protected software inventory {}: {e}",
                    self.path.display()
                )
            })?;
        let Some(state) = loaded else {
            return Ok(Vec::new());
        };
        if state.schema_version != SOFTWARE_INVENTORY_SCHEMA_VERSION {
            return Err(format!(
                "unsupported software inventory schema {} in {}",
                state.schema_version,
                self.path.display()
            ));
        }
        Ok(state.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_store_round_trip() {
        let store = ProtectedJsonInventoryStore::new_default();
        let rows = vec![InstalledSoftware {
            product_key: "curl".into(),
            display_name: "curl".into(),
            executable_path: "/usr/bin/curl".into(),
            publisher_hint: None,
            source: crate::software_inventory::InventorySource::RunningProcess,
        }];
        store.replace_inventory(&rows).unwrap();
        let loaded = store.load_inventory().unwrap();
        assert!(loaded.iter().any(|r| r.product_key == "curl"));
    }
}
