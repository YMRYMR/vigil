pub mod db;

use crate::software_inventory::InstalledSoftware;
pub trait InventoryStore {
    fn replace_inventory(&self, entries: &[InstalledSoftware]) -> Result<(), String>;
    fn load_inventory(&self) -> Result<Vec<InstalledSoftware>, String>;
}

pub struct DbInventoryStore;

impl DbInventoryStore {
    pub fn new() -> Self {
        Self
    }
}

impl InventoryStore for DbInventoryStore {
    fn replace_inventory(&self, entries: &[InstalledSoftware]) -> Result<(), String> {
        let db = crate::storage::db::StorageDb::open()?;
        db.replace_software_inventory(entries)?;
        db.checkpoint()?;
        Ok(())
    }

    fn load_inventory(&self) -> Result<Vec<InstalledSoftware>, String> {
        let db = crate::storage::db::StorageDb::open()?;
        db.load_software_inventory()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::software_inventory::{InstalledSoftware, InventorySource};

    #[test]
    fn protected_store_round_trip() {
        let store = DbInventoryStore::new();
        let rows = vec![InstalledSoftware {
            product_key: "curl".into(),
            display_name: "curl".into(),
            executable_path: "/usr/bin/curl".into(),
            publisher_hint: Some("curl project".into()),
            version_hint: Some("8.8.0".into()),
            product_aliases: vec!["curl".into()],
            vendor_key: Some("curl-project".into()),
            source: InventorySource::RunningProcess,
        }];
        store.replace_inventory(&rows).unwrap();
        let loaded = store.load_inventory().unwrap();
        assert!(loaded.iter().any(|r| r.product_key == "curl"));
        assert_eq!(loaded[0].publisher_hint.as_deref(), Some("curl project"));
        assert_eq!(loaded[0].version_hint.as_deref(), Some("8.8.0"));
        assert_eq!(loaded[0].product_aliases, vec!["curl".to_string()]);
        assert_eq!(loaded[0].vendor_key.as_deref(), Some("curl-project"));
    }
}
