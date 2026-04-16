//! MaxMind GeoLite2 offline lookup (City + ASN).
//!
//! Vigil does not ship the MaxMind databases — users must download them
//! from https://www.maxmind.com/en/geolite2/signup (free with a registered
//! account) and point `geoip_city_db` / `geoip_asn_db` in `vigil.json` at
//! the `.mmdb` files.
//!
//! When either path is empty or the file is missing / corrupt, the lookup
//! silently returns empty results — nothing in Vigil fails.
//!
//! All lookups are pure disk reads (no network I/O) and take a few µs.

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;
use std::sync::RwLock;

// ── Result type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct GeoInfo {
    /// ISO-3166-1 alpha-2 country code, uppercase (e.g. "US").
    pub country: Option<String>,
    /// Autonomous System Number.
    pub asn: Option<u32>,
    /// AS organisation name (e.g. "Google LLC").
    pub asn_org: Option<String>,
}

impl GeoInfo {
    pub fn is_empty(&self) -> bool {
        self.country.is_none() && self.asn.is_none() && self.asn_org.is_none()
    }
}

// ── Engine ───────────────────────────────────────────────────────────────────

/// Loaded MaxMind readers. Thread-safe (maxminddb's `Reader` is `Send + Sync`
/// when the backing data is `Vec<u8>`).
pub struct GeoEngine {
    city: Option<Reader<Vec<u8>>>,
    asn:  Option<Reader<Vec<u8>>>,
}

impl GeoEngine {
    pub fn load(city_path: &str, asn_path: &str) -> Self {
        let city = open(city_path, "city");
        let asn  = open(asn_path,  "asn");
        Self { city, asn }
    }

    pub fn is_loaded(&self) -> bool {
        self.city.is_some() || self.asn.is_some()
    }

    /// Look up `ip` in the loaded databases. Returns an empty `GeoInfo` when
    /// nothing is known (no DB loaded, private IP, or not in the DB).
    pub fn lookup(&self, ip: &str) -> GeoInfo {
        let Ok(addr): Result<IpAddr, _> = ip.parse() else {
            return GeoInfo::default();
        };
        if is_private_ip(&addr) {
            return GeoInfo::default();
        }

        let mut info = GeoInfo::default();

        if let Some(r) = &self.city {
            if let Ok(rec) = r.lookup::<geoip2::City>(addr) {
                info.country = rec.country
                    .and_then(|c| c.iso_code)
                    .map(|s| s.to_uppercase());
            }
        }
        if let Some(r) = &self.asn {
            if let Ok(rec) = r.lookup::<geoip2::Asn>(addr) {
                info.asn = rec.autonomous_system_number;
                info.asn_org = rec.autonomous_system_organization.map(|s| s.to_string());
            }
        }
        info
    }
}

fn open(path: &str, label: &str) -> Option<Reader<Vec<u8>>> {
    if path.is_empty() {
        return None;
    }
    if !Path::new(path).exists() {
        tracing::warn!("GeoIP {label} database not found: {path}");
        return None;
    }
    match Reader::open_readfile(path) {
        Ok(r) => {
            tracing::info!("loaded GeoIP {label} database: {path}");
            Some(r)
        }
        Err(e) => {
            tracing::warn!("failed to open GeoIP {label} database {path}: {e}");
            None
        }
    }
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
                || v4.is_broadcast() || v4.is_unspecified() || v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified()
                // ULA fc00::/7 and link-local fe80::/10
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

// ── Global singleton ─────────────────────────────────────────────────────────

static ENGINE: RwLock<Option<GeoEngine>> = RwLock::new(None);

/// Load the engine once at startup. Safe to call multiple times (later calls
/// replace the engine — useful after the user updates the DB paths in the
/// Settings UI).
pub fn init(city_path: &str, asn_path: &str) {
    let eng = GeoEngine::load(city_path, asn_path);
    *ENGINE.write().unwrap() = Some(eng);
}

/// Lookup helper over the global engine. Returns empty `GeoInfo` when no
/// engine is loaded.
pub fn lookup(ip: &str) -> GeoInfo {
    match ENGINE.read().unwrap().as_ref() {
        Some(eng) => eng.lookup(ip),
        None => GeoInfo::default(),
    }
}

pub fn is_loaded() -> bool {
    ENGINE.read().unwrap().as_ref().map(|e| e.is_loaded()).unwrap_or(false)
}
