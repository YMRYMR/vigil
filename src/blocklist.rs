//! IP reputation + domain + hash reputation via user-supplied plain-text blocklists
//! and optionally from advisory-sourced indicators.
//!
//! This is the "offline reputation" half of Phase 10.  Active online lookups
//! (AbuseIPDB, Shodan, VirusTotal) are deferred — they require API keys and
//! a network round-trip per check.  A static blocklist is almost as useful:
//! users can subscribe to community feeds (FireHOL, Emerging Threats,
//! AbuseIPDB daily dumps) and drop them into `%LOCALAPPDATA%\\Vigil\\blocklists\\`
//! then list the paths in `blocklist_paths` in `vigil.json`.
//!
//! ## File format
//! - One entry per line: IP, CIDR, domain, or SHA-256 hash.
//! - `#` to end-of-line is a comment.
//! - Blank lines are ignored.
//! - Required integrity sidecar: place `<blocklist>.sha256` beside the file,
//!   containing a SHA-256 digest in standard `sha256sum` format. Vigil verifies
//!   it before parsing and fails closed if it is missing or mismatched.
//!
//! ## Degraded mode
//! When a blocklist fails integrity verification but a prior good version was
//! loaded, the cached version is served with a warning instead of dropping
//! the blocklist entirely. Call `reload()` to retry all paths.

use crate::security::integrity;
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
#[allow(unused_imports)]
use std::path::PathBuf;
use std::sync::RwLock;

// ── One loaded list ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct Blocklist {
    name: String,
    ips: HashSet<IpAddr>,
    nets: Vec<IpNetwork>,
    domains: HashSet<String>,
    hashes: HashSet<String>,
}

impl Blocklist {
    fn load(path: &Path) -> Option<Self> {
        let raw = match integrity::read_verified_to_string(path, "blocklist") {
            Ok((text, integrity::VerificationStatus::Verified { sidecar })) => {
                #[cfg(not(test))]
                let _observation =
                    crate::security::operator_provenance::observe_operator_file("blocklist", path);
                tracing::info!(
                    "verified blocklist {} with sidecar {}",
                    path.display(),
                    sidecar.display()
                );
                text
            }
            Err(e) => {
                tracing::warn!("refusing blocklist {}: {e}", path.display());
                return None;
            }
        };

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("blocklist")
            .to_string();

        let mut ips = HashSet::new();
        let mut nets = Vec::new();
        let mut domains = HashSet::new();
        let mut hashes = HashSet::new();

        for (lineno, raw_line) in raw.lines().enumerate() {
            let line = match raw_line.find('#') {
                Some(i) => &raw_line[..i],
                None => raw_line,
            }
            .trim();
            if line.is_empty() {
                continue;
            }

            if line.contains('/') {
                match line.parse::<IpNetwork>() {
                    Ok(n) => nets.push(n),
                    Err(e) => {
                        tracing::warn!("{}:{}: bad CIDR '{line}': {e}", path.display(), lineno + 1)
                    }
                }
            } else if let Ok(a) = line.parse::<IpAddr>() {
                ips.insert(a);
            } else if is_hash(line) {
                hashes.insert(line.to_lowercase());
            } else if is_domain(line) {
                domains.insert(line.to_lowercase());
            } else {
                tracing::warn!(
                    "{}:{}: unrecognised entry '{line}'",
                    path.display(),
                    lineno + 1
                )
            }
        }

        tracing::info!(
            "loaded blocklist '{}': {} IPs, {} CIDRs, {} domains, {} hashes from {}",
            name,
            ips.len(),
            nets.len(),
            domains.len(),
            hashes.len(),
            path.display()
        );
        Some(Self {
            name,
            ips,
            nets,
            domains,
            hashes,
        })
    }

    fn matches_ip(&self, ip: &IpAddr) -> bool {
        if self.ips.contains(ip) {
            return true;
        }
        self.nets.iter().any(|n| n.contains(*ip))
    }

    fn matches_domain(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        self.domains.contains(&d)
            || self
                .domains
                .iter()
                .any(|pat| d.ends_with(&format!(".{pat}")))
    }

    fn matches_hash(&self, hash: &str) -> bool {
        self.hashes.contains(&hash.to_lowercase())
    }
}

fn is_hash(s: &str) -> bool {
    let lower = s.as_bytes();
    (lower.len() == 64 || lower.len() == 40 || lower.len() == 32)
        && lower.iter().all(|&b| b.is_ascii_hexdigit())
}

fn is_domain(s: &str) -> bool {
    s.contains('.')
        && !s.contains(':')
        && !s.contains('/')
        && s.chars()
            .all(|c| c.is_ascii() && (c.is_ascii_alphanumeric() || c == '.' || c == '-'))
}

// ── Engine ───────────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct BlocklistEngine {
    lists: Vec<Blocklist>,
}

impl BlocklistEngine {
    pub fn load(paths: &[String]) -> Self {
        let mut lists = Vec::new();
        for p in paths {
            if let Some(bl) = Blocklist::load(Path::new(p)) {
                lists.push(bl);
            }
        }
        Self { lists }
    }

    pub fn lookup(&self, ip: &str) -> Option<String> {
        let addr: IpAddr = ip.parse().ok()?;
        for bl in &self.lists {
            if bl.matches_ip(&addr) {
                return Some(bl.name.clone());
            }
        }
        None
    }

    pub fn lookup_domain(&self, domain: &str) -> Option<String> {
        for bl in &self.lists {
            if bl.matches_domain(domain) {
                return Some(bl.name.clone());
            }
        }
        None
    }

    pub fn lookup_hash(&self, hash: &str) -> Option<String> {
        for bl in &self.lists {
            if bl.matches_hash(hash) {
                return Some(bl.name.clone());
            }
        }
        None
    }

    pub fn add_iocs(
        &mut self,
        source_name: &str,
        ips: Vec<IpAddr>,
        domains: Vec<String>,
        hashes: Vec<String>,
    ) {
        if ips.is_empty() && domains.is_empty() && hashes.is_empty() {
            return;
        }
        self.lists.push(Blocklist {
            name: format!("advisory:{source_name}"),
            ips: ips.into_iter().collect(),
            nets: Vec::new(),
            domains: domains.into_iter().collect(),
            hashes: hashes.into_iter().collect(),
        });
        tracing::info!(
            "added advisory-sourced blocklist 'advisory:{}'",
            source_name
        );
    }

    pub fn total_entries(&self) -> usize {
        self.lists
            .iter()
            .map(|l| l.ips.len() + l.nets.len() + l.domains.len() + l.hashes.len())
            .sum()
    }

    pub fn list_count(&self) -> usize {
        self.lists.len()
    }
}

// ── Global singleton with degraded-mode caching ──────────────────────────────

static ENGINE: RwLock<Option<BlocklistEngine>> = RwLock::new(None);
/// Last-known-good engine, preserved across reload failures for degraded mode.
static DEGRADED_BACKUP: RwLock<Option<BlocklistEngine>> = RwLock::new(None);

pub fn init(paths: &[String]) {
    let eng = BlocklistEngine::load(paths);
    let empty = eng.list_count() == 0;
    if empty {
        if let Ok(backup) = DEGRADED_BACKUP.read() {
            if let Some(prev) = backup.as_ref() {
                tracing::warn!(
                    "all blocklists failed to load; serving previous good state in degraded mode"
                );
                *ENGINE.write().unwrap() = Some(prev.clone());
                return;
            }
        }
    }
    // Save current as backup for future degraded mode.
    if !empty {
        *DEGRADED_BACKUP.write().unwrap() = Some(eng.clone());
    }
    *ENGINE.write().unwrap() = if empty { None } else { Some(eng) };
}

/// Reload all blocklist paths. If all fail, the previous good state is kept.
pub fn reload(paths: &[String]) {
    init(paths);
}

/// Add advisory-sourced IOCs to the in-memory engine.
pub fn add_advisory_iocs(
    source_name: &str,
    ips: Vec<IpAddr>,
    domains: Vec<String>,
    hashes: Vec<String>,
) {
    if let Ok(mut eng) = ENGINE.write() {
        match eng.as_mut() {
            Some(e) => e.add_iocs(source_name, ips, domains, hashes),
            None => {
                let mut e = BlocklistEngine::default();
                e.add_iocs(source_name, ips, domains, hashes);
                *eng = Some(e);
            }
        }
    }
}

pub fn lookup(ip: &str) -> Option<String> {
    ENGINE.read().unwrap().as_ref().and_then(|e| e.lookup(ip))
}

pub fn lookup_domain(domain: &str) -> Option<String> {
    ENGINE
        .read()
        .unwrap()
        .as_ref()
        .and_then(|e| e.lookup_domain(domain))
}

pub fn lookup_hash(hash: &str) -> Option<String> {
    ENGINE
        .read()
        .unwrap()
        .as_ref()
        .and_then(|e| e.lookup_hash(hash))
}

pub fn stats() -> (usize, usize) {
    match ENGINE.read().unwrap().as_ref() {
        Some(e) => (e.list_count(), e.total_entries()),
        None => (0, 0),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;

    fn mktmp(content: &str, name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("vigil_bl_test_{}_{}.txt", std::process::id(), name));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    }

    fn write_sidecar(path: &Path, content: &str) {
        let digest = Sha256::digest(content.as_bytes());
        std::fs::write(
            integrity::sidecar_path(path),
            format!(
                "{}  {}\n",
                hex(&digest),
                path.file_name().unwrap().to_string_lossy()
            ),
        )
        .unwrap();
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    #[test]
    fn exact_match() {
        let content = "185.220.101.1\n1.2.3.4\n";
        let p = mktmp(content, "exact");
        write_sidecar(&p, content);
        let eng = BlocklistEngine::load(&[p.to_string_lossy().into_owned()]);
        assert!(eng.lookup("1.2.3.4").is_some());
        assert!(eng.lookup("185.220.101.1").is_some());
        assert!(eng.lookup("8.8.8.8").is_none());
        let _ = std::fs::remove_file(integrity::sidecar_path(&p));
    }

    #[test]
    fn cidr_match() {
        let content = "10.0.0.0/8\n";
        let p = mktmp(content, "cidr");
        write_sidecar(&p, content);
        let eng = BlocklistEngine::load(&[p.to_string_lossy().into_owned()]);
        assert!(eng.lookup("10.1.2.3").is_some());
        assert!(eng.lookup("11.1.2.3").is_none());
        let _ = std::fs::remove_file(integrity::sidecar_path(&p));
    }

    #[test]
    fn comments_and_blanks_ok() {
        let content = "# comment\n\n 1.1.1.1 # trailing\n";
        let p = mktmp(content, "cmt");
        write_sidecar(&p, content);
        let eng = BlocklistEngine::load(&[p.to_string_lossy().into_owned()]);
        assert!(eng.lookup("1.1.1.1").is_some());
        let _ = std::fs::remove_file(integrity::sidecar_path(&p));
    }

    #[test]
    fn domain_match() {
        let content = "badhost.example.com\nevil.org\n";
        let p = mktmp(content, "domain");
        write_sidecar(&p, content);
        let eng = BlocklistEngine::load(&[p.to_string_lossy().into_owned()]);
        assert!(eng.lookup_domain("badhost.example.com").is_some());
        assert!(eng.lookup_domain("sub.evil.org").is_some());
        assert!(eng.lookup_domain("goodhost.example.com").is_none());
        let _ = std::fs::remove_file(integrity::sidecar_path(&p));
    }

    #[test]
    fn hash_match() {
        let content = "a".repeat(64) + "\n";
        let p = mktmp(&content, "hash");
        write_sidecar(&p, &content);
        let eng = BlocklistEngine::load(&[p.to_string_lossy().into_owned()]);
        assert!(eng.lookup_hash("a".repeat(64).as_str()).is_some());
        let _ = std::fs::remove_file(integrity::sidecar_path(&p));
    }

    #[test]
    fn source_name_is_file_stem() {
        let content = "1.2.3.4\n";
        let p = mktmp(content, "source");
        write_sidecar(&p, content);
        let eng = BlocklistEngine::load(&[p.to_string_lossy().into_owned()]);
        let hit = eng.lookup("1.2.3.4").unwrap();
        assert!(hit.contains("source"));
        let _ = std::fs::remove_file(integrity::sidecar_path(&p));
    }

    #[test]
    fn bad_sidecar_rejects_blocklist() {
        let p = mktmp("203.0.113.5\n", "tampered");
        write_sidecar(&p, "198.51.100.9\n");
        let eng = BlocklistEngine::load(&[p.to_string_lossy().into_owned()]);
        assert_eq!(eng.list_count(), 0);
        assert!(eng.lookup("203.0.113.5").is_none());
        let _ = std::fs::remove_file(integrity::sidecar_path(&p));
    }

    #[test]
    fn missing_sidecar_rejects_blocklist() {
        let p = mktmp("203.0.113.6\n", "unsigned");
        let eng = BlocklistEngine::load(&[p.to_string_lossy().into_owned()]);
        assert_eq!(eng.list_count(), 0);
        assert!(eng.lookup("203.0.113.6").is_none());
    }

    #[test]
    fn ioc_addition_works() {
        let mut eng = BlocklistEngine::default();
        eng.add_iocs(
            "test-source",
            vec!["10.0.0.1".parse().unwrap()],
            vec!["malware.example".into()],
            vec!["a".repeat(64)],
        );
        assert_eq!(eng.list_count(), 1);
        assert!(eng.lookup("10.0.0.1").is_some());
        assert!(eng.lookup_domain("malware.example").is_some());
        assert!(eng.lookup_hash(&"a".repeat(64)).is_some());
    }
}
