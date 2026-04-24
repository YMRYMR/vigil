//! IP reputation via user-supplied plain-text blocklists.
//!
//! This is the "offline reputation" half of Phase 10.  Active online lookups
//! (AbuseIPDB, Shodan, VirusTotal) are deferred — they require API keys and
//! a network round-trip per check.  A static blocklist is almost as useful:
//! users can subscribe to community feeds (FireHOL, Emerging Threats,
//! AbuseIPDB daily dumps) and drop them into `%LOCALAPPDATA%\Vigil\blocklists\`
//! then list the paths in `blocklist_paths` in `vigil.json`.
//!
//! ## File format
//! - One IP (v4 or v6) or CIDR per line.
//! - `#` to end-of-line is a comment.
//! - Blank lines are ignored.
//!
//! Example `abuseipdb.txt`:
//! ```text
//! # Compiled 2026-04-14 from AbuseIPDB top reports
//! 185.220.101.0/24   # Tor exit nodes
//! 45.141.84.15       # Known C2
//! 2001:db8::/32      # Research net
//! ```

use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::path::Path;
use std::sync::RwLock;

// ── One loaded list ──────────────────────────────────────────────────────────

struct Blocklist {
    /// File stem shown in alerts (e.g. "abuseipdb").
    name: String,
    /// Exact-match IPs (fast path).
    ips: std::collections::HashSet<IpAddr>,
    /// CIDR networks (linear scan; usually small).
    nets: Vec<IpNetwork>,
}

impl Blocklist {
    fn load(path: &Path) -> Option<Self> {
        #[cfg(not(test))]
        let _observation = crate::security::operator_provenance::observe_operator_file(
            "blocklist",
            path,
        );
        let raw = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to read blocklist {}: {e}", path.display());
                return None;
            }
        };

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("blocklist")
            .to_string();

        let mut ips = std::collections::HashSet::new();
        let mut nets = Vec::new();

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
            } else {
                match line.parse::<IpAddr>() {
                    Ok(a) => {
                        ips.insert(a);
                    }
                    Err(e) => {
                        tracing::warn!("{}:{}: bad IP '{line}': {e}", path.display(), lineno + 1)
                    }
                }
            }
        }

        tracing::info!(
            "loaded blocklist '{name}': {} IPs, {} CIDRs from {}",
            ips.len(),
            nets.len(),
            path.display()
        );
        Some(Self { name, ips, nets })
    }

    fn matches(&self, ip: &IpAddr) -> bool {
        if self.ips.contains(ip) {
            return true;
        }
        self.nets.iter().any(|n| n.contains(*ip))
    }
}

// ── Engine ───────────────────────────────────────────────────────────────────

#[derive(Default)]
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

    /// Check `ip` against every loaded list. Returns the name of the first
    /// matching list, or `None` if no list contains the IP.
    pub fn lookup(&self, ip: &str) -> Option<String> {
        let addr: IpAddr = ip.parse().ok()?;
        for bl in &self.lists {
            if bl.matches(&addr) {
                return Some(bl.name.clone());
            }
        }
        None
    }

    pub fn total_entries(&self) -> usize {
        self.lists.iter().map(|l| l.ips.len() + l.nets.len()).sum()
    }

    pub fn list_count(&self) -> usize {
        self.lists.len()
    }
}

// ── Global singleton ─────────────────────────────────────────────────────────

static ENGINE: RwLock<Option<BlocklistEngine>> = RwLock::new(None);

pub fn init(paths: &[String]) {
    let eng = BlocklistEngine::load(paths);
    *ENGINE.write().unwrap() = Some(eng);
}

pub fn lookup(ip: &str) -> Option<String> {
    ENGINE.read().unwrap().as_ref().and_then(|e| e.lookup(ip))
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
    use std::io::Write;

    fn mktmp(content: &str, name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("vigil_bl_test_{}_{}.txt", std::process::id(), name));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    }

    #[test]
    fn exact_match() {
        let p = mktmp("185.220.101.1\n1.2.3.4\n", "exact");
        let eng = BlocklistEngine::load(&[p.to_string_lossy().into_owned()]);
        assert!(eng.lookup("1.2.3.4").is_some());
        assert!(eng.lookup("185.220.101.1").is_some());
        assert!(eng.lookup("8.8.8.8").is_none());
    }

    #[test]
    fn cidr_match() {
        let p = mktmp("10.0.0.0/8\n", "cidr");
        let eng = BlocklistEngine::load(&[p.to_string_lossy().into_owned()]);
        assert!(eng.lookup("10.1.2.3").is_some());
        assert!(eng.lookup("11.1.2.3").is_none());
    }

    #[test]
    fn comments_and_blanks_ok() {
        let p = mktmp("# comment\n\n 1.1.1.1 # trailing\n", "cmt");
        let eng = BlocklistEngine::load(&[p.to_string_lossy().into_owned()]);
        assert!(eng.lookup("1.1.1.1").is_some());
    }

    #[test]
    fn source_name_is_file_stem() {
        let p = mktmp("1.2.3.4\n", "source");
        let eng = BlocklistEngine::load(&[p.to_string_lossy().into_owned()]);
        let hit = eng.lookup("1.2.3.4").unwrap();
        // Stem is something like "vigil_bl_test_<pid>_source"
        assert!(hit.contains("source"));
    }
}
