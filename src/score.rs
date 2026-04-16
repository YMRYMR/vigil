//! Connection risk scorer.
//!
//! `score()` is a pure function — no I/O, no side effects.
//! It maps a connection snapshot + config → (risk_score, reasons).
//!
//! Point values (do not change without updating Help tab text):
//!   +5  known malware port
//!   +4  living-off-the-land binary (LOLBin)
//!   +3  no executable path on disk  (possible injection)
//!   +3  executable running from a suspicious directory
//!   +3  suspicious parent process (Office → shell, etc.)
//!   +2  process not in trusted list
//!   +2  no publisher / unsigned binary making an external connection
//!   +1  unusual destination port (not in common_ports) for untrusted process

use crate::config::Config;

// ── Input ─────────────────────────────────────────────────────────────────────

/// Everything the scorer needs from one connection snapshot.
pub struct ScoreInput<'a> {
    /// Process name: **lowercase, `.exe` suffix already stripped**.
    pub name: &'a str,
    /// Full path to the executable. Empty string if unknown / inaccessible.
    pub path: &'a str,
    /// Publisher (company name from PE version info). Empty if unavailable.
    pub publisher: &'a str,
    /// Remote IP address string. Empty when status == LISTEN.
    pub remote_ip: &'a str,
    /// Remote port. 0 when status == LISTEN.
    pub remote_port: u16,
    /// Connection status string.
    pub status: &'a str,
    /// Ancestor chain: [(name_lowercase_no_ext, pid), …] from parent to root.
    pub ancestors: &'a [(String, u32)],
}

// ── Suspicious parent rules ───────────────────────────────────────────────────

/// Office / document apps that should never spawn network-active shells.
const SUSPICIOUS_PARENTS: &[(&str, &[&str])] = &[
    // Office apps spawning any shell / scripting engine
    ("winword",    &["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "wmic", "regsvr32", "rundll32"]),
    ("excel",      &["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "wmic", "regsvr32", "rundll32"]),
    ("powerpnt",   &["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta"]),
    ("outlook",    &["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta"]),
    ("onenote",    &["cmd", "powershell", "pwsh", "wscript", "cscript"]),
    // PDF / browser spawning shells
    ("acrord32",   &["cmd", "powershell", "pwsh", "wscript", "cscript"]),
    ("acrobat",    &["cmd", "powershell", "pwsh", "wscript", "cscript"]),
    // Shells spawning shells (lateral movement)
    ("cmd",        &["powershell", "pwsh"]),
    ("powershell", &["cmd", "pwsh"]),
    // WMI provider host spawning shells (common malware vector)
    ("wmiprvse",   &["cmd", "powershell", "pwsh", "wscript", "cscript"]),
    // Task scheduler spawning unusual children
    ("taskeng",    &["cmd", "powershell", "pwsh", "wscript"]),
    ("schtasks",   &["cmd", "powershell", "pwsh", "wscript"]),
];

// ── Scorer ────────────────────────────────────────────────────────────────────

/// Score a connection. Returns `(score, reasons)`.
pub fn score(input: &ScoreInput<'_>, cfg: &Config) -> (u8, Vec<String>) {
    // ── Early exits ───────────────────────────────────────────────────────────

    if input.remote_ip.is_empty() && input.status == "LISTEN" {
        return (0, vec![]);
    }
    const LOOPBACK: &[&str] = &["127.0.0.1", "::1", "0.0.0.0", ""];
    if LOOPBACK.contains(&input.remote_ip) {
        return (0, vec![]);
    }

    // ── Build lookup sets ─────────────────────────────────────────────────────
    let trusted: std::collections::HashSet<String> =
        cfg.trusted_processes.iter().map(|s| s.to_lowercase()).collect();
    let lolbins: std::collections::HashSet<String> =
        cfg.lolbins.iter().map(|s| s.to_lowercase()).collect();
    let common_ports: std::collections::HashSet<u16> =
        cfg.common_ports.iter().copied().collect();
    let malware_ports: std::collections::HashSet<u16> =
        cfg.malware_ports.iter().copied().collect();

    let is_trusted = trusted.contains(input.name);

    let mut s: u8 = 0;
    let mut reasons: Vec<String> = Vec::new();

    // +3  No executable path (possible process injection / hollowing)
    const SAFE_NO_PATH: &[&str] = &["system", "kernel", "registry"];
    if input.path.is_empty() && !SAFE_NO_PATH.contains(&input.name) {
        s = s.saturating_add(3);
        reasons.push("No executable path (possible process injection / hollowing)".into());
    }

    // +3  Running from a suspicious directory
    if !input.path.is_empty() {
        let path_upper = input.path.to_uppercase();
        for frag in &cfg.suspicious_path_fragments {
            if path_upper.contains(&frag.to_uppercase()) {
                s = s.saturating_add(3);
                reasons.push(format!("Running from suspicious path: {}", input.path));
                break;
            }
        }
    }

    // +4  Living-off-the-land binary making a network connection
    if lolbins.contains(input.name) {
        s = s.saturating_add(4);
        reasons.push(format!(
            "System binary making network connection: {} (living-off-the-land)",
            input.name
        ));
    }

    // +3  Suspicious parent/grandparent process
    // Walk the ancestor chain and check for known-bad parent → child combos.
    for (parent_name_lc, _pid) in input.ancestors.iter() {
        let parent_key = crate::config::normalise_name(parent_name_lc);
        for (bad_parent, bad_children) in SUSPICIOUS_PARENTS {
            if parent_key == *bad_parent && bad_children.contains(&input.name) {
                s = s.saturating_add(3);
                reasons.push(format!(
                    "Suspicious parent process: {} spawned {}",
                    parent_name_lc, input.name,
                ));
                break;
            }
        }
    }

    // +5 / +1  Port-based scoring
    if input.remote_port > 0 {
        if malware_ports.contains(&input.remote_port) {
            s = s.saturating_add(5);
            reasons.push(format!(
                "Connection to known malware/C2 port {}",
                input.remote_port
            ));
        } else if !common_ports.contains(&input.remote_port) && !is_trusted {
            s = s.saturating_add(1);
            reasons.push(format!("Unusual destination port {}", input.remote_port));
        }
    }

    // +2  Unrecognised / unsigned process with external connection
    if !is_trusted {
        s = s.saturating_add(2);
        reasons.push(format!("Unrecognised process: {}", input.name));

        // +2  No publisher (unsigned or stripped binary) — extra signal for
        //     unknown processes; trusted processes are assumed legitimate.
        if input.publisher.is_empty() && !input.path.is_empty() {
            s = s.saturating_add(2);
            reasons.push("Unsigned binary (no publisher information)".into());
        }
    }

    (s, reasons)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg() -> Config { Config::default() }

    fn input<'a>(
        name: &'a str,
        path: &'a str,
        remote_ip: &'a str,
        remote_port: u16,
        status: &'a str,
    ) -> ScoreInput<'a> {
        ScoreInput {
            name, path, publisher: "", remote_ip, remote_port, status,
            ancestors: &[],
        }
    }

    #[test]
    fn listen_no_remote_is_zero() {
        let (s, r) = score(&input("vigil", "", "", 0, "LISTEN"), &cfg());
        assert_eq!(s, 0); assert!(r.is_empty());
    }

    #[test]
    fn loopback_127_is_zero() {
        let (s, _) = score(&input("unknown", "/bin/unknown", "127.0.0.1", 8080, "ESTABLISHED"), &cfg());
        assert_eq!(s, 0);
    }

    #[test]
    fn loopback_ipv6_is_zero() {
        let (s, _) = score(&input("unknown", "/bin/unknown", "::1", 9000, "ESTABLISHED"), &cfg());
        assert_eq!(s, 0);
    }

    #[test]
    fn no_path_adds_three() {
        let (s, r) = score(&input("strangething", "", "1.2.3.4", 443, "ESTABLISHED"), &cfg());
        // +3 no path  +2 untrusted  +2 unsigned(skip — path empty)  (port 443 common)
        assert_eq!(s, 5);
        assert!(r.iter().any(|r| r.contains("injection")));
    }

    #[test]
    fn system_with_no_path_is_not_penalised() {
        let (s, _) = score(&input("system", "", "1.2.3.4", 443, "ESTABLISHED"), &cfg());
        assert_eq!(s, 0); // system is trusted
    }

    #[test]
    fn suspicious_path_adds_three() {
        let (s, r) = score(
            &input("myapp", r"C:\Users\raul\AppData\Roaming\myapp.exe", "8.8.8.8", 443, "ESTABLISHED"),
            &cfg(),
        );
        // +3 path  +2 untrusted  +2 unsigned  (port 443 common)
        assert_eq!(s, 7);
        assert!(r.iter().any(|r| r.contains("suspicious path")));
    }

    #[test]
    fn lolbin_adds_four() {
        let (s, r) = score(
            &ScoreInput {
                name: "powershell",
                path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                publisher: "Microsoft Corporation",
                remote_ip: "93.184.216.34",
                remote_port: 443,
                status: "ESTABLISHED",
                ancestors: &[],
            },
            &cfg(),
        );
        // +4 lolbin  +2 untrusted  (publisher set, port 443 common)
        assert_eq!(s, 6);
        assert!(r.iter().any(|r| r.contains("living-off-the-land")));
    }

    #[test]
    fn malware_port_adds_five() {
        let (s, r) = score(
            &input("badthing", r"C:\Windows\Temp\badthing.exe", "198.51.100.1", 4444, "ESTABLISHED"),
            &cfg(),
        );
        // +3 suspicious path  +5 malware port  +2 untrusted  +2 unsigned
        assert_eq!(s, 12);
        assert!(r.iter().any(|r| r.contains("malware")));
    }

    #[test]
    fn suspicious_parent_adds_three() {
        let ancestors = vec![("winword".to_string(), 1000u32)];
        let (s, r) = score(
            &ScoreInput {
                name: "powershell",
                path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                publisher: "Microsoft Corporation",
                remote_ip: "1.2.3.4",
                remote_port: 443,
                status: "ESTABLISHED",
                ancestors: &ancestors,
            },
            &cfg(),
        );
        // +4 lolbin  +3 suspicious parent  +2 untrusted
        assert_eq!(s, 9);
        assert!(r.iter().any(|r| r.contains("winword")));
    }

    #[test]
    fn trusted_on_common_port_is_zero() {
        let (s, _) = score(
            &input("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                   "142.250.80.46", 443, "ESTABLISHED"),
            &cfg(),
        );
        assert_eq!(s, 0);
    }

    #[test]
    fn unsigned_untrusted_gets_extra_penalty() {
        let (s, r) = score(
            &ScoreInput {
                name: "unknownapp",
                path: r"C:\Program Files\UnknownApp\app.exe",
                publisher: "",
                remote_ip: "10.10.10.1",
                remote_port: 443,
                status: "ESTABLISHED",
                ancestors: &[],
            },
            &cfg(),
        );
        // +2 untrusted  +2 unsigned  (port 443 common)
        assert_eq!(s, 4);
        assert!(r.iter().any(|r| r.contains("Unsigned")));
    }
}
