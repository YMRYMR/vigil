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
//!   +3  beaconing pattern detected (C2 callback timing signature)
//!   +3  IP matched a user-supplied reputation blocklist (Phase 10)
//!   +3  executable was dropped into a watched dir just before connecting (Phase 10)
//!   +2  process not in trusted list
//!   +2  no publisher / unsigned binary making an external connection
//!   +2  DNS query from a non-DNS process (possible DNS tunneling)
//!   +2  connection observed before any interactive user login (boot-time
//!        persistence — classic rootkit / dropper signal)
//!   +2  connection to an unexpected country (Phase 10, requires allowed_countries)
//!   +2  long-lived connection past threshold for untrusted process (Phase 10)
//!   +2  hostname looks DGA-generated (high Shannon entropy) (Phase 10)
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
    /// `true` when the beacon detector has identified a regular C2-style callback
    /// pattern for this `(pid, remote_ip)` pair.
    pub beaconing: bool,
    /// `true` when no interactive user session is active — i.e. the event
    /// was captured by Vigil running as a boot-time service / daemon before
    /// anyone logged in.
    pub pre_login: bool,

    // ── Phase 10 inputs ──────────────────────────────────────────────────────
    /// Name of the matching blocklist file (stem), or `None` if no match.
    pub reputation_hit: Option<&'a str>,
    /// ISO country code for the remote IP, uppercase (e.g. "US"), when known.
    pub country: Option<&'a str>,
    /// Reverse-DNS hostname for the remote IP, when resolved.
    pub hostname: Option<&'a str>,
    /// `true` when the executable at `path` was dropped into a watched dir
    /// within the configured correlation window.
    pub recently_dropped: bool,
    /// `true` when the connection has been open past the long-lived threshold.
    pub long_lived: bool,
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
    //
    // Two exceptions:
    //   * Legitimate kernel-side "processes" that never have a disk image
    //     (System, kernel, Registry).
    //   * Ghost rows where sysinfo couldn't resolve the PID at all — the
    //     name looks like "<1234>".  These already get a visible marker in
    //     the UI and we don't want to double-count the lack-of-path.
    const SAFE_NO_PATH: &[&str] = &["system", "kernel", "registry"];
    let is_ghost = input.name.starts_with('<') && input.name.ends_with('>');
    if input.path.is_empty()
        && !SAFE_NO_PATH.contains(&input.name)
        && !is_ghost
    {
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

    // +3  Beaconing pattern (regular C2 callback intervals)
    if input.beaconing {
        s = s.saturating_add(3);
        reasons.push(
            "Beaconing pattern detected (regular C2 callback timing signature)".into(),
        );
    }

    // +2  Pre-login / boot-time activity
    // Connections observed before any interactive user has logged in are a
    // classic rootkit / dropper callback signal.
    if input.pre_login {
        s = s.saturating_add(2);
        reasons.push(
            "Connection observed before user login (boot-time persistence)".into(),
        );
    }

    // ── Phase 10 rules ───────────────────────────────────────────────────────

    // +3  IP reputation hit
    if let Some(src) = input.reputation_hit {
        s = s.saturating_add(3);
        reasons.push(format!("Reputation hit: {} is in blocklist '{}'", input.remote_ip, src));
    }

    // +3  Executable dropped into a watched dir right before connecting
    if input.recently_dropped {
        s = s.saturating_add(3);
        reasons.push(
            "Executable was just dropped into a watched directory (possible dropper)".into(),
        );
    }

    // +2  Unexpected country (only when allowed_countries is non-empty)
    if let Some(country) = input.country {
        if !cfg.allowed_countries.is_empty()
            && !cfg.allowed_countries.iter().any(|a| a.eq_ignore_ascii_case(country))
        {
            s = s.saturating_add(2);
            reasons.push(format!("Connection to unexpected country: {country}"));
        }
    }

    // +2  Long-lived connection from an untrusted process
    if input.long_lived && !is_trusted {
        s = s.saturating_add(2);
        reasons.push(format!(
            "Long-lived connection held open past {}s by untrusted process",
            cfg.long_lived_secs,
        ));
    }

    // +2  DGA-like hostname (Shannon entropy over leftmost label)
    if let Some(host) = input.hostname {
        if !host.is_empty()
            && crate::entropy::is_dga_like(host, cfg.dga_entropy_threshold)
        {
            s = s.saturating_add(2);
            reasons.push(format!("Hostname looks DGA-generated: {host}"));
        }
    }

    // +2  DNS query from a non-DNS process (possible DNS tunneling / exfiltration)
    // System DNS resolvers are exempt; anything else querying port 53 is suspicious.
    const DNS_NATIVE: &[&str] = &[
        "svchost", "dnscache", "dns", "systemd-resolved",
        "resolved", "named", "unbound", "dnsmasq",
    ];
    if input.remote_port == 53
        && !DNS_NATIVE.contains(&input.name)
        && !is_trusted
    {
        s = s.saturating_add(2);
        reasons.push(format!(
            "DNS query from non-DNS process: {} (possible DNS tunneling)",
            input.name
        ));
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
            ancestors: &[], beaconing: false, pre_login: false,
            reputation_hit: None, country: None, hostname: None,
            recently_dropped: false, long_lived: false,
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
                beaconing: false,
                pre_login: false,
                reputation_hit: None, country: None, hostname: None,
                recently_dropped: false, long_lived: false,
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
                beaconing: false,
                pre_login: false,
                reputation_hit: None, country: None, hostname: None,
                recently_dropped: false, long_lived: false,
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
                beaconing: false,
                pre_login: false,
                reputation_hit: None, country: None, hostname: None,
                recently_dropped: false, long_lived: false,
            },
            &cfg(),
        );
        // +2 untrusted  +2 unsigned  (port 443 common)
        assert_eq!(s, 4);
        assert!(r.iter().any(|r| r.contains("Unsigned")));
    }

    #[test]
    fn beaconing_adds_three() {
        let (s, r) = score(
            &ScoreInput {
                name: "updater",
                path: r"C:\Program Files\SomeApp\updater.exe",
                publisher: "",
                remote_ip: "203.0.113.10",
                remote_port: 443,
                status: "ESTABLISHED",
                ancestors: &[],
                beaconing: true,
                pre_login: false,
                reputation_hit: None, country: None, hostname: None,
                recently_dropped: false, long_lived: false,
            },
            &cfg(),
        );
        // +3 beaconing  +2 untrusted  +2 unsigned  (port 443 common)
        assert_eq!(s, 7);
        assert!(r.iter().any(|r| r.contains("Beaconing")));
    }

    #[test]
    fn dns_query_from_untrusted_process_adds_two() {
        let (s, r) = score(
            &input("strangething", r"C:\Temp\strangething.exe", "8.8.8.8", 53, "ESTABLISHED"),
            &cfg(),
        );
        // +3 suspicious path  +2 untrusted  +2 unsigned  +2 DNS tunneling
        assert_eq!(s, 9);
        assert!(r.iter().any(|r| r.contains("DNS tunneling")));
    }

    #[test]
    fn ghost_pid_row_skips_no_path_penalty() {
        // ETW fired before sysinfo could resolve the process — name is "<12345>".
        // Without the fix we'd stack the "+3 no path" penalty on top of the
        // other signals and score these ghost rows at 6 even though we already
        // know the lack of info is a sysinfo race, not process hollowing.
        let (s, r) = score(&input("<12345>", "", "1.2.3.4", 443, "ESTABLISHED"), &cfg());
        // +2 untrusted  (port 443 common, path empty skips unsigned rule)
        assert_eq!(s, 2);
        assert!(!r.iter().any(|r| r.contains("injection")));
    }

    #[test]
    fn pre_login_adds_two() {
        let (s, r) = score(
            &ScoreInput {
                name: "chrome",
                path: r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                publisher: "Google LLC",
                remote_ip: "142.250.80.46",
                remote_port: 443,
                status: "ESTABLISHED",
                ancestors: &[],
                beaconing: false,
                pre_login: true,
                reputation_hit: None, country: None, hostname: None,
                recently_dropped: false, long_lived: false,
            },
            &cfg(),
        );
        // Chrome is trusted (no +2), port 443 common, but pre_login adds +2
        assert_eq!(s, 2);
        assert!(r.iter().any(|r| r.contains("before user login")));
    }

    // ── Phase 10 tests ───────────────────────────────────────────────────────

    #[test]
    fn reputation_hit_adds_three() {
        let mut inp = input("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                            "45.141.84.15", 443, "ESTABLISHED");
        inp.reputation_hit = Some("abuseipdb");
        let (s, r) = score(&inp, &cfg());
        // chrome trusted, port 443 common, +3 blocklist
        assert_eq!(s, 3);
        assert!(r.iter().any(|r| r.contains("abuseipdb")));
    }

    #[test]
    fn unexpected_country_adds_two_when_allowlist_set() {
        let mut cfg = cfg();
        cfg.allowed_countries = vec!["US".into(), "GB".into()];
        let mut inp = input("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                            "1.2.3.4", 443, "ESTABLISHED");
        inp.country = Some("RU");
        let (s, r) = score(&inp, &cfg);
        assert_eq!(s, 2);
        assert!(r.iter().any(|r| r.contains("unexpected country")));
    }

    #[test]
    fn allowed_country_does_not_score() {
        let mut cfg = cfg();
        cfg.allowed_countries = vec!["US".into()];
        let mut inp = input("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                            "1.2.3.4", 443, "ESTABLISHED");
        inp.country = Some("US");
        let (s, _) = score(&inp, &cfg);
        assert_eq!(s, 0);
    }

    #[test]
    fn empty_allowlist_skips_country_rule() {
        let mut inp = input("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                            "1.2.3.4", 443, "ESTABLISHED");
        inp.country = Some("RU");
        let (s, _) = score(&inp, &cfg());
        assert_eq!(s, 0);
    }

    #[test]
    fn recently_dropped_adds_three() {
        let mut inp = input("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                            "1.2.3.4", 443, "ESTABLISHED");
        inp.recently_dropped = true;
        let (s, r) = score(&inp, &cfg());
        assert_eq!(s, 3);
        assert!(r.iter().any(|r| r.contains("dropped")));
    }

    #[test]
    fn long_lived_adds_two_only_for_untrusted() {
        // Trusted: skipped
        let mut inp = input("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                            "1.2.3.4", 443, "ESTABLISHED");
        inp.long_lived = true;
        let (s, _) = score(&inp, &cfg());
        assert_eq!(s, 0);

        // Untrusted: +2
        let mut inp = input("unknownthing", r"C:\Program Files\Unknown\u.exe",
                            "1.2.3.4", 443, "ESTABLISHED");
        inp.long_lived = true;
        let (s, _) = score(&inp, &cfg());
        // +2 untrusted + 2 unsigned + 2 long-lived
        assert_eq!(s, 6);
    }

    #[test]
    fn dga_hostname_adds_two() {
        let mut inp = input("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                            "1.2.3.4", 443, "ESTABLISHED");
        inp.hostname = Some("xj4k8s9qzr.example.com");
        let (s, r) = score(&inp, &cfg());
        assert_eq!(s, 2);
        assert!(r.iter().any(|r| r.contains("DGA-generated")));
    }

    #[test]
    fn normal_hostname_does_not_score_dga() {
        let mut inp = input("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                            "1.2.3.4", 443, "ESTABLISHED");
        inp.hostname = Some("www.google.com");
        let (s, _) = score(&inp, &cfg());
        assert_eq!(s, 0);
    }

    #[test]
    fn svchost_dns_query_not_penalised() {
        // svchost is trusted, so no DNS tunneling penalty
        let (s, _) = score(
            &input("svchost", r"C:\Windows\System32\svchost.exe", "8.8.8.8", 53, "ESTABLISHED"),
            &cfg(),
        );
        assert_eq!(s, 0); // svchost trusted
    }
}
