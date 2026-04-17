//! Shannon entropy for DGA (Domain Generation Algorithm) detection.
//!
//! Malware families such as Necurs, Mirai variants, and Conficker generate
//! random-looking domain names on a schedule to defeat static blocklists.
//! Humans pick memorable names (`google.com`, `mybank-online.co`), machines
//! pick high-entropy strings (`xj4k8s9q.com`).
//!
//! We compute Shannon entropy over the **leftmost label** of a hostname and
//! flag labels whose entropy exceeds a configurable threshold
//! (`dga_entropy_threshold`, default 3.2 bits/char).  Note that Shannon
//! entropy is bounded by `log2(unique_chars_in_label)`, so the ceiling for a
//! 10-char label with 10 distinct chars is only ~3.32 bits.  Real DGA samples
//! typically score 3.3–3.9; real brand names score 2.0–3.0.
//!
//! ## Caveats
//! - Real brand names like `paypal` or `microsoft` score well under the
//!   threshold; randomised CDN prefixes (`a1b2c3.cloudfront.net`) do not.
//!   We only score the leftmost label, so `xj4k8s9q.example.com` is flagged
//!   but `www.xj4k8s9q.example.com` is not — that's intentional; attackers
//!   rarely bother with a `www` prefix for their DGA domains.
//! - Labels shorter than 7 characters are exempt (too little signal).
//! - IP-address hostnames (no letters) are exempt.

/// Shannon entropy in bits per character over the bytes of `s`.
/// Returns 0.0 for empty input.
pub fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let bytes = s.as_bytes();
    let len = bytes.len() as f32;
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let mut h = 0.0f32;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f32 / len;
        h -= p * p.log2();
    }
    h
}

/// Returns `true` when the leftmost label of `hostname` has entropy ≥ `threshold`.
/// Short labels (< 7 chars) and labels containing no letters return `false`.
pub fn is_dga_like(hostname: &str, threshold: f32) -> bool {
    let label = hostname
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if label.len() < 7 {
        return false;
    }
    if !label.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    shannon_entropy(&label) >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn repeated_char_is_zero() {
        assert_eq!(shannon_entropy("aaaaaa"), 0.0);
    }

    #[test]
    fn english_brands_are_below_threshold() {
        assert!(!is_dga_like("google.com", 3.2));
        assert!(!is_dga_like("paypal.com", 3.2));
        assert!(!is_dga_like("microsoft.com", 3.2));
        assert!(!is_dga_like("mybank.co.uk", 3.2));
    }

    #[test]
    fn random_looking_is_above_threshold() {
        assert!(is_dga_like("xj4k8s9qzr.com", 3.2));
        assert!(is_dga_like("a1b2c3d4e5f6g7h8.net", 3.2));
    }

    #[test]
    fn short_labels_are_exempt() {
        // Even if entropy is high, a 5-letter label is too short to judge.
        assert!(!is_dga_like("xj4k.com", 3.2));
    }

    #[test]
    fn ip_literal_is_exempt() {
        assert!(!is_dga_like("192.168.0.1", 3.0));
    }
}
