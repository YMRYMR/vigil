use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSource {
    Default,
    DebianPackage,
    RpmPackage,
    AlpinePackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionScheme {
    Unknown,
    SemverLike,
    Debian,
    Rpm,
    AlpineApk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VersionRange<'a> {
    pub exact: Option<&'a str>,
    pub start_including: Option<&'a str>,
    pub start_excluding: Option<&'a str>,
    pub end_including: Option<&'a str>,
    pub end_excluding: Option<&'a str>,
}

impl<'a> VersionRange<'a> {
    pub fn is_empty(&self) -> bool {
        self.exact.is_none()
            && self.start_including.is_none()
            && self.start_excluding.is_none()
            && self.end_including.is_none()
            && self.end_excluding.is_none()
    }
}

pub fn detect_version_scheme(installed_version: &str, source: VersionSource) -> VersionScheme {
    match source {
        VersionSource::DebianPackage => VersionScheme::Debian,
        VersionSource::RpmPackage => VersionScheme::Rpm,
        VersionSource::AlpinePackage => VersionScheme::AlpineApk,
        VersionSource::Default => detect_default_scheme(installed_version),
    }
}

pub fn version_in_range(
    installed_version: &str,
    range: VersionRange<'_>,
    source: VersionSource,
) -> Option<bool> {
    let installed_version = installed_version.trim();
    if installed_version.is_empty() {
        return None;
    }

    let scheme = detect_version_scheme(installed_version, source);
    if matches!(scheme, VersionScheme::Unknown) {
        return None;
    }

    if let Some(exact) = range.exact.filter(|value| !value.trim().is_empty()) {
        return compare_versions(installed_version, exact, scheme)
            .map(|ordering| ordering == Ordering::Equal);
    }

    if range.is_empty() {
        return None;
    }

    if let Some(start_including) = range
        .start_including
        .filter(|value| !value.trim().is_empty())
    {
        if compare_versions(installed_version, start_including, scheme)? == Ordering::Less {
            return Some(false);
        }
    }
    if let Some(start_excluding) = range
        .start_excluding
        .filter(|value| !value.trim().is_empty())
    {
        let ordering = compare_versions(installed_version, start_excluding, scheme)?;
        if matches!(ordering, Ordering::Less | Ordering::Equal) {
            return Some(false);
        }
    }
    if let Some(end_including) = range.end_including.filter(|value| !value.trim().is_empty()) {
        if compare_versions(installed_version, end_including, scheme)? == Ordering::Greater {
            return Some(false);
        }
    }
    if let Some(end_excluding) = range.end_excluding.filter(|value| !value.trim().is_empty()) {
        let ordering = compare_versions(installed_version, end_excluding, scheme)?;
        if matches!(ordering, Ordering::Greater | Ordering::Equal) {
            return Some(false);
        }
    }

    Some(true)
}

pub fn compare_versions(left: &str, right: &str, scheme: VersionScheme) -> Option<Ordering> {
    let left = left.trim();
    let right = right.trim();
    if left.is_empty() || right.is_empty() {
        return None;
    }

    Some(match scheme {
        VersionScheme::Unknown => return None,
        VersionScheme::SemverLike => compare_semver_like(left, right),
        VersionScheme::Debian => compare_debian(left, right),
        VersionScheme::Rpm => compare_rpm(left, right),
        VersionScheme::AlpineApk => compare_alpine_apk(left, right),
    })
}

pub fn extract_cpe23_version(cpe: &str) -> Option<&str> {
    let mut parts = cpe.split(':');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("cpe"), Some("2.3"), Some(_), Some(_), Some(_), Some(version)) => {
            let version = version.trim();
            if version.is_empty() || matches!(version, "*" | "-") {
                None
            } else {
                Some(version)
            }
        }
        _ => None,
    }
}

fn detect_default_scheme(installed_version: &str) -> VersionScheme {
    let installed_version = installed_version.trim();
    if installed_version.is_empty() {
        return VersionScheme::Unknown;
    }

    if looks_like_semver(installed_version) {
        return VersionScheme::SemverLike;
    }

    if installed_version
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '+' | '~'))
        && installed_version.chars().any(|ch| ch.is_ascii_digit())
    {
        return VersionScheme::SemverLike;
    }

    VersionScheme::Unknown
}

fn looks_like_semver(value: &str) -> bool {
    let trimmed = value.trim_start_matches(['v', 'V']);
    let core = trimmed
        .split_once('+')
        .map(|(core, _)| core)
        .unwrap_or(trimmed);
    let core = core.split_once('-').map(|(core, _)| core).unwrap_or(core);
    let mut saw_digit = false;
    let mut saw_dot = false;
    for ch in core.chars() {
        if ch.is_ascii_digit() {
            saw_digit = true;
        } else if ch == '.' {
            saw_dot = true;
        } else if !ch.is_ascii_alphanumeric() && ch != '_' {
            return false;
        }
    }
    saw_digit && saw_dot
}

fn compare_semver_like(left: &str, right: &str) -> Ordering {
    let left = left.trim_start_matches(['v', 'V']);
    let right = right.trim_start_matches(['v', 'V']);
    let (left_core, left_pre) = split_semver_parts(left);
    let (right_core, right_pre) = split_semver_parts(right);

    let core_ordering = compare_mixed_version(left_core, right_core);
    if core_ordering != Ordering::Equal {
        return core_ordering;
    }

    match (left_pre, right_pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left_pre), Some(right_pre)) => compare_semver_prerelease(left_pre, right_pre),
    }
}

fn split_semver_parts(value: &str) -> (&str, Option<&str>) {
    let without_build = value.split_once('+').map(|(head, _)| head).unwrap_or(value);
    match without_build.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (without_build, None),
    }
}

fn compare_semver_prerelease(left: &str, right: &str) -> Ordering {
    let left_parts: Vec<&str> = left.split('.').filter(|part| !part.is_empty()).collect();
    let right_parts: Vec<&str> = right.split('.').filter(|part| !part.is_empty()).collect();
    let len = left_parts.len().max(right_parts.len());
    for idx in 0..len {
        match (left_parts.get(idx), right_parts.get(idx)) {
            (Some(left_part), Some(right_part)) => {
                let ordering = compare_prerelease_identifier(left_part, right_part);
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => return Ordering::Equal,
        }
    }
    Ordering::Equal
}

fn compare_prerelease_identifier(left: &str, right: &str) -> Ordering {
    match (
        left.chars().all(|ch| ch.is_ascii_digit()),
        right.chars().all(|ch| ch.is_ascii_digit()),
    ) {
        (true, true) => compare_numeric_chunk(left, right),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => compare_mixed_version(left, right),
    }
}

fn compare_debian(left: &str, right: &str) -> Ordering {
    let (left_epoch, left_upstream, left_revision) = parse_debian_version(left);
    let (right_epoch, right_upstream, right_revision) = parse_debian_version(right);

    match left_epoch.cmp(&right_epoch) {
        Ordering::Equal => {}
        ordering => return ordering,
    }

    let upstream_ordering = compare_debian_part(left_upstream, right_upstream);
    if upstream_ordering != Ordering::Equal {
        return upstream_ordering;
    }

    compare_debian_part(left_revision.unwrap_or("0"), right_revision.unwrap_or("0"))
}

fn parse_debian_version(value: &str) -> (u64, &str, Option<&str>) {
    let (epoch, remainder) = match value.split_once(':') {
        Some((epoch, remainder)) => (epoch.trim().parse::<u64>().unwrap_or(0), remainder),
        None => (0, value),
    };
    let (upstream, revision) = match remainder.rsplit_once('-') {
        Some((upstream, revision)) => (upstream, Some(revision)),
        None => (remainder, None),
    };
    (epoch, upstream, revision)
}

fn compare_debian_part(left: &str, right: &str) -> Ordering {
    let mut left_idx = 0usize;
    let mut right_idx = 0usize;
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();

    while left_idx < left_bytes.len() || right_idx < right_bytes.len() {
        let left_non_digits_end =
            advance_while(left_bytes, left_idx, |byte| !byte.is_ascii_digit());
        let right_non_digits_end =
            advance_while(right_bytes, right_idx, |byte| !byte.is_ascii_digit());
        let ordering = compare_debian_non_digit_part(
            &left[left_idx..left_non_digits_end],
            &right[right_idx..right_non_digits_end],
        );
        if ordering != Ordering::Equal {
            return ordering;
        }
        left_idx = left_non_digits_end;
        right_idx = right_non_digits_end;

        let left_digits_end = advance_while(left_bytes, left_idx, |byte| byte.is_ascii_digit());
        let right_digits_end = advance_while(right_bytes, right_idx, |byte| byte.is_ascii_digit());
        let ordering = compare_numeric_chunk(
            &left[left_idx..left_digits_end],
            &right[right_idx..right_digits_end],
        );
        if ordering != Ordering::Equal {
            return ordering;
        }
        left_idx = left_digits_end;
        right_idx = right_digits_end;
    }

    Ordering::Equal
}

fn compare_debian_non_digit_part(left: &str, right: &str) -> Ordering {
    let mut left_chars = left.chars();
    let mut right_chars = right.chars();
    loop {
        let ordering =
            debian_char_order(left_chars.next()).cmp(&debian_char_order(right_chars.next()));
        if ordering != Ordering::Equal {
            return ordering;
        }
        if left_chars.as_str().is_empty() && right_chars.as_str().is_empty() {
            return Ordering::Equal;
        }
    }
}

fn debian_char_order(ch: Option<char>) -> i32 {
    match ch {
        Some('~') => -1,
        None => 0,
        Some(ch) if ch.is_ascii_alphabetic() => ch.to_ascii_lowercase() as i32,
        Some(ch) => ch as i32 + 256,
    }
}

fn compare_rpm(left: &str, right: &str) -> Ordering {
    let (left_epoch, left_version, left_release) = parse_rpm_evr(left);
    let (right_epoch, right_version, right_release) = parse_rpm_evr(right);

    match left_epoch.cmp(&right_epoch) {
        Ordering::Equal => {}
        ordering => return ordering,
    }

    let version_ordering = compare_rpm_part(left_version, right_version);
    if version_ordering != Ordering::Equal {
        return version_ordering;
    }

    compare_rpm_part(left_release.unwrap_or(""), right_release.unwrap_or(""))
}

fn parse_rpm_evr(value: &str) -> (u64, &str, Option<&str>) {
    let (epoch, remainder) = match value.split_once(':') {
        Some((epoch, remainder)) => (epoch.trim().parse::<u64>().unwrap_or(0), remainder),
        None => (0, value),
    };
    let (version, release) = match remainder.rsplit_once('-') {
        Some((version, release)) => (version, Some(release)),
        None => (remainder, None),
    };
    (epoch, version, release)
}

fn compare_rpm_part(left: &str, right: &str) -> Ordering {
    let mut left = left;
    let mut right = right;

    loop {
        left = skip_rpm_separators(left);
        right = skip_rpm_separators(right);

        match (left.strip_prefix('~'), right.strip_prefix('~')) {
            (Some(rest), Some(other_rest)) => {
                left = rest;
                right = other_rest;
                continue;
            }
            (Some(_), None) => return Ordering::Less,
            (None, Some(_)) => return Ordering::Greater,
            (None, None) => {}
        }

        match (left.strip_prefix('^'), right.strip_prefix('^')) {
            (Some(rest), Some(other_rest)) => {
                left = rest;
                right = other_rest;
                continue;
            }
            (Some(_), None) => {
                return if right.is_empty() {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            (None, Some(_)) => {
                return if left.is_empty() {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            (None, None) => {}
        }

        if left.is_empty() || right.is_empty() {
            return left.is_empty().cmp(&right.is_empty()).reverse();
        }

        let Some((left_is_numeric, left_segment, left_rest)) = next_rpm_segment(left) else {
            return Ordering::Equal;
        };
        let Some((right_is_numeric, right_segment, right_rest)) = next_rpm_segment(right) else {
            return Ordering::Equal;
        };

        let ordering = match (left_is_numeric, right_is_numeric) {
            (true, true) => compare_numeric_chunk(left_segment, right_segment),
            (false, false) => left_segment
                .to_ascii_lowercase()
                .cmp(&right_segment.to_ascii_lowercase()),
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
        };
        if ordering != Ordering::Equal {
            return ordering;
        }

        left = left_rest;
        right = right_rest;
    }
}

fn skip_rpm_separators(value: &str) -> &str {
    value.trim_start_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '~' && ch != '^')
}

fn next_rpm_segment(value: &str) -> Option<(bool, &str, &str)> {
    let mut chars = value.char_indices();
    let (_, first) = chars.next()?;
    let is_numeric = first.is_ascii_digit();
    let mut end = value.len();
    for (idx, ch) in chars {
        if ch.is_ascii_digit() != is_numeric {
            end = idx;
            break;
        }
        if !ch.is_ascii_alphanumeric() {
            end = idx;
            break;
        }
    }
    Some((is_numeric, &value[..end], &value[end..]))
}

fn compare_alpine_apk(left: &str, right: &str) -> Ordering {
    let (left_base, left_revision) = split_apk_revision(left);
    let (right_base, right_revision) = split_apk_revision(right);
    let base_ordering = compare_mixed_version(left_base, right_base);
    if base_ordering != Ordering::Equal {
        return base_ordering;
    }
    left_revision.cmp(&right_revision)
}

fn split_apk_revision(value: &str) -> (&str, u64) {
    match value.rsplit_once("-r") {
        Some((base, revision)) if revision.chars().all(|ch| ch.is_ascii_digit()) => {
            (base, revision.parse::<u64>().unwrap_or(0))
        }
        _ => (value, 0),
    }
}

fn compare_mixed_version(left: &str, right: &str) -> Ordering {
    let left_tokens = tokenize_version(left);
    let right_tokens = tokenize_version(right);
    let len = left_tokens.len().max(right_tokens.len());
    for idx in 0..len {
        match (left_tokens.get(idx), right_tokens.get(idx)) {
            (Some(Token::Number(left)), Some(Token::Number(right))) => {
                let ordering = compare_numeric_chunk(left, right);
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            (Some(Token::Text(left)), Some(Token::Text(right))) => {
                let ordering = left.cmp(right);
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            (Some(Token::Number(_)), Some(Token::Text(_))) => return Ordering::Greater,
            (Some(Token::Text(_)), Some(Token::Number(_))) => return Ordering::Less,
            (Some(left), None) => {
                if !token_is_zeroish(left) {
                    return Ordering::Greater;
                }
            }
            (None, Some(right)) => {
                if !token_is_zeroish(right) {
                    return Ordering::Less;
                }
            }
            (None, None) => return Ordering::Equal,
        }
    }
    Ordering::Equal
}

fn token_is_zeroish(token: &Token<'_>) -> bool {
    match token {
        Token::Number(value) => trim_leading_zeros(value).is_empty(),
        Token::Text(_) => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token<'a> {
    Number(&'a str),
    Text(String),
}

fn tokenize_version(value: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let mut idx = 0usize;
    while idx < value.len() {
        let slice = &value[idx..];
        let mut chars = slice.char_indices();
        let Some((_, first)) = chars.next() else {
            break;
        };
        if !first.is_ascii_alphanumeric() {
            idx += first.len_utf8();
            continue;
        }
        let is_numeric = first.is_ascii_digit();
        let mut end = idx + first.len_utf8();
        for (offset, ch) in chars {
            if !ch.is_ascii_alphanumeric() || ch.is_ascii_digit() != is_numeric {
                break;
            }
            end = idx + offset + ch.len_utf8();
        }
        let token = &value[idx..end];
        if is_numeric {
            tokens.push(Token::Number(token));
        } else {
            tokens.push(Token::Text(token.to_ascii_lowercase()));
        }
        idx = end;
    }
    tokens
}

fn compare_numeric_chunk(left: &str, right: &str) -> Ordering {
    let left = trim_leading_zeros(left);
    let right = trim_leading_zeros(right);
    match left.len().cmp(&right.len()) {
        Ordering::Equal => left.cmp(right),
        ordering => ordering,
    }
}

fn trim_leading_zeros(value: &str) -> &str {
    value.trim_start_matches('0')
}

fn advance_while(bytes: &[u8], start: usize, predicate: impl Fn(u8) -> bool) -> usize {
    let mut idx = start;
    while idx < bytes.len() && predicate(bytes[idx]) {
        idx += 1;
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_scheme_from_source_hint() {
        assert_eq!(
            detect_version_scheme("2:1.0-1", VersionSource::DebianPackage),
            VersionScheme::Debian
        );
        assert_eq!(
            detect_version_scheme("1.2.3-r2", VersionSource::AlpinePackage),
            VersionScheme::AlpineApk
        );
        assert_eq!(
            detect_version_scheme("1.2.3", VersionSource::Default),
            VersionScheme::SemverLike
        );
    }

    #[test]
    fn semver_range_checks_respect_inclusive_and_exclusive_bounds() {
        let range = VersionRange {
            start_including: Some("1.2.0"),
            end_excluding: Some("2.0.0"),
            ..VersionRange::default()
        };
        assert_eq!(
            version_in_range("1.2.0", range, VersionSource::Default),
            Some(true)
        );
        assert_eq!(
            version_in_range("1.9.9", range, VersionSource::Default),
            Some(true)
        );
        assert_eq!(
            version_in_range("2.0.0", range, VersionSource::Default),
            Some(false)
        );
    }

    #[test]
    fn semver_release_beats_prerelease() {
        assert_eq!(
            compare_versions("1.2.3", "1.2.3-rc.1", VersionScheme::SemverLike),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_versions("1.2.3-rc.2", "1.2.3-rc.10", VersionScheme::SemverLike),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn semver_prerelease_hyphen_stays_inside_identifier() {
        assert_eq!(
            compare_versions(
                "1.0.0-a-b",
                "1.0.0-a.b",
                VersionScheme::SemverLike,
            ),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_versions(
                "1.0.0-alpha-beta",
                "1.0.0-alpha-beta",
                VersionScheme::SemverLike,
            ),
            Some(Ordering::Equal)
        );
    }

    #[test]
    fn debian_versions_handle_epoch_and_tilde() {
        assert_eq!(
            compare_versions("1.0~beta1", "1.0", VersionScheme::Debian),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_versions("2:1.0-1", "1:9.9-9", VersionScheme::Debian),
            Some(Ordering::Greater)
        );
    }

    #[test]
    fn rpm_versions_handle_epoch_and_release_segments() {
        assert_eq!(
            compare_versions("1:1.0-2.fc40", "1:1.0-1.fc40", VersionScheme::Rpm),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_versions("0:1.0a-1", "0:1.0b-1", VersionScheme::Rpm),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn rpm_versions_place_caret_snapshots_between_base_and_next_release() {
        assert_eq!(
            compare_versions("2.0^20250611", "2.0", VersionScheme::Rpm),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_versions("2.0^20250611", "2.0.1", VersionScheme::Rpm),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn alpine_versions_compare_revision_suffixes() {
        assert_eq!(
            compare_versions("1.2.3-r10", "1.2.3-r2", VersionScheme::AlpineApk),
            Some(Ordering::Greater)
        );
        assert_eq!(
            version_in_range(
                "1.2.3-r2",
                VersionRange {
                    start_including: Some("1.2.0-r1"),
                    end_excluding: Some("1.2.3-r3"),
                    ..VersionRange::default()
                },
                VersionSource::AlpinePackage
            ),
            Some(true)
        );
    }

    #[test]
    fn exact_match_works_for_cpe_versions() {
        let exact = extract_cpe23_version("cpe:2.3:a:example:agent:2.4.1:*:*:*:*:*:*:*");
        assert_eq!(
            version_in_range(
                "2.4.1",
                VersionRange {
                    exact,
                    ..VersionRange::default()
                },
                VersionSource::Default
            ),
            Some(true)
        );
        assert_eq!(
            version_in_range(
                "2.4.2",
                VersionRange {
                    exact,
                    ..VersionRange::default()
                },
                VersionSource::Default
            ),
            Some(false)
        );
    }

    #[test]
    fn unknown_scheme_stays_conservative() {
        assert_eq!(
            detect_version_scheme("release-candidate", VersionSource::Default),
            VersionScheme::Unknown
        );
        assert_eq!(
            version_in_range(
                "release-candidate",
                VersionRange {
                    exact: Some("release-candidate"),
                    ..VersionRange::default()
                },
                VersionSource::Default
            ),
            None
        );
    }
}
