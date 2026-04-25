#![allow(clippy::collapsible_match)]
//! TLS ClientHello parsing helpers for Phase 12.
//!
//! This module is intentionally dependency-light and conservative. It parses
//! raw TLS record bytes to extract operator-useful metadata such as SNI and the
//! JA3 tuple string. The current branch does not yet have a fully-wired packet
//! source for this on every platform, but this parser provides the hardened
//! building block needed for future TLS depth work.

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientHelloMeta {
    pub server_name: Option<String>,
    pub ja3_string: Option<String>,
    pub tls_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

pub fn parse_client_hello(record: &[u8]) -> Option<ClientHelloMeta> {
    if record.len() < 5 || record[0] != 22 {
        return None;
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() < 5 + record_len {
        return None;
    }
    let body = &record[5..5 + record_len];
    if body.len() < 4 || body[0] != 1 {
        return None;
    }
    let handshake_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    if body.len() < 4 + handshake_len {
        return None;
    }
    let hello = &body[4..4 + handshake_len];
    parse_client_hello_body(hello)
}

fn parse_client_hello_body(hello: &[u8]) -> Option<ClientHelloMeta> {
    if hello.len() < 2 + 32 + 1 {
        return None;
    }
    let mut offset = 0usize;
    let tls_version = read_u16(hello, &mut offset)?;
    offset += 32;

    let session_id_len = *hello.get(offset)? as usize;
    offset += 1 + session_id_len;
    if offset > hello.len() {
        return None;
    }

    let cipher_bytes = read_vec_u16_len(hello, &mut offset)?;
    if cipher_bytes.len() % 2 != 0 {
        return None;
    }
    let mut cipher_suites = Vec::new();
    for chunk in cipher_bytes.chunks_exact(2) {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]);
        if !is_grease_u16(value) {
            cipher_suites.push(value);
        }
    }

    let compression_len = *hello.get(offset)? as usize;
    offset += 1 + compression_len;
    if offset > hello.len() {
        return None;
    }

    let mut meta = ClientHelloMeta {
        tls_version,
        cipher_suites,
        ..Default::default()
    };

    if offset == hello.len() {
        meta.ja3_string = Some(build_ja3(&meta));
        return Some(meta);
    }

    let extensions_blob = read_vec_u16_len(hello, &mut offset)?;
    let mut ext_off = 0usize;
    while ext_off + 4 <= extensions_blob.len() {
        let ext_type = u16::from_be_bytes([extensions_blob[ext_off], extensions_blob[ext_off + 1]]);
        let ext_len =
            u16::from_be_bytes([extensions_blob[ext_off + 2], extensions_blob[ext_off + 3]])
                as usize;
        ext_off += 4;
        if ext_off + ext_len > extensions_blob.len() {
            return None;
        }
        let ext_data = &extensions_blob[ext_off..ext_off + ext_len];
        ext_off += ext_len;

        if !is_grease_u16(ext_type) {
            meta.extensions.push(ext_type);
        }
        match ext_type {
            0 => {
                if meta.server_name.is_none() {
                    meta.server_name = parse_sni_extension(ext_data);
                }
            }
            10 => {
                meta.elliptic_curves = parse_supported_groups(ext_data);
            }
            11 => {
                meta.ec_point_formats = parse_ec_point_formats(ext_data);
            }
            _ => {}
        }
    }

    meta.ja3_string = Some(build_ja3(&meta));
    Some(meta)
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Option<u16> {
    let out = u16::from_be_bytes([*bytes.get(*offset)?, *bytes.get(*offset + 1)?]);
    *offset += 2;
    Some(out)
}

fn read_vec_u16_len<'a>(bytes: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let len = read_u16(bytes, offset)? as usize;
    let start = *offset;
    let end = start.checked_add(len)?;
    let out = bytes.get(start..end)?;
    *offset = end;
    Some(out)
}

fn parse_sni_extension(ext: &[u8]) -> Option<String> {
    if ext.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    if ext.len() < 2 + list_len {
        return None;
    }
    let mut off = 2usize;
    while off + 3 <= 2 + list_len {
        let name_type = ext[off];
        let name_len = u16::from_be_bytes([ext[off + 1], ext[off + 2]]) as usize;
        off += 3;
        let name = ext.get(off..off + name_len)?;
        off += name_len;
        if name_type == 0 {
            let host = std::str::from_utf8(name).ok()?.trim().to_ascii_lowercase();
            if is_valid_sni(&host) {
                return Some(host);
            }
        }
    }
    None
}

fn parse_supported_groups(ext: &[u8]) -> Vec<u16> {
    if ext.len() < 2 {
        return Vec::new();
    }
    let len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    if ext.len() < 2 + len || !len.is_multiple_of(2) {
        return Vec::new();
    }
    ext[2..2 + len]
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .filter(|value| !is_grease_u16(*value))
        .collect()
}

fn parse_ec_point_formats(ext: &[u8]) -> Vec<u8> {
    let Some(len) = ext.first().copied() else {
        return Vec::new();
    };
    let len = len as usize;
    if ext.len() < 1 + len {
        return Vec::new();
    }
    ext[1..1 + len].to_vec()
}

fn build_ja3(meta: &ClientHelloMeta) -> String {
    format!(
        "{},{},{},{},{}",
        meta.tls_version,
        join_u16(&meta.cipher_suites),
        join_u16(&meta.extensions),
        join_u16(&meta.elliptic_curves),
        join_u8(&meta.ec_point_formats)
    )
}

fn join_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn join_u8(values: &[u8]) -> String {
    values
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn is_grease_u16(value: u16) -> bool {
    let hi = (value >> 8) as u8;
    let lo = (value & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

fn is_valid_sni(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_client_hello() -> Vec<u8> {
        vec![
            0x16, 0x03, 0x01, 0x00, 0x45, 0x01, 0x00, 0x00, 0x41, 0x03, 0x03, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02, 0x01, 0x00, 0x00, 0x14, 0x00, 0x00,
            0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            b'.', b'o', b'r', b'g',
        ]
    }

    #[test]
    fn parses_sni_and_ja3_string() {
        let meta = parse_client_hello(&sample_client_hello()).expect("client hello");
        assert_eq!(meta.server_name.as_deref(), Some("example.org"));
        assert_eq!(meta.ja3_string.as_deref(), Some("771,4865-4866,0,,"));
    }

    #[test]
    fn rejects_non_tls_records() {
        assert!(parse_client_hello(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]).is_none());
    }

    #[test]
    fn grease_values_are_excluded_from_ja3() {
        let mut record = sample_client_hello();
        record[46] = 0x0a;
        record[47] = 0x0a;
        let meta = parse_client_hello(&record).expect("client hello");
        assert_eq!(meta.ja3_string.as_deref(), Some("771,4866,0,,"));
    }
}
