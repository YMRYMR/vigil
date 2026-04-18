//! Best-effort TLS metadata extraction from captured packet artifacts.
//!
//! This is a conservative post-capture enrichment path for Phase 12. When Vigil
//! writes a `.pcapng` alert artifact, we scan the capture for a TLS ClientHello
//! headed to the alerted remote endpoint and extract SNI / JA3 metadata into a
//! small JSON sidecar next to the packet capture.

use crate::{tls, types::ConnInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsArtifactMeta {
    pub remote_ip: String,
    pub remote_port: u16,
    pub tls_sni: Option<String>,
    pub tls_ja3: Option<String>,
    pub tls_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

#[derive(Debug, Clone)]
struct CachedTlsMeta {
    observed_unix: u64,
    meta: TlsArtifactMeta,
}

const CACHE_TTL_SECS: u64 = 6 * 60 * 60;

pub fn analyze_capture(info: &ConnInfo, pcapng: &Path) -> Result<Option<PathBuf>, String> {
    let Some((remote_ip, remote_port)) = parse_remote_endpoint(&info.remote_addr) else {
        return Ok(None);
    };
    let bytes = std::fs::read(pcapng)
        .map_err(|e| format!("failed to read {}: {e}", pcapng.display()))?;
    let Some(meta) = extract_client_hello(&bytes, remote_ip, remote_port) else {
        return Ok(None);
    };

    remember(meta.clone());
    let sidecar = sidecar_path(pcapng);
    let json = serde_json::to_string_pretty(&meta)
        .map_err(|e| format!("failed to serialize TLS metadata: {e}"))?;
    std::fs::write(&sidecar, json)
        .map_err(|e| format!("failed to write {}: {e}", sidecar.display()))?;
    Ok(Some(sidecar))
}

pub fn lookup_remote(remote_ip: &str, remote_port: u16) -> Option<TlsArtifactMeta> {
    let cache = cache();
    let mut guard = cache.lock().ok()?;
    prune_stale_locked(&mut guard);
    let key = cache_key(remote_ip, remote_port);
    guard.get(&key).map(|entry| entry.meta.clone())
}

fn remember(meta: TlsArtifactMeta) {
    let cache = cache();
    if let Ok(mut guard) = cache.lock() {
        prune_stale_locked(&mut guard);
        let key = cache_key(&meta.remote_ip, meta.remote_port);
        guard.insert(
            key,
            CachedTlsMeta {
                observed_unix: unix_now(),
                meta,
            },
        );
    }
}

fn cache() -> &'static Mutex<HashMap<String, CachedTlsMeta>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedTlsMeta>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn prune_stale_locked(cache: &mut HashMap<String, CachedTlsMeta>) {
    let now = unix_now();
    cache.retain(|_, entry| now.saturating_sub(entry.observed_unix) <= CACHE_TTL_SECS);
}

fn cache_key(remote_ip: &str, remote_port: u16) -> String {
    format!("{}:{}", remote_ip.trim().to_ascii_lowercase(), remote_port)
}

fn sidecar_path(pcapng: &Path) -> PathBuf {
    let stem = pcapng
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("capture");
    pcapng.with_file_name(format!("{stem}.tls.json"))
}

fn parse_remote_endpoint(remote: &str) -> Option<(IpAddr, u16)> {
    let remote = remote.trim();
    let (ip, port) = remote.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let ip = ip.parse::<IpAddr>().ok()?;
    Some((ip, port))
}

fn extract_client_hello(bytes: &[u8], remote_ip: IpAddr, remote_port: u16) -> Option<TlsArtifactMeta> {
    let mut off = 0usize;
    let mut little_endian = true;
    let mut linktype = 1u16;

    while off + 12 <= bytes.len() {
        let block_type = read_u32_le(bytes, off)?;
        let block_len = read_u32_le(bytes, off + 4)? as usize;
        if block_len < 12 || off + block_len > bytes.len() {
            return None;
        }
        match block_type {
            0x0A0D0D0A => {
                if block_len < 28 {
                    return None;
                }
                let bom = &bytes[off + 8..off + 12];
                little_endian = bom == [0x4D, 0x3C, 0x2B, 0x1A];
                if !(little_endian || bom == [0x1A, 0x2B, 0x3C, 0x4D]) {
                    return None;
                }
            }
            0x00000001 => {
                if block_len >= 20 {
                    linktype = if little_endian {
                        u16::from_le_bytes([bytes[off + 8], bytes[off + 9]])
                    } else {
                        u16::from_be_bytes([bytes[off + 8], bytes[off + 9]])
                    };
                }
            }
            0x00000006 if linktype == 1 => {
                let cap_len = read_u32(bytes, off + 20, little_endian)? as usize;
                let packet_off = off + 28;
                if packet_off + cap_len <= off + block_len {
                    let packet = &bytes[packet_off..packet_off + cap_len];
                    if let Some(meta) = parse_ethernet_packet(packet, remote_ip, remote_port) {
                        return Some(meta);
                    }
                }
            }
            _ => {}
        }
        off += block_len;
    }
    None
}

fn parse_ethernet_packet(packet: &[u8], remote_ip: IpAddr, remote_port: u16) -> Option<TlsArtifactMeta> {
    if packet.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
    match ethertype {
        0x0800 => parse_ipv4_packet(&packet[14..], remote_ip, remote_port),
        0x86DD => parse_ipv6_packet(&packet[14..], remote_ip, remote_port),
        _ => None,
    }
}

fn parse_ipv4_packet(packet: &[u8], remote_ip: IpAddr, remote_port: u16) -> Option<TlsArtifactMeta> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if version != 4 || packet.len() < ihl || packet[9] != 6 {
        return None;
    }
    let dst = IpAddr::V4(std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));
    if dst != remote_ip {
        return None;
    }
    parse_tcp_segment(&packet[ihl..], remote_port, remote_ip)
}

fn parse_ipv6_packet(packet: &[u8], remote_ip: IpAddr, remote_port: u16) -> Option<TlsArtifactMeta> {
    if packet.len() < 40 || (packet[0] >> 4) != 6 {
        return None;
    }
    if packet[6] != 6 {
        return None;
    }
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&packet[24..40]);
    let dst = IpAddr::V6(std::net::Ipv6Addr::from(dst));
    if dst != remote_ip {
        return None;
    }
    parse_tcp_segment(&packet[40..], remote_port, remote_ip)
}

fn parse_tcp_segment(segment: &[u8], remote_port: u16, remote_ip: IpAddr) -> Option<TlsArtifactMeta> {
    if segment.len() < 20 {
        return None;
    }
    let dst_port = u16::from_be_bytes([segment[2], segment[3]]);
    if dst_port != remote_port {
        return None;
    }
    let data_offset = ((segment[12] >> 4) as usize) * 4;
    if segment.len() < data_offset || data_offset < 20 {
        return None;
    }
    let payload = &segment[data_offset..];
    let hello = tls::parse_client_hello(payload)?;
    Some(TlsArtifactMeta {
        remote_ip: remote_ip.to_string(),
        remote_port,
        tls_sni: hello.server_name,
        tls_ja3: hello.ja3_string,
        tls_version: hello.tls_version,
        cipher_suites: hello.cipher_suites,
        extensions: hello.extensions,
        elliptic_curves: hello.elliptic_curves,
        ec_point_formats: hello.ec_point_formats,
    })
}

fn read_u32(bytes: &[u8], off: usize, little_endian: bool) -> Option<u32> {
    let raw = bytes.get(off..off + 4)?;
    Some(if little_endian {
        u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
    } else {
        u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]])
    })
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let raw = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pcapng() -> Vec<u8> {
        let packet: Vec<u8> = vec![
            0,1,2,3,4,5, 6,7,8,9,10,11, 0x08,0x00,
            0x45,0x00,0x00,0x71,0x00,0x00,0x40,0x00,0x40,0x06,0x00,0x00,
            192,0,2,10, 93,184,216,34,
            0xC3,0x50, 0x01,0xBB, 0,0,0,1, 0,0,0,0, 0x50,0x18, 0x20,0x00, 0,0, 0,0,
            0x16,0x03,0x01,0x00,0x43,
            0x01,0x00,0x00,0x3f,
            0x03,0x03,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0x00,
            0x00,0x04, 0x13,0x01, 0x13,0x02,
            0x01, 0x00,
            0x00,0x12,
            0x00,0x00, 0x00,0x10,
            0x00,0x0e,
            0x00,
            0x00,0x0b,
            b'e',b'x',b'a',b'm',b'p',b'l',b'e',b'.',b'o',b'r',b'g'
        ];
        let cap_len = packet.len() as u32;
        let padded = ((packet.len() + 3) / 4) * 4;
        let block_len = (28 + padded + 4) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
        out.extend_from_slice(&28u32.to_le_bytes());
        out.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
        out.extend_from_slice(&28u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&20u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&20u32.to_le_bytes());
        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(&block_len.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&cap_len.to_le_bytes());
        out.extend_from_slice(&cap_len.to_le_bytes());
        out.extend_from_slice(&packet);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(&block_len.to_le_bytes());
        out
    }

    #[test]
    fn extracts_tls_metadata_for_matching_remote() {
        let meta = extract_client_hello(&sample_pcapng(), "93.184.216.34".parse().unwrap(), 443)
            .expect("tls meta");
        assert_eq!(meta.tls_sni.as_deref(), Some("example.org"));
        assert_eq!(meta.tls_ja3.as_deref(), Some("771,4865-4866,0,,"));
    }

    #[test]
    fn remembered_tls_metadata_is_reusable() {
        let meta = extract_client_hello(&sample_pcapng(), "93.184.216.34".parse().unwrap(), 443)
            .expect("tls meta");
        remember(meta);
        let cached = lookup_remote("93.184.216.34", 443).expect("cached meta");
        assert_eq!(cached.tls_sni.as_deref(), Some("example.org"));
    }
}
