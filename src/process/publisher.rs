//! Windows-only: extract selected PE version-resource strings.
//! Results are cached for the lifetime of the process.

use dashmap::DashMap;
use std::sync::OnceLock;

static PUBLISHER_CACHE: OnceLock<DashMap<String, String>> = OnceLock::new();
static VERSION_CACHE: OnceLock<DashMap<String, String>> = OnceLock::new();

fn publisher_cache() -> &'static DashMap<String, String> {
    PUBLISHER_CACHE.get_or_init(DashMap::new)
}

fn version_cache() -> &'static DashMap<String, String> {
    VERSION_CACHE.get_or_init(DashMap::new)
}

/// Return the `CompanyName` string from the PE version info of `path`.
/// Returns an empty string if unavailable, inaccessible, or not on Windows.
pub fn get_publisher(path: &str) -> String {
    cached_lookup(path, publisher_cache(), query_publisher)
}

/// Return the `ProductVersion` or `FileVersion` string from the PE version
/// info of `path`. Returns an empty string if unavailable, inaccessible, or
/// not on Windows.
pub fn get_file_version(path: &str) -> String {
    cached_lookup(path, version_cache(), query_file_version)
}

fn cached_lookup(
    path: &str,
    cache: &'static DashMap<String, String>,
    query: fn(&str) -> String,
) -> String {
    if path.is_empty() {
        return String::new();
    }

    if let Some(value) = cache.get(path) {
        return value.clone();
    }

    let result = query(path);
    cache.insert(path.to_string(), result.clone());
    result
}

// -- Windows implementation -------------------------------------------------

#[cfg(windows)]
fn query_publisher(path: &str) -> String {
    query_string_file_info(path, &["CompanyName"])
}

#[cfg(windows)]
fn query_file_version(path: &str) -> String {
    query_string_file_info(path, &["ProductVersion", "FileVersion"])
}

#[cfg(windows)]
fn query_string_file_info(path: &str, value_names: &[&str]) -> String {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    };

    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let pcwstr = PCWSTR(wide.as_ptr());

    unsafe {
        let size = GetFileVersionInfoSizeW(pcwstr, None);
        if size == 0 {
            return String::new();
        }

        let mut buf: Vec<u8> = vec![0u8; size as usize];
        if GetFileVersionInfoW(
            pcwstr,
            Some(0),
            size,
            buf.as_mut_ptr() as *mut _,
        )
        .is_err()
        {
            return String::new();
        }

        for value_name in value_names {
            let sub_block = format!("\\StringFileInfo\\040904B0\\{}", value_name);
            let sub_block: Vec<u16> = OsStr::new(&sub_block)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut p_val: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut p_len: u32 = 0;

            if VerQueryValueW(
                buf.as_ptr() as *const _,
                PCWSTR(sub_block.as_ptr()),
                &mut p_val,
                &mut p_len,
            )
            .as_bool()
                && p_len > 1
            {
                let chars = std::slice::from_raw_parts(
                    p_val as *const u16,
                    (p_len - 1) as usize,
                );
                let value = String::from_utf16_lossy(chars).trim().to_string();
                if !value.is_empty() {
                    return value;
                }
            }
        }
    }

    String::new()
}

#[cfg(not(windows))]
fn query_publisher(_path: &str) -> String {
    String::new()
}

#[cfg(not(windows))]
fn query_file_version(_path: &str) -> String {
    String::new()
}
