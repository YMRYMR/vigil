//! Windows-only: extract the CompanyName from a PE file's version resources.
//! Results are cached for the lifetime of the process.

use dashmap::DashMap;
use std::sync::OnceLock;

static CACHE: OnceLock<DashMap<String, String>> = OnceLock::new();

fn cache() -> &'static DashMap<String, String> {
    CACHE.get_or_init(DashMap::new)
}

/// Return the `CompanyName` string from the PE version info of `path`.
/// Returns an empty string if unavailable, inaccessible, or not on Windows.
pub fn get_publisher(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    // Fast path: cached
    if let Some(v) = cache().get(path) {
        return v.clone();
    }

    let result = query_publisher(path);
    cache().insert(path.to_string(), result.clone());
    result
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(windows)]
fn query_publisher(path: &str) -> String {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    };

    // Encode path as wide string
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let pcwstr = PCWSTR(wide.as_ptr());

    unsafe {
        // 1. Get size of version info block
        let size = GetFileVersionInfoSizeW(pcwstr, None);
        if size == 0 {
            return String::new();
        }

        // 2. Read version info block
        let mut buf: Vec<u8> = vec![0u8; size as usize];
        if GetFileVersionInfoW(pcwstr, Some(0), size, buf.as_mut_ptr() as *mut _).is_err() {
            return String::new();
        }

        // 3. Query CompanyName (English/Unicode codepage 040904B0)
        let sub_block: Vec<u16> = OsStr::new("\\StringFileInfo\\040904B0\\CompanyName")
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
            // p_val points into buf; p_len includes the null terminator
            let chars = std::slice::from_raw_parts(p_val as *const u16, (p_len - 1) as usize);
            return String::from_utf16_lossy(chars).trim().to_string();
        }
    }

    String::new()
}

#[cfg(not(windows))]
fn query_publisher(_path: &str) -> String {
    String::new()
}
