// Build script for Vigil.
//
// Platform-agnostic:
//   Uses `assets/vigil_icon.png` when present (preferred shipped icon) and
//   falls back to generating `assets/vigil.png` (256 × 256 RGBA) for installers.
//
// Windows only:
//   Uses `assets/vigil_icon.ico` when present (preferred shipped icon) and
//   falls back to generating `assets/vigil.ico` (16 / 32 / 48 px).
//   The selected .ico is embedded via `winres`.

fn main() {
    // Regenerate resources when script or icon assets change.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/vigil_icon.png");
    println!("cargo:rerun-if-changed=assets/vigil_icon.ico");
    println!("cargo:rerun-if-changed=assets/vigil_tray_green.ico");
    println!("cargo:rerun-if-changed=assets/vigil_tray_orange.ico");
    println!("cargo:rerun-if-changed=assets/vigil_tray_red.ico");
    println!("cargo:rerun-if-changed=assets/vigil.png");
    println!("cargo:rerun-if-changed=assets/vigil.ico");

    std::fs::create_dir_all("assets").expect("failed to create assets/");

    let app_png = std::path::Path::new("assets/vigil_icon.png");
    let legacy_png = std::path::Path::new("assets/vigil.png");
    if !app_png.exists() {
        if legacy_png.exists() {
            std::fs::copy(legacy_png, app_png)
                .expect("failed to copy assets/vigil.png to vigil_icon.png");
        } else {
            write_png("assets/vigil_icon.png", 256, 0x22, 0xC5, 0x5E);
        }
    }
    if !legacy_png.exists() {
        std::fs::copy(app_png, legacy_png).expect("failed to create assets/vigil.png");
    }

    let app_ico = std::path::Path::new("assets/vigil_icon.ico");
    let legacy_ico = std::path::Path::new("assets/vigil.ico");
    if !app_ico.exists() {
        if legacy_ico.exists() {
            std::fs::copy(legacy_ico, app_ico)
                .expect("failed to copy assets/vigil.ico to vigil_icon.ico");
        } else {
            let ico = make_ico(&[16, 32, 48], 0x22, 0xC5, 0x5E);
            std::fs::write(app_ico, &ico).expect("failed to write assets/vigil_icon.ico");
        }
    }
    if !legacy_ico.exists() {
        std::fs::copy(app_ico, legacy_ico).expect("failed to create assets/vigil.ico");
    }

    ensure_tray_ico("assets/vigil_tray_green.ico", 0x22, 0xC5, 0x5E);
    ensure_tray_ico("assets/vigil_tray_orange.ico", 0xF5, 0x9E, 0x0B);
    ensure_tray_ico("assets/vigil_tray_red.ico", 0xEF, 0x44, 0x44);

    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        embed_windows_icon();
    }
}

#[cfg(windows)]
fn embed_windows_icon() {
    // Embed via winres. Requires the Windows SDK (rc.exe) or llvm-rc.
    // Non-fatal: warn but don't abort the build if the toolchain is absent.
    if let Err(e) = winres::WindowsResource::new()
        .set_icon("assets/vigil_icon.ico")
        .compile()
    {
        println!("cargo:warning=winres failed (Windows SDK / llvm-rc not found): {e}");
    }
}

#[cfg(not(windows))]
fn embed_windows_icon() {}

fn ensure_tray_ico(path: &str, r: u8, g: u8, b: u8) {
    if std::path::Path::new(path).exists() {
        return;
    }
    let ico = make_ico(&[16, 32, 48], r, g, b);
    std::fs::write(path, &ico).unwrap_or_else(|e| panic!("failed to write {path}: {e}"));
}

// ── ICO generation ────────────────────────────────────────────────────────────

fn make_ico(sizes: &[u32], r: u8, g: u8, b: u8) -> Vec<u8> {
    let n = sizes.len();
    let images: Vec<Vec<u8>> = sizes.iter().map(|&s| make_image_data(s, r, g, b)).collect();

    // ICONDIR (6 bytes)
    let mut ico = Vec::new();
    ico.extend_from_slice(&0u16.to_le_bytes()); // reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // type = icon
    ico.extend_from_slice(&(n as u16).to_le_bytes()); // count

    // All ICONDIRENTRY records come immediately after ICONDIR.
    // First image data starts after ICONDIR + all ICONDIRENTRYs.
    let header_size = 6u32 + n as u32 * 16;
    let mut offset = header_size;

    for (i, &size) in sizes.iter().enumerate() {
        let img_size = images[i].len() as u32;
        // ICONDIRENTRY (16 bytes)
        ico.push(size as u8); // width  (0 = 256)
        ico.push(size as u8); // height (0 = 256)
        ico.push(0); // color count (0 for 32-bpp)
        ico.push(0); // reserved
        ico.extend_from_slice(&1u16.to_le_bytes()); // planes
        ico.extend_from_slice(&32u16.to_le_bytes()); // bit count
        ico.extend_from_slice(&img_size.to_le_bytes()); // bytes in resource
        ico.extend_from_slice(&offset.to_le_bytes()); // offset from file start
        offset += img_size;
    }

    for img in &images {
        ico.extend_from_slice(img);
    }

    ico
}

/// Build one DIB image entry: BITMAPINFOHEADER + BGRA pixels + AND mask.
fn make_image_data(size: u32, r: u8, g: u8, b: u8) -> Vec<u8> {
    let center = (size as f32 - 1.0) / 2.0;
    let radius = size as f32 * 0.42;

    // Pixel rows stored bottom-to-top (DIB convention).
    let mut bgra = vec![0u8; (size * size * 4) as usize];
    for row in 0..size {
        // `row` = bottom-to-top row index → screen y = (size-1-row)
        let screen_y = size - 1 - row;
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = screen_y as f32 - center;
            let d = (dx * dx + dy * dy).sqrt();
            let idx = ((row * size + x) * 4) as usize;
            if d <= radius {
                bgra[idx] = b; // B
                bgra[idx + 1] = g; // G
                bgra[idx + 2] = r; // R
                bgra[idx + 3] = 255; // A
            }
            // else: transparent (alpha=0, rest zero)
        }
    }

    // AND mask: 1 bit per pixel, rows DWORD-aligned, bottom-to-top.
    // All zeros = opaque (alpha channel carries the real transparency for 32-bpp).
    let mask_row_stride = size.div_ceil(32) * 4;
    let and_mask = vec![0u8; (mask_row_stride * size) as usize];

    // BITMAPINFOHEADER (40 bytes)
    let mut data: Vec<u8> = Vec::with_capacity(40 + bgra.len() + and_mask.len());
    data.extend_from_slice(&40u32.to_le_bytes()); // biSize
    data.extend_from_slice(&(size as i32).to_le_bytes()); // biWidth
    data.extend_from_slice(&((size * 2) as i32).to_le_bytes()); // biHeight (doubled)
    data.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    data.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
    data.extend_from_slice(&0u32.to_le_bytes()); // biCompression (BI_RGB)
    data.extend_from_slice(&0u32.to_le_bytes()); // biSizeImage
    data.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
    data.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
    data.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
    data.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant

    data.extend_from_slice(&bgra);
    data.extend_from_slice(&and_mask);
    data
}

// ── PNG generation ────────────────────────────────────────────────────────────

/// Write a `size × size` RGBA circle PNG to `path`.
/// Used for the macOS .app bundle icon and Linux AppImage icon.
fn write_png(path: &str, size: u32, r: u8, g: u8, b: u8) {
    let center = (size as f32 - 1.0) / 2.0;
    let radius = size as f32 * 0.42;

    // RGBA pixels, top-to-bottom (PNG convention).
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let d = (dx * dx + dy * dy).sqrt();
            let idx = ((y * size + x) * 4) as usize;
            if d <= radius {
                rgba[idx] = r;
                rgba[idx + 1] = g;
                rgba[idx + 2] = b;
                rgba[idx + 3] = 255;
            }
            // else: fully transparent
        }
    }

    let file =
        std::fs::File::create(path).unwrap_or_else(|e| panic!("failed to create {path}: {e}"));
    let mut enc = png::Encoder::new(file, size, size);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    let mut writer = enc
        .write_header()
        .unwrap_or_else(|e| panic!("failed to write PNG header for {path}: {e}"));
    writer
        .write_image_data(&rgba)
        .unwrap_or_else(|e| panic!("failed to write PNG data for {path}: {e}"));
}
