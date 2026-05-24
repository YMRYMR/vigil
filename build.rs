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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Deserialize)]
struct ImportedPackMetadata {
    pack_name: String,
    pack_version: String,
    generated_at: String,
    upstream_name: String,
    upstream_source_url: String,
    upstream_reference: String,
    license: String,
    files: Vec<ImportedPackFileMetadata>,
}

#[derive(Debug, Deserialize)]
struct ImportedPackFileMetadata {
    relative_path: String,
    source_path: String,
    source_url: String,
    source_reference: String,
    category: Option<String>,
}

#[derive(Debug, Serialize)]
struct GeneratedPackManifest<'a> {
    schema_version: u32,
    pack_name: &'a str,
    pack_version: &'a str,
    generated_at: &'a str,
    upstream_name: &'a str,
    upstream_source_url: &'a str,
    upstream_reference: &'a str,
    license: &'a str,
    files: Vec<GeneratedPackFileManifest<'a>>,
}

#[derive(Debug, Serialize)]
struct GeneratedPackFileManifest<'a> {
    relative_path: &'a str,
    sha256: String,
    rule_count: usize,
    source_url: &'a str,
    source_reference: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<&'a str>,
}

#[derive(Debug)]
struct EmbeddedPackFile {
    relative_path: String,
    repo_path: String,
}

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
    println!("cargo:rerun-if-changed=third_party/yara/inquest-community-core");

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
    generate_bundled_yara_pack();

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

fn generate_bundled_yara_pack() {
    let pack_root = Path::new("third_party/yara/inquest-community-core");
    let metadata_path = pack_root.join("pack-metadata.json");
    let metadata: ImportedPackMetadata = serde_json::from_str(
        &fs::read_to_string(&metadata_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", metadata_path.display())),
    )
    .unwrap_or_else(|e| panic!("failed to parse {}: {e}", metadata_path.display()));

    assert_non_empty(&metadata.pack_name, "pack_name");
    assert_non_empty(&metadata.pack_version, "pack_version");
    assert_non_empty(&metadata.generated_at, "generated_at");
    assert_non_empty(&metadata.upstream_name, "upstream_name");
    assert_non_empty(&metadata.upstream_source_url, "upstream_source_url");
    assert_non_empty(&metadata.upstream_reference, "upstream_reference");
    assert_non_empty(&metadata.license, "license");
    if metadata.files.is_empty() {
        panic!(
            "{} must list at least one bundled YARA rule file",
            metadata_path.display()
        );
    }

    let mut manifest_files = Vec::with_capacity(metadata.files.len());
    let mut embedded_files = Vec::with_capacity(metadata.files.len());
    for file in &metadata.files {
        assert_non_empty(&file.relative_path, "files[].relative_path");
        assert_non_empty(&file.source_path, "files[].source_path");
        assert_non_empty(&file.source_url, "files[].source_url");
        assert_non_empty(&file.source_reference, "files[].source_reference");
        if let Some(category) = &file.category {
            assert_non_empty(category, "files[].category");
        }
        ensure_normalized_relative_path(&file.relative_path, "files[].relative_path");
        ensure_normalized_relative_path(&file.source_path, "files[].source_path");

        let source_fs_path = pack_root.join(&file.source_path);
        let source_text = fs::read_to_string(&source_fs_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", source_fs_path.display()));
        let rule_count = count_rule_definitions(&source_text);
        if rule_count == 0 {
            panic!(
                "bundled YARA file {} does not contain any rule definitions",
                source_fs_path.display()
            );
        }
        manifest_files.push(GeneratedPackFileManifest {
            relative_path: &file.relative_path,
            sha256: sha256_hex(source_text.as_bytes()),
            rule_count,
            source_url: &file.source_url,
            source_reference: &file.source_reference,
            category: file.category.as_deref(),
        });
        embedded_files.push(EmbeddedPackFile {
            relative_path: file.relative_path.clone(),
            repo_path: normalize_repo_path(&source_fs_path),
        });
    }

    let manifest = GeneratedPackManifest {
        schema_version: 1,
        pack_name: &metadata.pack_name,
        pack_version: &metadata.pack_version,
        generated_at: &metadata.generated_at,
        upstream_name: &metadata.upstream_name,
        upstream_source_url: &metadata.upstream_source_url,
        upstream_reference: &metadata.upstream_reference,
        license: &metadata.license,
        files: manifest_files,
    };

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR missing"));
    fs::write(
        out_dir.join("bundled_yara_pack_manifest.json"),
        serde_json::to_string_pretty(&manifest)
            .expect("failed to serialize generated bundled YARA manifest"),
    )
    .expect("failed to write bundled YARA manifest");
    fs::write(
        out_dir.join("bundled_yara_pack_files.rs"),
        render_embedded_file_index(&embedded_files),
    )
    .expect("failed to write bundled YARA embedded file index");
}

fn render_embedded_file_index(files: &[EmbeddedPackFile]) -> String {
    let mut rendered =
        String::from("const EMBEDDED_BUNDLED_RULE_FILES: &[EmbeddedBundledRuleFile] = &[\n");
    for file in files {
        rendered.push_str(&format!(
            "    EmbeddedBundledRuleFile {{ relative_path: {relative_path:?}, source_text: include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{repo_path}\")) }},\n",
            relative_path = file.relative_path,
            repo_path = file.repo_path,
        ));
    }
    rendered.push_str("];\n");
    rendered
}

fn normalize_repo_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn assert_non_empty(value: &str, field_name: &str) {
    if value.trim().is_empty() {
        panic!("{field_name} must not be empty");
    }
}

fn ensure_normalized_relative_path(path: &str, field_name: &str) {
    if path.trim().is_empty() {
        panic!("{field_name} must not be empty");
    }
    if path.contains('\\') {
        panic!("{field_name} must use slash-separated relative paths: {path}");
    }
    let candidate = Path::new(path);
    for component in candidate.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                panic!("{field_name} must stay normalized and relative: {path}");
            }
        }
    }
}

fn count_rule_definitions(source_text: &str) -> usize {
    source_text
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("rule ")
                || trimmed.starts_with("private rule ")
                || trimmed.starts_with("global rule ")
                || trimmed.starts_with("private global rule ")
                || trimmed.starts_with("global private rule ")
        })
        .count()
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
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
