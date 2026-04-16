# Vigil — build recipes
# Requires: https://just.systems

default: build

# Development build (fast, with console window)
build:
    cargo build

# Optimised release build (console hidden on Windows)
release:
    cargo build --release

# Alias kept for backward compat with the roadmap
build-windows: release

# Run the test suite
test:
    cargo test

# Lint (treat warnings as errors, matching CI)
lint:
    cargo clippy -- -D warnings

# Check formatting without modifying files
fmt-check:
    cargo fmt --check

# Apply formatting
fmt:
    cargo fmt

# Install the release binary to %LOCALAPPDATA%\Vigil\ (Windows)
# The app enables autostart on first launch.
[windows]
install: release
    powershell -NoProfile -Command "\
        $dest = \"$env:LOCALAPPDATA\\Vigil\"; \
        New-Item -ItemType Directory -Force -Path $dest | Out-Null; \
        Copy-Item -Force target\\release\\vigil.exe $dest\\vigil.exe; \
        Write-Host 'Installed to' $dest\\vigil.exe"

# Install on Unix (copies to ~/.local/bin)
[unix]
install: release
    install -Dm755 target/release/vigil ~/.local/bin/vigil
    @echo "Installed to ~/.local/bin/vigil"

# ── Native installers ─────────────────────────────────────────────────────────

# Build the Windows setup wizard (.exe) via Inno Setup.
# Output: installer\windows\output\Vigil-Setup-<ver>-x86_64.exe
[windows]
installer-windows: release
    powershell -NoProfile -Command " \
        $ver = (Get-Content Cargo.toml | Select-String '^version').ToString().Split('\"')[1]; \
        $iscc = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'; \
        Copy-Item -Force target\release\vigil.exe installer\windows\vigil.exe; \
        & $iscc /DMyAppVersion=$ver installer\windows\setup.iss; \
        Write-Host ''; \
        Write-Host 'Installer ready:' (Resolve-Path installer\windows\output\*.exe)"

# ── Distribution (cargo-dist) ─────────────────────────────────────────────────
# Requires: cargo install cargo-dist --locked

# Preview what a release would build (dry-run, no compilation)
dist-plan:
    cargo dist plan

# Build installers for the current platform into target/distrib/
dist:
    cargo dist build

# Regenerate .github/workflows/release.yml from [workspace.metadata.dist]
# Run this after changing the dist config in Cargo.toml.
dist-generate:
    cargo dist generate

# ── Housekeeping ──────────────────────────────────────────────────────────────

# Remove build artefacts
clean:
    cargo clean

# Run all CI checks locally
ci: fmt-check lint test
