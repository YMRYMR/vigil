#!/usr/bin/env pwsh
# Vigil VM Integration Test Runner
# Deploys and tests Vigil firewall in the "vigil-linux" VirtualBox VM.
#
# Usage: ./tests/vm_test_runner.ps1 [-NoCleanup] [-SkipBuild]
#
# Prerequisites:
#   - VirtualBox with "vigil-linux" VM (Ubuntu, SSH forwarded to 2222)
#   - SSH key auth or passwordless sudo inside VM
#   - Rust toolchain installed on host for building

param(
    [switch]$NoCleanup,  # Leave VM running after tests
    [switch]$SkipBuild   # Skip cargo build (use existing binary)
)

$ErrorActionPreference = "Stop"
$VBox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$VM = "vigil-linux"
$SSH = "ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost"
$SCP = "scp -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
$BINARY = "target/release/vigil"
$VM_BINARY = "/tmp/vigil"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Vigil VM Integration Test Runner" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

function Step($msg) { Write-Host "--- $msg ---" -ForegroundColor Yellow }

# ── Build ────────────────────────────────────────────────────────────

if (-not $SkipBuild) {
    Step "Building vigil release binary"
    cargo build --release --bin vigil 2>&1 | Select-Object -Last 3
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    Write-Host "  Binary: $BINARY ($((Get-Item $BINARY).Length) bytes)" -ForegroundColor Green
}

# ── Start VM ─────────────────────────────────────────────────────────

Step "Starting VM: $VM"
$state = & $VBox showvminfo $VM --machinereadable | Select-String "VMState="
if ($state -match "running") {
    Write-Host "  VM already running" -ForegroundColor Green
} else {
    & $VBox startvm $VM --type headless 2>&1 | Out-Null
    Write-Host "  Waiting for VM to boot..." -ForegroundColor Cyan
    Start-Sleep -Seconds 10
}

# ── Wait for SSH ─────────────────────────────────────────────────────

Step "Waiting for SSH (port 2222)"
$maxWait = 120
for ($i = 0; $i -lt $maxWait; $i += 2) {
    $result = & ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 root@localhost "echo ok" 2>&1
    if ($result -eq "ok") {
        Write-Host "  SSH ready after ${i}s" -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds 2
}
if ($i -ge $maxWait) { throw "SSH not available after ${maxWait}s" }

# ── Upload binary ────────────────────────────────────────────────────

Step "Uploading vigil binary to VM"
& $SCP $BINARY "root@localhost:$VM_BINARY" 2>&1
if ($LASTEXITCODE -ne 0) { throw "SCP upload failed" }
Invoke-Expression "$SSH 'chmod +x $VM_BINARY'"
Write-Host "  Binary uploaded to $VM_BINARY" -ForegroundColor Green

# ── Upload test script ───────────────────────────────────────────────

Step "Uploading test scripts"
$testScript = "tests/firewall_integration_test.sh"
$cliTestScript = "tests/firewall_cli_smoke_test.sh"
& $SCP $testScript "root@localhost:/tmp/firewall_integration_test.sh" 2>&1
& $SCP $cliTestScript "root@localhost:/tmp/firewall_cli_smoke_test.sh" 2>&1

# ── Run CLI smoke test ───────────────────────────────────────────────

Step "Running CLI smoke test (no root)"
$result = Invoke-Expression "$SSH 'VIGIL_BINARY=$VM_BINARY bash /tmp/firewall_cli_smoke_test.sh'" 2>&1
Write-Host $result
if ($LASTEXITCODE -ne 0) { Write-Host "  CLI smoke test FAILED" -ForegroundColor Red }

# ── Run integration test ─────────────────────────────────────────────

Step "Running firewall integration test (root)"
$result = Invoke-Expression "$SSH 'VIGIL_BINARY=$VM_BINARY bash /tmp/firewall_integration_test.sh'" 2>&1
Write-Host $result
if ($LASTEXITCODE -ne 0) { Write-Host "  Integration test FAILED" -ForegroundColor Red }

# ── Check DB ─────────────────────────────────────────────────────────

Step "Checking SQLite state"
Invoke-Expression "$SSH 'sqlite3 /root/.vigil-data/vigil-state.db \".tables\" 2>&1 || echo no-db'"

# ── Cleanup ──────────────────────────────────────────────────────────

if (-not $NoCleanup) {
    Step "Cleaning up VM"
    Invoke-Expression "$SSH 'rm -f $VM_BINARY /tmp/firewall_*.sh'"
    & $VBox controlvm $VM poweroff 2>&1 | Out-Null
    Write-Host "  VM powered off" -ForegroundColor Green
} else {
    Write-Host "  NoCleanup: VM left running" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Test run complete" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
