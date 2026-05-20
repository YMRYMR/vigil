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
$SSH = "ssh -p 2222 -o StrictHostKeyChecking=no root@localhost"
$SCP = "scp -P 2222 -o StrictHostKeyChecking=no"
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
$state = & $VBox showvminfo $VM --machinereadable 2>&1 | Select-String "VMState="
if ($state -match "running") {
    Write-Host "  VM already running" -ForegroundColor Green
} else {
    Write-Host "  Launching headless VM..." -ForegroundColor Cyan
    $startOutput = & $VBox startvm $VM --type headless 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  VBoxManage startvm failed: $startOutput" -ForegroundColor Red
        throw "VM start failed"
    }
    Write-Host "  VM started. Waiting for guest OS to boot..." -ForegroundColor Cyan
    Start-Sleep -Seconds 15
}

# Verify VM is actually running
$state = & $VBox showvminfo $VM --machinereadable 2>&1 | Select-String "VMState="
if ($state -notmatch "running") {
    throw "VM state is not running: $state"
}
Write-Host "  VM state confirmed: running" -ForegroundColor Green

# Ensure SSH key exists (generate if needed)
$sshKey = "$env:USERPROFILE\.ssh\id_ed25519"
if (-not (Test-Path $sshKey)) {
    Write-Host "  Generating SSH key pair..." -ForegroundColor Cyan
    & ssh-keygen -t ed25519 -f $sshKey -N '""' 2>&1 | Out-Null
}
Write-Host "  SSH key: $sshKey"

# ── Wait for SSH ─────────────────────────────────────────────────────

Step "Waiting for SSH (port 2222)"
$maxWait = 120
for ($i = 0; $i -lt $maxWait; $i += 2) {
    $result = & ssh -p 2222 -o StrictHostKeyChecking=no -o ConnectTimeout=2 root@localhost "echo ok" 2>&1
    if ($result -eq "ok") {
        Write-Host "  SSH ready after ${i}s" -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds 2
}
if ($i -ge $maxWait) { throw "SSH not available after ${maxWait}s" }

# Copy SSH public key to VM for passwordless access (if not already set up)
$sshKeyPub = "$env:USERPROFILE\.ssh\id_ed25519.pub"
if (Test-Path $sshKeyPub) {
    $keyContent = Get-Content $sshKeyPub -Raw
    $checkResult = Invoke-Expression "$SSH 'grep -F `"$keyContent`" /root/.ssh/authorized_keys 2>/dev/null'" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Installing SSH public key in VM..." -ForegroundColor Cyan
        Invoke-Expression "$SSH 'mkdir -p /root/.ssh'" 2>&1 | Out-Null
        & $SCP $sshKeyPub "root@localhost:/root/.ssh/authorized_keys" 2>&1 | Out-Null
        Write-Host "  SSH key installed" -ForegroundColor Green
    }
}

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
