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
$VM_USER = "vigil"
$VM_HOST = "localhost"
$VM_PORT = 2222
$VM_PASSWORD = "vigil"

$ErrorActionPreference = "Stop"
$VBox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$VM = "vigil-linux"

# Auto-detect best SSH client for password auth
$SSH_TYPE = if (Get-Command plink -ErrorAction SilentlyContinue) { "plink" }
            elseif (Get-Command sshpass -ErrorAction SilentlyContinue) { "sshpass" }
            else { "ssh" }
if ($SSH_TYPE -eq "plink") {
    $SSH = "plink -P $VM_PORT -pw $VM_PASSWORD $VM_USER@$VM_HOST"
    $SCP = "pscp -P $VM_PORT -pw $VM_PASSWORD"
} elseif ($SSH_TYPE -eq "sshpass") {
    $SSH = "sshpass -p $VM_PASSWORD ssh -p $VM_PORT -o StrictHostKeyChecking=no $VM_USER@$VM_HOST"
    $SCP = "sshpass -p $VM_PASSWORD scp -P $VM_PORT -o StrictHostKeyChecking=no"
} else {
    Write-Host "  WARNING: No password-capable SSH client found." -ForegroundColor Yellow
    Write-Host "  Install PuTTY (plink/pscp) or sshpass for automated password auth." -ForegroundColor Yellow
    Write-Host "  Falling back to interactive SSH - you'll need to type the password." -ForegroundColor Yellow
    $SSH = "ssh -p $VM_PORT -o StrictHostKeyChecking=no $VM_USER@$VM_HOST"
    $SCP = "scp -P $VM_PORT -o StrictHostKeyChecking=no"
}
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
    Write-Host "  Launching VM with GUI (so you can see it)..." -ForegroundColor Cyan
    $startOutput = & $VBox startvm $VM 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  VBoxManage startvm failed: $startOutput" -ForegroundColor Red
        throw "VM start failed"
    }
    Write-Host "  VM started. Waiting for guest OS to boot (this can take 30-60s)..." -ForegroundColor Cyan
    Write-Host "  If the VM login screen appears, log in as root to speed up boot." -ForegroundColor DarkYellow
    Start-Sleep -Seconds 30
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

Step "Waiting for SSH (port 2222 → guest:22)"
$maxWait = 180
$sshStarted = $false
for ($i = 0; $i -lt $maxWait; $i += 5) {
    if ($SSH_TYPE -eq "plink") {
        $result = & plink -P $VM_PORT -pw $VM_PASSWORD -batch $VM_USER@$VM_HOST "echo ok" 2>&1
    } else {
        $result = & ssh -p $VM_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o BatchMode=no $VM_USER@$VM_HOST "echo ok" 2>&1
    }
    if ($result -eq "ok") {
        Write-Host "  SSH ready after ${i}s" -ForegroundColor Green
        $sshStarted = $true
        break
    }
    # Show connection status every 15s
    if ($i % 15 -eq 0) {
        $status = if ($result -match "Connection refused") { "connection refused (SSH daemon not ready yet)" }
                  elseif ($result -match "timed out") { "timeout (guest still booting)" }
                  elseif ($result -match "Permission denied") { "permission denied (auth issue)" }
                  else { "waiting..." }
        Write-Host "  [${i}s] $status" -ForegroundColor DarkYellow
    }
    Start-Sleep -Seconds 5
}
if (-not $sshStarted) {
    Write-Host "  SSH not available after ${maxWait}s. Check:" -ForegroundColor Red
    Write-Host "    1. Is the VM logged in as root?" -ForegroundColor Red
    Write-Host "    2. Is sshd running? (systemctl status sshd)" -ForegroundColor Red
    Write-Host "    3. Is port forwarding active? (VBoxManage showvminfo $VM | grep Forwarding)" -ForegroundColor Red
    throw "SSH timeout"
}

# Copy SSH public key to VM for passwordless access (if not already set up)
$sshKeyPub = "$env:USERPROFILE\.ssh\id_ed25519.pub"
if (Test-Path $sshKeyPub) {
    $keyContent = Get-Content $sshKeyPub -Raw
    $keyContent = $keyContent.Trim()
    # Use ssh-copy-id to install the key (if available) or do it manually
    $sshCopyId = Get-Command ssh-copy-id -ErrorAction SilentlyContinue
    if ($sshCopyId) {
        Write-Host "  Installing SSH key via ssh-copy-id..." -ForegroundColor Cyan
        & ssh-copy-id -p $VM_PORT -o StrictHostKeyChecking=no $VM_USER@$VM_HOST 2>&1 | Out-Null
    } else {
        # Manual key install — write to ~/.ssh/authorized_keys
        Write-Host "  Ensuring .ssh directory exists..." -ForegroundColor Cyan
        $null = Invoke-Expression "$SSH 'mkdir -p ~/.ssh && chmod 700 ~/.ssh'" 2>&1
        $escapedKey = $keyContent -replace '"', '""'
        $cmd = "echo '$escapedKey' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
        $null = Invoke-Expression "$SSH '$cmd'" 2>&1
    }
    Write-Host "  SSH key setup complete" -ForegroundColor Green
}

# ── Upload binary ────────────────────────────────────────────────────

Step "Uploading vigil binary to VM"
if ($SSH_TYPE -eq "plink") {
    & pscp -P $VM_PORT -pw $VM_PASSWORD $BINARY "$VM_USER@${VM_HOST}:$VM_BINARY" 2>&1
} else {
    & $SCP $BINARY "$VM_USER@${VM_HOST}:$VM_BINARY" 2>&1
}
if ($LASTEXITCODE -ne 0) { throw "SCP upload failed" }
Invoke-Expression "$SSH 'chmod +x $VM_BINARY'"
Write-Host "  Binary uploaded to $VM_BINARY" -ForegroundColor Green

# ── Upload test script ───────────────────────────────────────────────

Step "Uploading test scripts"
$testScript = "tests/firewall_integration_test.sh"
$cliTestScript = "tests/firewall_cli_smoke_test.sh"
if ($SSH_TYPE -eq "plink") {
    & pscp -P $VM_PORT -pw $VM_PASSWORD $testScript "$VM_USER@${VM_HOST}:/tmp/firewall_integration_test.sh" 2>&1
    & pscp -P $VM_PORT -pw $VM_PASSWORD $cliTestScript "$VM_USER@${VM_HOST}:/tmp/firewall_cli_smoke_test.sh" 2>&1
} else {
    & $SCP $testScript "$VM_USER@${VM_HOST}:/tmp/firewall_integration_test.sh" 2>&1
    & $SCP $cliTestScript "$VM_USER@${VM_HOST}:/tmp/firewall_cli_smoke_test.sh" 2>&1
}

# ── Run tests ───────────────────────────────────────────────────────

Step "Running CLI smoke test (no root)"
$result = Invoke-Expression "$SSH 'VIGIL_BINARY=$VM_BINARY bash /tmp/firewall_cli_smoke_test.sh'" 2>&1
Write-Host $result
if ($LASTEXITCODE -ne 0) { Write-Host "  CLI smoke test FAILED" -ForegroundColor Red }

Step "Running firewall integration test (needs sudo)"
$cmd = "echo $VM_PASSWORD | sudo -S VIGIL_BINARY=$VM_BINARY bash /tmp/firewall_integration_test.sh"
$result = Invoke-Expression "$SSH '$cmd'" 2>&1
Write-Host $result
if ($LASTEXITCODE -ne 0) { Write-Host "  Integration test FAILED" -ForegroundColor Red }

# ── Check DB ─────────────────────────────────────────────────────────

Step "Checking SQLite state"
Invoke-Expression "$SSH 'sqlite3 /home/$VM_USER/.vigil-data/vigil-state.db .tables 2>&1 || echo no-db'"

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
