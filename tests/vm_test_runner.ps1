param([switch]$NoCleanup,[switch]$SkipBuild)
$VM_USER="vigil";$VM_HOST="localhost";$VM_PORT=2222;$VM_PASSWORD="vigil"
$VBox="C:\Program Files\Oracle\VirtualBox\VBoxManage.exe";$VM="vigil-linux"
$BINARY="target/release/vigil";$VM_BINARY="/tmp/vigil"

function Step($m) { Write-Host "-- $m --" -ForegroundColor Yellow }

# Uses plink for password auth. Auto-installed via winget if missing.
function SshExec($c) {
    # Use & to invoke plink directly (escaping cmd /c pipe issues).
    # The remote command is wrapped in double quotes so bash metacharacters
    # like | and > are passed through, not interpreted by the host shell.
    & plink -P $VM_PORT -pw $VM_PASSWORD -batch $VM_USER@$VM_HOST " $c" 2>&1
}
function ScpUpload($local, $remote) {
    pscp -P $VM_PORT -pw $VM_PASSWORD $local "$VM_USER@$VM_HOST`:$remote" 2>&1
}
function AcceptHostKey() {
    $null = cmd /c "echo y | plink -P $VM_PORT -pw $VM_PASSWORD $VM_USER@$VM_HOST exit" 2>&1
}

# ── Dependencies ────────────────────────────────────────────────────
Step "Check dependencies"
if (-not (Test-Path "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")) { throw "VirtualBox not found" }
if (-not (Get-Command plink -ErrorAction SilentlyContinue)) {
    Write-Host "  Installing PuTTY via winget..." -ForegroundColor Cyan
    cmd /c "winget install --id PuTTY.PuTTY --silent --accept-package-agreements --accept-source-agreements" 2>&1 | Out-Null
    $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine")+";"+[Environment]::GetEnvironmentVariable("Path","User")
    if (-not (Get-Command plink -ErrorAction SilentlyContinue)) { throw "PuTTY install failed" }
}
Write-Host "  plink OK" -ForegroundColor Green
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw "Rust not found" }
Write-Host "  cargo OK" -ForegroundColor Green

# ── Build ────────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    Step "Building vigil"
    cargo build --release --bin vigil 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
}
if (-not (Test-Path $BINARY)) { throw "Binary not found. Use cargo build --release or remove -SkipBuild" }
Write-Host "  binary: $BINARY" -ForegroundColor Green

# ── Start VM ─────────────────────────────────────────────────────────
Step "Starting VM: $VM"
$state = & $VBox showvminfo $VM --machinereadable 2>&1
if ($state -match "running") { Write-Host "  already running" -ForegroundColor Green }
else { & $VBox startvm $VM 2>&1 | Out-Null; Write-Host "  VM started (GUI window opens)" -ForegroundColor Cyan }

# ── Wait for SSH and auto-setup VM ────────────────────────────────
Step "Waiting for SSH on port $VM_PORT (up to 180s)"
for ($i = 0; $i -lt 180; $i += 5) {
    $r = cmd /c "ssh -p $VM_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o AddressFamily=inet $VM_USER@$VM_HOST echo ok" 2>&1
    if ($r -eq "ok") { Write-Host "  SSH ready after ${i}s" -ForegroundColor Green; break }
    if ($i -eq 0) { AcceptHostKey }
    if ($i % 15 -eq 0) { Write-Host "  waiting ($i s)" -ForegroundColor DarkYellow }
    Start-Sleep -Seconds 5
}
$r = cmd /c "ssh -p $VM_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o AddressFamily=inet $VM_USER@$VM_HOST echo ok" 2>&1
if ($r -ne "ok") { throw "SSH timeout" }
AcceptHostKey

# Auto-setup: install packages and configure sudo via SSH.
# Since the pipe | is inside plink's remote command argument,
# bash on the remote side interprets it, not the host shell.
Step "Setting up VM (packages + sudo)"
Write-Host "  Installing openssh-server, nftables, iptables, sqlite3..." -ForegroundColor Cyan
SshExec "echo $VM_PASSWORD | sudo -S apt update -qq" | Out-Null
SshExec "echo $VM_PASSWORD | sudo -S apt install -y -qq openssh-server nftables iptables sqlite3" | Out-Null
Write-Host "  Setting up passwordless sudo..." -ForegroundColor Cyan
SshExec "echo $VM_PASSWORD | sudo -S sh -c 'echo $VM_USER ALL=(ALL) NOPASSWD:ALL > /etc/sudoers.d/vigil'" | Out-Null
SshExec "echo $VM_PASSWORD | sudo -S chmod 440 /etc/sudoers.d/vigil" | Out-Null

# Verify sudo works
$sudoCheck = SshExec "sudo -n whoami"
if ($sudoCheck -match "root") { Write-Host "  sudo OK" -ForegroundColor Green }
else { Write-Host "  sudo setup failed: $sudoCheck" -ForegroundColor Red; throw "sudo required" }

# ── Upload and test ──────────────────────────────────────────────────
Step "Uploading binary"
ScpUpload $BINARY $VM_BINARY
SshExec "chmod +x $VM_BINARY" | Out-Null

Step "Uploading test scripts"
ScpUpload "tests/firewall_cli_smoke_test.sh" "/tmp/firewall_cli_smoke_test.sh"
ScpUpload "tests/firewall_integration_test.sh" "/tmp/firewall_integration_test.sh"

Step "Running CLI smoke test"
$r = SshExec "sudo -n VIGIL_BINARY=$VM_BINARY bash /tmp/firewall_cli_smoke_test.sh"
Write-Host $r

Step "Running integration test"
$r = SshExec "sudo -n VIGIL_BINARY=$VM_BINARY bash /tmp/firewall_integration_test.sh"
Write-Host $r

# ── Cleanup ──────────────────────────────────────────────────────────
if (-not $NoCleanup) {
    Step "Cleanup"
    SshExec "rm -f $VM_BINARY /tmp/firewall_*.sh" | Out-Null
    & $VBox controlvm $VM poweroff 2>&1 | Out-Null
    Write-Host "  VM powered off" -ForegroundColor Green
}
Write-Host "Complete" -ForegroundColor Cyan
