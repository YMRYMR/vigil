param(
    [switch]$NoCleanup,
    [switch]$SkipBuild,
    [switch]$SetupVM   # Install SSH + deps inside VM via guest control
)

$VM_USER="vigil";$VM_HOST="localhost";$VM_PORT=2222;$VM_PASSWORD="vigil"
$VBox="C:\Program Files\Oracle\VirtualBox\VBoxManage.exe";$VM="vigil-linux"
$BINARY="target/release/vigil";$VM_BINARY="/tmp/vigil"

function Step($m) { Write-Host "-- $m --" -ForegroundColor Yellow }

# Auto-detect SSH client
$USE_PLINK = $false
if (Get-Command plink -ErrorAction SilentlyContinue) { $USE_PLINK = $true }

function SshExec($c) {
    if ($USE_PLINK) {
        cmd /c "plink -P $VM_PORT -pw $VM_PASSWORD $VM_USER@$VM_HOST $c" 2>&1
    } else {
        cmd /c "ssh -p $VM_PORT -o StrictHostKeyChecking=no -o AddressFamily=inet $VM_USER@$VM_HOST $c" 2>&1
    }
}

function ScpUpload($local, $remote) {
    if ($USE_PLINK) {
        cmd /c "pscp -P $VM_PORT -pw $VM_PASSWORD $local $VM_USER@$VM_HOST`:$remote" 2>&1
    } else {
        cmd /c "scp -P $VM_PORT -o StrictHostKeyChecking=no $local $VM_USER@$VM_HOST`:$remote" 2>&1
    }
}

# Check dependencies
Step "Check dependencies"
if (-not (Test-Path "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")) { throw "VirtualBox not found" }
Write-Host "  VirtualBox OK" -ForegroundColor Green
if (-not $USE_PLINK) {
    cmd /c "winget install --id PuTTY.PuTTY --silent --accept-package-agreements --accept-source-agreements" 2>&1 | Out-Null
    $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine")+";"+[Environment]::GetEnvironmentVariable("Path","User")
    if (Get-Command plink -ErrorAction SilentlyContinue) { $USE_PLINK = $true }
}
if ($USE_PLINK) { Write-Host "  plink OK" -ForegroundColor Green } else { Write-Host "  plink n/a, using ssh" -ForegroundColor Yellow }
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw "Rust not found" }
Write-Host "  cargo OK" -ForegroundColor Green

# Build
if (-not $SkipBuild) {
    Step "Building vigil"
    cargo build --release --bin vigil 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    Write-Host "  built $BINARY" -ForegroundColor Green
}

# Start VM
Step "Starting VM: $VM"
$state = & $VBox showvminfo $VM --machinereadable 2>&1
if ($state -match "running") {
    Write-Host "  already running" -ForegroundColor Green
} else {
    & $VBox startvm $VM 2>&1 | Out-Null
    Write-Host "  VM started. Log into the VM console window and wait for boot to complete." -ForegroundColor Cyan
    Write-Host "  A terminal will appear once booted." -ForegroundColor Cyan
}

# Install SSH if requested
if ($SetupVM) {
    Step "Setting up VM for testing"
    Write-Host "  This requires Guest Additions installed inside the VM." -ForegroundColor Yellow
    Write-Host "  If the VM console is at a login prompt, log in as vigil/vigil." -ForegroundColor Yellow
    Write-Host "  Then press Enter here when the VM desktop is ready." -ForegroundColor Yellow
    Read-Host "  Press Enter to continue"

    # Try direct console commands
    Write-Host "  Installing openssh-server..." -ForegroundColor Cyan
    & $VBox guestcontrol $VM run --exe "/usr/bin/apt" --username $VM_USER --password $VM_PASSWORD --wait-stdout --wait-stderr -- -y update 2>&1 | Out-Null
    & $VBox guestcontrol $VM run --exe "/usr/bin/apt" --username $VM_USER --password $VM_PASSWORD --wait-stdout --wait-stderr -- -y install openssh-server nftables iptables sqlite3 2>&1 | Out-Null
    & $VBox guestcontrol $VM run --exe "/usr/bin/systemctl" --username $VM_USER --password $VM_PASSWORD --wait-stdout -- - - - enable --now ssh 2>&1 | Out-Null
    Write-Host "  SSH server installed." -ForegroundColor Green
    Write-Host "  Please restart the VM for changes to take effect." -ForegroundColor Cyan
    Write-Host "  Then re-run this script without --SetupVM." -ForegroundColor Cyan
    exit 0
}

# Wait for SSH
Step "Waiting for SSH on port $VM_PORT -> guest:22"
Write-Host "  If SSH doesn't connect, the VM might not have SSH server installed." -ForegroundColor Yellow
Write-Host "  Re-run with --SetupVM to install it, or manually inside VM:" -ForegroundColor Yellow
Write-Host "    sudo apt update && sudo apt install -y openssh-server" -ForegroundColor Yellow
$started = $false
for ($i = 0; $i -lt 180; $i += 5) {
    $r = cmd /c "ssh -p $VM_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o AddressFamily=inet $VM_USER@$VM_HOST echo ok" 2>&1
    if ($r -eq "ok") { Write-Host "  ready after ${i}s" -ForegroundColor Green; $started=$true; break }
    if ($i % 15 -eq 0) { Write-Host "  waiting ($i s)" -ForegroundColor DarkYellow }
    Start-Sleep -Seconds 5
}
if (-not $started) {
    Write-Host "  Failed to connect. Check inside the VM:" -ForegroundColor Red
    Write-Host "  1. systemctl status sshd" -ForegroundColor Red
    Write-Host "  2. sudo ufw status" -ForegroundColor Red
    Write-Host "  3. ip addr (get IP, then test: ssh vigil@<IP>)" -ForegroundColor Red
    throw "SSH timeout"
}

Step "Uploading binary"
ScpUpload $BINARY "$VM_BINARY"
SshExec "chmod +x $VM_BINARY" | Out-Null
Write-Host "  binary uploaded" -ForegroundColor Green

Step "Uploading test scripts"
ScpUpload "tests/firewall_cli_smoke_test.sh" "/tmp/firewall_cli_smoke_test.sh"
ScpUpload "tests/firewall_integration_test.sh" "/tmp/firewall_integration_test.sh"

Step "Running CLI smoke test"
$r = SshExec "VIGIL_BINARY=$VM_BINARY bash /tmp/firewall_cli_smoke_test.sh"
Write-Host $r

Step "Running integration test"
$r = SshExec "echo $VM_PASSWORD | sudo -S VIGIL_BINARY=$VM_BINARY bash /tmp/firewall_integration_test.sh"
Write-Host $r

if (-not $NoCleanup) {
    Step "Cleanup"
    SshExec "rm -f $VM_BINARY /tmp/firewall_*.sh" | Out-Null
    & $VBox controlvm $VM poweroff 2>&1 | Out-Null
    Write-Host "  VM powered off" -ForegroundColor Green
}

Write-Host "Complete" -ForegroundColor Cyan
