param([switch]$NoCleanup,[switch]$SkipBuild,[switch]$SetupVM)

$VM_USER="vigil";$VM_HOST="localhost";$VM_PORT=2222;$VM_PASSWORD="vigil"
$VBox="C:\Program Files\Oracle\VirtualBox\VBoxManage.exe";$VM="vigil-linux"
$BINARY="target/release/vigil";$VM_BINARY="/tmp/vigil"

function Step($m) { Write-Host "-- $m --" -ForegroundColor Yellow }

# Auto-detect SSH client
$USE_PLINK = $false
if (Get-Command plink -ErrorAction SilentlyContinue) { $USE_PLINK = $true }

function SshExec($c) {
    $batch = if ($USE_PLINK) { "-batch" } else { "" }
    cmd /c "plink -P $VM_PORT -pw $VM_PASSWORD $batch $VM_USER@$VM_HOST $c" 2>&1
}

function ScpUpload($local, $remote) {
    pscp -P $VM_PORT -pw $VM_PASSWORD $local "$VM_USER@$VM_HOST`:$remote" 2>&1
}

function AcceptHostKey() {
    # Pre-cache the host key so plink doesn't prompt interactively
    $null = cmd /c "echo y | plink -P $VM_PORT -pw $VM_PASSWORD $VM_USER@$VM_HOST exit" 2>&1
}

Step "Check dependencies"
if (-not (Test-Path "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")) { throw "VirtualBox not found" }
Write-Host "  VirtualBox OK" -ForegroundColor Green

if (-not $USE_PLINK) {
    cmd /c "winget install --id PuTTY.PuTTY --silent --accept-package-agreements --accept-source-agreements" 2>&1 | Out-Null
    $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine")+";"+[Environment]::GetEnvironmentVariable("Path","User")
    if (Get-Command plink -ErrorAction SilentlyContinue) { $USE_PLINK = $true }
}
if ($USE_PLINK) { Write-Host "  plink OK" -ForegroundColor Green } else { Write-Host "  plink not available" -ForegroundColor Red; throw "plink required" }

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw "Rust not found" }
Write-Host "  cargo OK" -ForegroundColor Green

# Build if needed
if (-not $SkipBuild) {
    Step "Building vigil"
    cargo build --release --bin vigil 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
}
Write-Host "  binary: $BINARY (exists: $(Test-Path $BINARY))" -ForegroundColor Green
if (-not (Test-Path $BINARY)) { throw "Binary not found at $BINARY - build with cargo build --release or remove -SkipBuild" }

# Start VM
Step "Starting VM: $VM"
$state = & $VBox showvminfo $VM --machinereadable 2>&1
if ($state -match "running") {
    Write-Host "  already running" -ForegroundColor Green
} else {
    & $VBox startvm $VM 2>&1 | Out-Null
    Write-Host "  VM started (GUI will open). Wait for boot." -ForegroundColor Cyan
}

# Setup mode
if ($SetupVM) {
    Step "Setting up VM"
    Write-Host "  Log into the VM console and open a terminal." -ForegroundColor Yellow
    Write-Host "  Run inside the VM:" -ForegroundColor Yellow
    Write-Host "    sudo apt update && sudo apt install -y openssh-server nftables iptables sqlite3" -ForegroundColor Cyan
    Write-Host "    sudo systemctl enable --now ssh" -ForegroundColor Cyan
    Write-Host "    echo 'vigil ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/vigil" -ForegroundColor Cyan
    Write-Host "  Then re-run without --SetupVM." -ForegroundColor Yellow
    exit 0
}

# Wait for SSH and accept host key
Step "Waiting for SSH on port $VM_PORT"
for ($i = 0; $i -lt 180; $i += 5) {
    $r = cmd /c "ssh -p $VM_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o AddressFamily=inet $VM_USER@$VM_HOST echo ok" 2>&1
    if ($r -eq "ok") { Write-Host "  ready after ${i}s" -ForegroundColor Green; break }
    if ($i % 15 -eq 0) { Write-Host "  waiting ($i s)" -ForegroundColor DarkYellow }
    Start-Sleep -Seconds 5
    if ($i -eq 0) { AcceptHostKey }  # Pre-cache host key for plink
}
$r = cmd /c "ssh -p $VM_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o AddressFamily=inet $VM_USER@$VM_HOST echo ok" 2>&1
if ($r -ne "ok") { throw "SSH timeout - see VM console for errors" }

# Accept host key in plink cache
AcceptHostKey

# Test sudo
Step "Testing sudo access"
$sudoOk = SshExec "echo $VM_PASSWORD | sudo -S whoami"
if ($sudoOk -match "root") {
    Write-Host "  sudo OK" -ForegroundColor Green
} else {
    Write-Host "  sudo failed (output: $sudoOk)" -ForegroundColor Red
    Write-Host "  Run in VM: echo 'vigil ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/vigil" -ForegroundColor Yellow
    throw "sudo access required"
}

Step "Uploading binary"
ScpUpload $BINARY $VM_BINARY
SshExec "chmod +x $VM_BINARY" | Out-Null
Write-Host "  done" -ForegroundColor Green

Step "Uploading test scripts"
ScpUpload "tests/firewall_cli_smoke_test.sh" "/tmp/firewall_cli_smoke_test.sh"
ScpUpload "tests/firewall_integration_test.sh" "/tmp/firewall_integration_test.sh"

Step "Running CLI smoke test"
$r = SshExec "VIGIL_BINARY=$VM_BINARY bash /tmp/firewall_cli_smoke_test.sh" 2>&1
Write-Host $r

Step "Running integration test"
$r = SshExec "echo $VM_PASSWORD | sudo -S VIGIL_BINARY=$VM_BINARY bash /tmp/firewall_integration_test.sh" 2>&1
Write-Host $r

if (-not $NoCleanup) {
    Step "Cleanup"
    SshExec "rm -f $VM_BINARY /tmp/firewall_*.sh" | Out-Null
    & $VBox controlvm $VM poweroff 2>&1 | Out-Null
    Write-Host "  VM powered off" -ForegroundColor Green
}

Write-Host "Complete" -ForegroundColor Cyan
