param([switch]$SkipBuild)
$VM_USER="vigil";$VM_HOST="localhost";$VM_PORT=2222;$VM_PASSWORD="vigil"
$V="C:\Program Files\Oracle\VirtualBox\VBoxManage.exe";$VM="vigil-linux"
$BIN="target/release/vigil";$VBIN="/tmp/vigil"

function Step($m){Write-Host "-- $m --" -ForegroundColor Yellow}
function Ssh($c){& plink -P $VM_PORT -pw $VM_PASSWORD -batch $VM_USER@$VM_HOST $c 2>&1}
function Upload($l,$r){& pscp -P $VM_PORT -pw $VM_PASSWORD $l "$VM_USER@$VM_HOST`:${r}" 2>&1}

function Step($m){Write-Host "-- $m --" -ForegroundColor Yellow}
function Ssh($c){& plink -P $VM_PORT -pw $VM_PASSWORD -batch $VM_USER@$VM_HOST $c 2>&1}
function Upload($l,$r){& pscp -P $VM_PORT -pw $VM_PASSWORD $l "$VM_USER@$VM_HOST`:${r}" 2>&1}

Step "Dependencies"
if(-not(Test-Path "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")){throw "VirtualBox missing"}
if(-not(Get-Command plink -ErrorAction SilentlyContinue)){
    cmd /c "winget install --id PuTTY.PuTTY --silent --accept-package-agreements --accept-source-agreements" 2>&1|Out-Null
    $env:Path=[Environment]::GetEnvironmentVariable("Path","Machine")+";"+[Environment]::GetEnvironmentVariable("Path","User")
    if(-not(Get-Command plink -ErrorAction SilentlyContinue)){throw "PuTTY install failed"}
}
Write-Host "  plink OK" -ForegroundColor Green
if(-not(Get-Command cargo -ErrorAction SilentlyContinue)){throw "Rust missing"}
Write-Host "  cargo OK" -ForegroundColor Green

if(-not $SkipBuild){
    Step "Build"
    $out=cargo build --release --bin vigil 2>&1
    if($LASTEXITCODE -ne 0){
        Write-Host "  Release build failed, trying debug..." -ForegroundColor Yellow
        $out = cargo build --bin vigil 2>&1
        if($LASTEXITCODE -ne 0){$out|Select -Last 10|%{Write-Host $_};throw "Build failed"}
        $BIN="target/debug/vigil"
    }
    Write-Host "  built $BIN" -ForegroundColor Green
}
# Windows .exe fix
if(Test-Path "target/release/vigil.exe"){$BIN="target/release/vigil.exe"}
elseif(Test-Path "target/debug/vigil.exe"){$BIN="target/debug/vigil.exe"}
elseif(Test-Path "target/release/vigil"){}
elseif(Test-Path "target/debug/vigil"){$BIN="target/debug/vigil"}
else{
    Write-Host "  No binary found. Trying: cargo build --bin vigil" -ForegroundColor Yellow
    $out = cargo build --bin vigil 2>&1
    if($LASTEXITCODE -ne 0){$out|Select -Last 10|%{Write-Host $_};throw "Build failed"}
    $BIN="target/debug/vigil.exe"
}
Write-Host "  binary: $BIN" -ForegroundColor Green

Step "Start VM"
$s=& $V showvminfo $VM --machinereadable 2>&1
if($s -match "running"){Write-Host "  already running" -ForegroundColor Green}
else{
    Write-Host "  launching VM GUI..." -ForegroundColor Cyan
    $startOut = & $V startvm $VM 2>&1
    Write-Host "  $startOut" -ForegroundColor Cyan
}

Step "Wait SSH"
$null=cmd /c "echo y | plink -P $VM_PORT -pw $VM_PASSWORD $VM_USER@$VM_HOST exit" 2>&1
for($i=0;$i -lt 180;$i+=5){
    $r=Ssh "echo ok"
    if("$r".Trim() -eq "ok"){Write-Host "  ready ${i}s" -ForegroundColor Green;break}
    if($i%15 -eq 0){Write-Host "  wait $i s" -ForegroundColor DarkYellow}
    sleep 5
}
if("$r".Trim() -ne "ok"){throw "SSH timeout"}

Step "Setup VM"
# Write a helper script that runs sudo with password, upload it, execute it.
# This avoids PowerShell pipe-quoting issues entirely.
$setupScript = @'
#!/bin/bash
set -e
PW="vigil"
echo "SETUP-START"

# Wait for apt locks
for i in $(seq 1 30); do
    if ! fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock >/dev/null 2>&1; then break; fi
    echo "Waiting for apt lock... ($i)"
    sleep 2
done

echo $PW | sudo -S apt update -qq || true
echo $PW | sudo -S apt install -y -qq openssh-server nftables iptables sqlite3 curl build-essential pkg-config libssl-dev
echo "vigil ALL=(ALL) NOPASSWD:ALL" | sudo -S tee /etc/sudoers.d/vigil >/dev/null
echo $PW | sudo -S chmod 440 /etc/sudoers.d/vigil

# Install Rust (non-interactive)
if ! command -v cargo &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
echo "SETUP-OK"
'@
Set-Content -Path "$env:TEMP\vigil_vm_setup.sh" -Value $setupScript -Encoding ASCII
Upload "$env:TEMP\vigil_vm_setup.sh" "/tmp/vigil_vm_setup.sh"
Ssh "chmod +x /tmp/vigil_vm_setup.sh" | Out-Null
Write-Host "  Running VM setup script..." -ForegroundColor Cyan
$setupOut = Ssh "bash /tmp/vigil_vm_setup.sh"
Write-Host $setupOut
if("$setupOut" -notmatch "SETUP-OK"){throw "VM setup failed"}
Ssh "rm -f /tmp/vigil_vm_setup.sh" | Out-Null
Remove-Item "$env:TEMP\vigil_vm_setup.sh" -ErrorAction SilentlyContinue
$sc=Ssh "sudo -n whoami"
if("$sc" -match "root"){Write-Host "  sudo OK" -ForegroundColor Green}
else{throw "sudo still needs password - VM setup failed"}  # Added fallback

Step "Source + build"
Write-Host "  Creating tarball..." -ForegroundColor Cyan
$tarPath="$env:TEMP\vigil_src.tar.gz"
cmd /c "tar -czf $tarPath --exclude=target --exclude=.git -C $PWD ." 2>&1|Out-Null
if($LASTEXITCODE -ne 0){git archive --format=tar.gz -o "$tarPath" HEAD}
Upload "$tarPath" "/tmp/vigil_src.tar.gz"
Write-Host "  Building inside VM (~5-10 min)..." -ForegroundColor Cyan
$buildOut=Ssh "cd /tmp && rm -rf vs && mkdir vs && cd vs && tar -xzf ../vigil_src.tar.gz && source ~/.cargo/env && cargo build --release --bin vigil 2>&1 && cp target/release/vigil /tmp/vigil && echo BUILD-OK"
Write-Host $buildOut
if("$buildOut" -notmatch "BUILD-OK"){throw "Build in VM failed"}
$VBIN="/tmp/vigil"
Write-Host "  Installing to /usr/local/bin..." -ForegroundColor Cyan
Ssh "echo vigil | sudo -S cp /tmp/vs/target/release/vigil /usr/local/bin/vigil && echo vigil | sudo -S chmod 755 /usr/local/bin/vigil" | Out-Null
Ssh "echo vigil | sudo -S setcap cap_net_admin,cap_net_raw,cap_bpf+ep /usr/local/bin/vigil" | Out-Null
Write-Host "  vigil installed system-wide" -ForegroundColor Green
Upload "tests/firewall_cli_smoke_test.sh" "/tmp/firewall_cli_smoke_test.sh"
Upload "tests/firewall_integration_test.sh" "/tmp/firewall_integration_test.sh"
Write-Host "  done" -ForegroundColor Green

Step "Tests"
$o=Ssh "sudo -n VIGIL_BINARY=$VBIN bash /tmp/firewall_cli_smoke_test.sh"
Write-Host "  CLI smoke:"
Write-Host $o
$o=Ssh "sudo -n VIGIL_BINARY=$VBIN bash /tmp/firewall_integration_test.sh"
Write-Host "  Integration:"
Write-Host $o

Ssh "rm -f /tmp/firewall_*.sh"|Out-Null
Write-Host "Done - VM running on port $VM_PORT" -ForegroundColor Cyan
Write-Host "In the VM, run: sudo vigil" -ForegroundColor Cyan
Write-Host "Connect: plink -P $VM_PORT -pw $VM_PASSWORD $VM_USER@$VM_HOST" -ForegroundColor Cyan