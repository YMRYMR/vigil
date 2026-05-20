param([switch]$SkipBuild)
$VM_USER="vigil";$VM_HOST="localhost";$VM_PORT=2222;$VM_PASSWORD="vigil"
$V="C:\Program Files\Oracle\VirtualBox\VBoxManage.exe";$VM="vigil-linux"
$BIN="target/release/vigil";$VBIN="/tmp/vigil"

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
        Write-Host "  Build FAILED. Trying debug build..." -ForegroundColor Yellow
        $out = cargo build --bin vigil 2>&1
        if($LASTEXITCODE -ne 0){$out|Select -Last 10|%{Write-Host $_};throw "Build failed"}
        $BIN="target/debug/vigil"
    }
    Write-Host "  built $BIN" -ForegroundColor Green
}
if(-not(Test-Path $BIN)){
    # Try debug build as fallback
    $BIN="target/debug/vigil"
    if(-not(Test-Path $BIN)){
        Write-Host "  No binary found. Trying: cargo build" -ForegroundColor Yellow
        $out = cargo build --bin vigil 2>&1
        if($LASTEXITCODE -ne 0){$out|Select -Last 10|%{Write-Host $_};throw "Build failed"}
        Write-Host "  built debug" -ForegroundColor Green
    }
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
    $r=cmd /c "ssh -p $VM_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o AddressFamily=inet $VM_USER@$VM_HOST echo ok" 2>&1
    if($r -eq "ok"){Write-Host "  ready ${i}s" -ForegroundColor Green;break}
    if($i%15 -eq 0){Write-Host "  wait $i s" -ForegroundColor DarkYellow}
    sleep 5
}
if($r -ne "ok"){throw "SSH timeout"}

Step "Setup VM"
Ssh "echo $VM_PASSWORD | sudo -S apt update -qq"|Out-Null
Ssh "echo $VM_PASSWORD | sudo -S apt install -y -qq openssh-server nftables iptables sqlite3"|Out-Null
Ssh "echo $VM_PASSWORD | sudo -S sh -c 'echo $VM_USER ALL=(ALL) NOPASSWD:ALL > /etc/sudoers.d/vigil'"|Out-Null
Ssh "echo $VM_PASSWORD | sudo -S chmod 440 /etc/sudoers.d/vigil"|Out-Null
$sc=Ssh "sudo -n whoami"
if($sc -match "root"){Write-Host "  sudo OK" -ForegroundColor Green}
else{throw "sudo failed: $sc"}

Step "Upload"
Upload $BIN $VBIN
Ssh "chmod +x $VBIN"|Out-Null
Upload "tests/firewall_cli_smoke_test.sh" "/tmp/firewall_cli_smoke_test.sh"
Upload "tests/firewall_integration_test.sh" "/tmp/firewall_integration_test.sh"
Write-Host "  done" -ForegroundColor Green

Step "CLI smoke"
$o=Ssh "sudo -n VIGIL_BINARY=$VBIN bash /tmp/firewall_cli_smoke_test.sh"
Write-Host $o

Step "Integration"
$o=Ssh "sudo -n VIGIL_BINARY=$VBIN bash /tmp/firewall_integration_test.sh"
Write-Host $o

Ssh "rm -f $VBIN /tmp/firewall_*.sh"|Out-Null
Write-Host "Done - VM running on port $VM_PORT" -ForegroundColor Cyan
Write-Host "Connect: plink -P $VM_PORT -pw $VM_PASSWORD $VM_USER@$VM_HOST" -ForegroundColor Cyan
