# Vigil adversarial resilience lab

This plan describes a repeatable, local-only lab for validating Vigil against
hostile-looking but harmless behavior. The lab uses benign simulators instead of
real malware. Its purpose is to answer whether Vigil can observe, explain, resist
tampering, degrade safely, and recover under controlled conditions.

## Safety rules

These rules are part of the test contract:

- Do not use real malware, exploit kits, credential theft tools, persistence
  kits, rootkits, or destructive payloads.
- Keep all tests inside local VMs and private/host-only networks.
- Prefer VirtualBox. Docker may be used only as an optional Linux-local traffic
  or process generator, not as a replacement for host-level VM testing.
- Do not use WSL or WSL2 for this lab. They have different kernel, networking,
  service, and filesystem behavior from normal Windows/Linux hosts.
- Snapshot every VM before each disruptive test batch.
- Every simulator must have a cleanup path.
- Every test must define expected results, including acceptable documented
  limitations when Vigil cannot observe a behavior.
- No simulator should remain useful as malware if it escapes the lab. Keep it
  local, obvious, logged, and non-persistent.

## Lab topology

Use a host-only VirtualBox network so the VMs can talk to each other and the host
without needing internet access during tests.

Recommended VMs:

| VM | OS | Purpose |
| --- | --- | --- |
| `vigil-linux` | Ubuntu LTS or Fedora Workstation | Linux Vigil install and Linux host-level tests |
| `target-linux` | Ubuntu Server or Debian | Benign traffic target and local services |
| `vigil-windows` | Windows 11 or Windows 10 evaluation VM | Windows Vigil install and Windows host-level tests |
| `target-windows` | Optional Windows evaluation VM | Windows-specific local service target |

Default host-only network:

| Node | Suggested IP |
| --- | --- |
| Host-only adapter gateway | `192.168.56.1/24` |
| `vigil-linux` | `192.168.56.10/24` |
| `target-linux` | `192.168.56.20/24` |
| `vigil-windows` | `192.168.56.30/24` |
| `target-windows` | `192.168.56.40/24` |

## Host setup with VirtualBox

### Ubuntu/Debian host

```bash
sudo apt update
sudo apt install -y virtualbox virtualbox-ext-pack
VBoxManage --version
```

If Secure Boot blocks the VirtualBox kernel module, either enroll the module key
or use a host configuration where VirtualBox modules can load normally.

### macOS host

```bash
brew install --cask virtualbox
VBoxManage --version
```

Grant the required macOS system extension permissions if prompted.

### Windows host with PowerShell

Install VirtualBox from the official installer, then open a new PowerShell window
where `VBoxManage.exe` is available:

```powershell
& "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe" --version
```

The remaining `VBoxManage` examples use the command name `VBoxManage`; on
Windows, replace it with the full path above if needed.

## Create the host-only network

```bash
VBoxManage hostonlyif create
VBoxManage list hostonlyifs
```

Find the adapter name, usually `vboxnet0`, then configure it:

```bash
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0
```

Optional DHCP, useful for quick experiments but not required for the static-IP
plan:

```bash
VBoxManage dhcpserver add \
  --interface vboxnet0 \
  --server-ip 192.168.56.1 \
  --netmask 255.255.255.0 \
  --lower-ip 192.168.56.100 \
  --upper-ip 192.168.56.150 \
  --enable
```

## Temporary internet access for setup only

The VM definitions below are host-only by default. If you need internet access to
install OS packages, fetch updates, or download Vigil release artifacts, attach a
NAT adapter temporarily, perform the setup, then remove or disable NAT before
creating the `vigil-installed` snapshot and before running any resilience test.

Attach temporary NAT to a powered-off VM:

```bash
VBoxManage modifyvm vigil-linux --nic2 nat
VBoxManage modifyvm target-linux --nic2 nat
VBoxManage modifyvm vigil-windows --nic2 nat
```

Remove NAT again before tests:

```bash
VBoxManage modifyvm vigil-linux --nic2 none
VBoxManage modifyvm target-linux --nic2 none
VBoxManage modifyvm vigil-windows --nic2 none
```

Verify no VM has NAT enabled before running test phases:

```bash
VBoxManage showvminfo vigil-linux --machinereadable | grep '^nic[0-9]="'
VBoxManage showvminfo target-linux --machinereadable | grep '^nic[0-9]="'
VBoxManage showvminfo vigil-windows --machinereadable | grep '^nic[0-9]="'
```

Expected test-time result: `nic1="hostonly"` and no `nat` adapters.

## Create Linux VMs

Download Linux ISOs manually and place them under `~/iso/` or another local
folder. The examples below assume:

- `~/iso/ubuntu-desktop.iso` for `vigil-linux`
- `~/iso/ubuntu-server.iso` for `target-linux`

Create the Vigil Linux VM:

```bash
VBoxManage createvm --name vigil-linux --ostype Ubuntu_64 --register
VBoxManage modifyvm vigil-linux --memory 4096 --cpus 2 --vram 128 --graphicscontroller vmsvga
VBoxManage modifyvm vigil-linux --nic1 hostonly --hostonlyadapter1 vboxnet0 --nic2 none
VBoxManage createhd --filename "$HOME/VirtualBox VMs/vigil-linux/vigil-linux.vdi" --size 50000
VBoxManage storagectl vigil-linux --name SATA --add sata --controller IntelAhci
VBoxManage storageattach vigil-linux --storagectl SATA --port 0 --device 0 --type hdd \
  --medium "$HOME/VirtualBox VMs/vigil-linux/vigil-linux.vdi"
VBoxManage storagectl vigil-linux --name IDE --add ide
VBoxManage storageattach vigil-linux --storagectl IDE --port 0 --device 0 --type dvddrive \
  --medium "$HOME/iso/ubuntu-desktop.iso"
VBoxManage startvm vigil-linux --type gui
```

Create the target Linux VM:

```bash
VBoxManage createvm --name target-linux --ostype Ubuntu_64 --register
VBoxManage modifyvm target-linux --memory 2048 --cpus 1 --vram 64 --graphicscontroller vmsvga
VBoxManage modifyvm target-linux --nic1 hostonly --hostonlyadapter1 vboxnet0 --nic2 none
VBoxManage createhd --filename "$HOME/VirtualBox VMs/target-linux/target-linux.vdi" --size 25000
VBoxManage storagectl target-linux --name SATA --add sata --controller IntelAhci
VBoxManage storageattach target-linux --storagectl SATA --port 0 --device 0 --type hdd \
  --medium "$HOME/VirtualBox VMs/target-linux/target-linux.vdi"
VBoxManage storagectl target-linux --name IDE --add ide
VBoxManage storageattach target-linux --storagectl IDE --port 0 --device 0 --type dvddrive \
  --medium "$HOME/iso/ubuntu-server.iso"
VBoxManage startvm target-linux --type gui
```

Install the operating systems normally, then configure the host-only interface
inside each Linux guest.

On `vigil-linux`:

```bash
ip link
sudo ip addr add 192.168.56.10/24 dev enp0s3
sudo ip link set enp0s3 up
ping -c 3 192.168.56.1
```

On `target-linux`:

```bash
ip link
sudo ip addr add 192.168.56.20/24 dev enp0s3
sudo ip link set enp0s3 up
ping -c 3 192.168.56.10
```

Persist the static IP with NetworkManager, if present.

On `vigil-linux`:

```bash
sudo nmcli con add type ethernet ifname enp0s3 con-name vigil-hostonly \
  ipv4.method manual ipv4.addresses 192.168.56.10/24 ipv4.gateway "" \
  ipv4.dns "" connection.autoconnect yes
sudo nmcli con up vigil-hostonly
```

On `target-linux`:

```bash
sudo nmcli con add type ethernet ifname enp0s3 con-name target-hostonly \
  ipv4.method manual ipv4.addresses 192.168.56.20/24 ipv4.gateway "" \
  ipv4.dns "" connection.autoconnect yes
sudo nmcli con up target-hostonly
```

## Create Windows VMs

Windows installation is less practical to fully automate without a prepared
unattended install image. Create the VM shell with `VBoxManage`, attach the ISO,
and complete setup in the GUI.

Create `vigil-windows`:

```bash
VBoxManage createvm --name vigil-windows --ostype Windows11_64 --register
VBoxManage modifyvm vigil-windows --memory 6144 --cpus 2 --vram 128 --graphicscontroller vboxsvga
VBoxManage modifyvm vigil-windows --firmware efi --ioapic on --boot1 dvd --boot2 disk
VBoxManage modifyvm vigil-windows --nic1 hostonly --hostonlyadapter1 vboxnet0 --nic2 none
VBoxManage createhd --filename "$HOME/VirtualBox VMs/vigil-windows/vigil-windows.vdi" --size 80000
VBoxManage storagectl vigil-windows --name SATA --add sata --controller IntelAhci
VBoxManage storageattach vigil-windows --storagectl SATA --port 0 --device 0 --type hdd \
  --medium "$HOME/VirtualBox VMs/vigil-windows/vigil-windows.vdi"
VBoxManage storagectl vigil-windows --name IDE --add ide
VBoxManage storageattach vigil-windows --storagectl IDE --port 0 --device 0 --type dvddrive \
  --medium "$HOME/iso/windows.iso"
VBoxManage startvm vigil-windows --type gui
```

Inside Windows, set the host-only adapter to a static address:

```powershell
Get-NetAdapter
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.56.30 -PrefixLength 24
Test-NetConnection 192.168.56.1
Test-NetConnection 192.168.56.20 -Port 8080
```

Use the actual adapter alias shown by `Get-NetAdapter` if it is not `Ethernet`.

## Snapshot discipline

Create a clean snapshot after OS install and before any Vigil install:

```bash
VBoxManage snapshot vigil-linux take clean-os --description "Fresh OS before Vigil"
VBoxManage snapshot target-linux take clean-os --description "Fresh local target"
VBoxManage snapshot vigil-windows take clean-os --description "Fresh OS before Vigil"
```

Create a second snapshot after installing and configuring Vigil, with NAT disabled:

```bash
VBoxManage modifyvm vigil-linux --nic2 none
VBoxManage modifyvm target-linux --nic2 none
VBoxManage modifyvm vigil-windows --nic2 none
VBoxManage snapshot vigil-linux take vigil-installed --description "Vigil installed and baseline configured"
VBoxManage snapshot vigil-windows take vigil-installed --description "Vigil installed and baseline configured"
```

Restore before destructive or overload tests:

```bash
VBoxManage controlvm vigil-linux poweroff
VBoxManage snapshot vigil-linux restore vigil-installed
VBoxManage startvm vigil-linux --type gui
```

## Install Vigil in the Linux VM

From a release AppImage:

```bash
mkdir -p ~/vigil-lab
cd ~/vigil-lab
# Copy the AppImage into this directory from the host or attach temporary NAT only for download/setup.
chmod +x Vigil-*.AppImage
./Vigil-*.AppImage
```

From source:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev git curl iproute2 iptables nftables
curl https://sh.rustup.rs -sSf | sh -s -- -y
. "$HOME/.cargo/env"
git clone https://github.com/YMRYMR/vigil.git
cd vigil
cargo build --release
./target/release/vigil
```

Install boot-time service only after basic GUI tests pass:

```bash
sudo ./target/release/vigil --install-service
systemctl status vigil.service --no-pager
```

Remove it during cleanup:

```bash
sudo ./target/release/vigil --uninstall-service
systemctl status vigil.service --no-pager || true
```

## Install Vigil in the Windows VM

Use the latest Windows installer or a locally built artifact. Start with normal
user-mode operation, then test elevated behavior separately.

PowerShell checks:

```powershell
Get-Process vigil -ErrorAction SilentlyContinue
Get-NetTCPConnection | Select-Object -First 10
```

Service/pre-login mode should be tested only after GUI and restore-network tests
are proven from a snapshot:

```powershell
Start-Process powershell -Verb RunAs
# In the elevated shell:
& "C:\Program Files\Vigil\vigil.exe" --install-service
schtasks /Query /TN VigilBootMonitor
```

Cleanup:

```powershell
Start-Process powershell -Verb RunAs
# In the elevated shell:
& "C:\Program Files\Vigil\vigil.exe" --uninstall-service
schtasks /Query /TN VigilBootMonitor
```

## Configure local target services

On `target-linux`, run harmless local services that create observable traffic.

HTTP target:

```bash
mkdir -p ~/vigil-target/www
printf 'vigil lab target\n' > ~/vigil-target/www/index.txt
cd ~/vigil-target/www
python3 -m http.server 8080 --bind 192.168.56.20
```

TCP echo-like listener using netcat:

```bash
sudo apt update
sudo apt install -y netcat-openbsd
while true; do printf 'vigil-lab\n' | nc -l 192.168.56.20 9001; done
```

From `vigil-linux`, verify traffic:

```bash
curl http://192.168.56.20:8080/index.txt
printf 'hello\n' | nc 192.168.56.20 9001
```

From `vigil-windows`, verify traffic:

```powershell
Invoke-WebRequest http://192.168.56.20:8080/index.txt
Test-NetConnection 192.168.56.20 -Port 9001
```

## Optional Docker supplement on Linux

Docker can help generate benign local load, but it should not replace full VM
host testing because container networking and namespaces can hide host details.
Use it only inside `vigil-linux` after snapshots are in place and after any
required temporary NAT setup has been removed again.

```bash
sudo apt update
sudo apt install -y docker.io
sudo systemctl enable --now docker
sudo docker run --rm --network host busybox sh -c 'for i in $(seq 1 100); do wget -qO- http://192.168.56.20:8080/index.txt >/dev/null; done'
```

Document whether Vigil sees the container-generated traffic as expected. If it
cannot attribute it precisely, record that as a visibility limitation rather than
trying to add stealth behavior to the simulator.

## Test phases

Before each phase, verify the VM is on the host-only network only:

```bash
VBoxManage showvminfo vigil-linux --machinereadable | grep '^nic[0-9]="'
```

### Phase 0: baseline observation

Goal: confirm normal network and process visibility.

Commands from `vigil-linux`:

```bash
curl http://192.168.56.20:8080/index.txt
for i in $(seq 1 10); do curl -s http://192.168.56.20:8080/index.txt >/dev/null; sleep 1; done
```

Expected result:

- Vigil shows the local process and remote endpoint.
- No containment action is taken automatically unless explicitly configured.
- Logs include enough context to identify the process and target.

### Phase 1: benign beacon simulation

Goal: create periodic outbound connections without malicious payloads.

```bash
for i in $(seq 1 60); do
  curl -s "http://192.168.56.20:8080/index.txt?beat=$i" >/dev/null
  sleep 5
done
```

Expected result:

- Vigil should surface repeated outbound behavior if scoring rules consider it
  suspicious.
- If not detected, record the scoring threshold and whether that is acceptable.

### Phase 2: connection churn and short-lived sockets

Goal: test event loss and UI/log backpressure.

```bash
for i in $(seq 1 500); do
  curl -s --max-time 2 http://192.168.56.20:8080/index.txt >/dev/null &
done
wait
```

Expected result:

- Vigil remains responsive.
- CPU and memory return to baseline after the burst.
- Any dropped-event warnings are visible in logs.

### Phase 3: process tree simulation

Goal: create benign nested process trees that produce network traffic.

```bash
bash -c 'sh -c "python3 - <<PY
import urllib.request
urllib.request.urlopen(\"http://192.168.56.20:8080/index.txt\", timeout=3).read()
PY"'
```

Expected result:

- Vigil records the process and, where supported, ancestor context.
- Any missing ancestor depth is documented.

### Phase 4: file tamper simulation

Goal: validate protected-file integrity, quarantine, and recovery using harmless
edits. Start only from a snapshot and only touch Vigil-owned lab files.

Suggested workflow:

1. Identify the Vigil data directory from logs or settings.
2. Stop Vigil if the specific test requires offline tampering.
3. Copy files before modifying them.
4. Modify only known Vigil-owned config/state/artifact files.
5. Restart Vigil and observe detection/recovery behavior.

Example pattern on Linux, using placeholders intentionally:

```bash
VIGIL_DATA_DIR="$HOME/.local/share/vigil"
mkdir -p "$HOME/vigil-lab/backups"
cp -a "$VIGIL_DATA_DIR" "$HOME/vigil-lab/backups/vigil-data-before-tamper"
find "$VIGIL_DATA_DIR" -maxdepth 1 -type f -name '*.json' -print
# Choose one non-critical lab file, then make a reversible edit.
cp "$VIGIL_DATA_DIR/CHOSEN_FILE.json" "$VIGIL_DATA_DIR/CHOSEN_FILE.json.labbak"
printf '\n{"lab_tamper": true}\n' >> "$VIGIL_DATA_DIR/CHOSEN_FILE.json"
```

Expected result:

- Vigil logs an integrity or parse failure for protected files.
- Vigil fails open rather than preventing login/session usability.
- Quarantine/recovery behavior matches the file type and documentation.

### Phase 5: service resilience

Goal: ensure Vigil service failures do not trap the OS.

Linux service checks:

```bash
sudo systemctl status vigil.service --no-pager
sudo systemctl restart vigil.service
sudo systemctl status vigil.service --no-pager
journalctl -u vigil.service -n 100 --no-pager
```

Controlled stop:

```bash
sudo systemctl stop vigil.service
sleep 10
sudo systemctl start vigil.service
```

Expected result:

- Service restart is observable and logged.
- Repeated failure does not permanently break the VM.
- Startup fail-open guard behavior matches the support contract.

### Phase 6: overload simulation

Goal: apply resource pressure without destructive payloads.

CPU pressure for a short window:

```bash
python3 - <<'PY'
import multiprocessing, time
end = time.time() + 30
def spin():
    while time.time() < end:
        pass
procs = [multiprocessing.Process(target=spin) for _ in range(max(1, multiprocessing.cpu_count() - 1))]
[p.start() for p in procs]
[p.join() for p in procs]
PY
```

Network plus CPU pressure:

```bash
for i in $(seq 1 200); do curl -s http://192.168.56.20:8080/index.txt >/dev/null & done
python3 - <<'PY'
import time
end = time.time() + 15
while time.time() < end:
    sum(range(10000))
PY
wait
```

Expected result:

- Vigil remains usable or degrades visibly and recovers.
- Logs capture overload symptoms without unbounded growth.
- No automatic destructive action occurs unless configured.

### Phase 7: containment and break-glass recovery

Goal: validate reversible containment from a snapshot.

Linux checks before isolation:

```bash
ip route
ip addr
iptables -S || true
nft list ruleset || true
```

After triggering a Vigil isolation action in the UI or rules engine, collect:

```bash
ip route
ip addr
iptables -S || true
nft list ruleset || true
journalctl -u vigil.service -n 200 --no-pager || true
```

Expected result:

- Containment is clearly visible to the operator.
- Restore-network returns host-only connectivity.
- Break-glass recovery restores connectivity if Vigil crashes during isolation.

## Result template

For every run, record:

```text
Test ID:
Date:
VM snapshot:
Vigil commit/release:
Host OS:
Guest OS:
Privilege mode:
Commands run:
Expected result:
Actual result:
Detection status: detected / partially detected / not detected / not applicable
Recovery status: recovered / manual recovery / snapshot restore required
Logs/artifacts collected:
Follow-up issue or PR:
```

## Cleanup

Stop local services:

```bash
pkill -f 'python3 -m http.server' || true
pkill -f 'nc -l 192.168.56.20 9001' || true
```

Restore firewall state from a snapshot if any containment test changed host
networking. Prefer snapshot restore over manual cleanup for disruptive tests.

Remove Linux service mode when not testing it. Set `VIGIL_BIN` to the same binary
path used for installation, then fail loudly if that binary is missing:

```bash
VIGIL_BIN="${VIGIL_BIN:-$HOME/vigil/target/release/vigil}"
test -x "$VIGIL_BIN"
sudo "$VIGIL_BIN" --uninstall-service
sudo systemctl daemon-reload
systemctl status vigil.service --no-pager || true
```

Restore the VM snapshot for a clean state:

```bash
VBoxManage controlvm vigil-linux poweroff
VBoxManage snapshot vigil-linux restore vigil-installed
VBoxManage startvm vigil-linux --type gui
```

## Future simulator scripts

Future scripts should live under `tests/adversarial/scripts/` and follow these
rules:

- local/private targets only;
- no real exploit or malware behavior;
- no credential access;
- no persistence beyond the running test process;
- bounded runtime and resource usage;
- clear cleanup instructions;
- expected Vigil observations documented beside the script.
