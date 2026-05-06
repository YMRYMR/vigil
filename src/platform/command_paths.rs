use std::path::{Path, PathBuf};

pub fn resolve(program: &str) -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        resolve_windows(program)
    }
    #[cfg(target_os = "linux")]
    {
        resolve_linux(program)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = program;
        Err("trusted command resolution is supported on Windows and Linux only".into())
    }
}

#[cfg(windows)]
fn resolve_windows(program: &str) -> Result<PathBuf, String> {
    let candidates: &[&str] = match program {
        "ipconfig" | "ipconfig.exe" => &[r"C:\Windows\System32\ipconfig.exe"],
        "netsh" | "netsh.exe" => &[r"C:\Windows\System32\netsh.exe"],
        "pktmon" | "pktmon.exe" => &[r"C:\Windows\System32\pktmon.exe"],
        "rundll32" | "rundll32.exe" => &[r"C:\Windows\System32\rundll32.exe"],
        "sc" | "sc.exe" => &[r"C:\Windows\System32\sc.exe"],
        "schtasks" | "schtasks.exe" => &[r"C:\Windows\System32\schtasks.exe"],
        "powershell" | "powershell.exe" => &[
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\powershell.exe",
        ],
        _ => &[],
    };
    resolve_from_candidates(program, candidates)
}

#[cfg(target_os = "linux")]
fn resolve_linux(program: &str) -> Result<PathBuf, String> {
    let candidates: &[&str] = match program {
        "kill" => &["/bin/kill", "/usr/bin/kill"],
        "iptables" => &["/usr/sbin/iptables", "/sbin/iptables"],
        "ip" => &["/usr/sbin/ip", "/sbin/ip"],
        "ss" => &["/usr/sbin/ss", "/usr/bin/ss", "/bin/ss"],
        "resolvectl" => &["/usr/bin/resolvectl", "/bin/resolvectl"],
        "systemd-resolve" => &["/usr/bin/systemd-resolve", "/bin/systemd-resolve"],
        "systemctl" => &["/bin/systemctl", "/usr/bin/systemctl"],
        "crontab" => &["/usr/bin/crontab", "/bin/crontab"],
        _ => &[],
    };
    resolve_from_candidates(program, candidates)
}

fn resolve_from_candidates(program: &str, candidates: &[&str]) -> Result<PathBuf, String> {
    candidates
        .iter()
        .copied()
        .map(PathBuf::from)
        .find(|path| Path::new(path).exists())
        .ok_or_else(|| format!("required trusted binary for {program} not found"))
}
