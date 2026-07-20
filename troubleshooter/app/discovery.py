"""Agentless server discovery over SSH.

One read-only SSH call gathers a broad set of facts about a server — OS,
kernel, virtualization, CPU/memory, disks, network, listening ports, running
services, package manager — parsed deterministically into a structured facts
dict and cached under data/discovery/<name>.json.

Discovered facts give the change/implementer AI real context about the target
(instead of asking the operator or guessing), so generated implementation
plans use the right package manager, service names, and downtime posture.
"""

import asyncio
import json
import re
import time

from .inventory import BASE_DIR, Server

DISCOVERY_DIR = BASE_DIR / "data" / "discovery"
TIMEOUT = 40


def _path(name: str):
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(name))[:80]
    return DISCOVERY_DIR / f"{safe}.json"


def load_facts(name: str) -> dict | None:
    try:
        return json.loads(_path(name).read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _save(name: str, facts: dict) -> dict:
    DISCOVERY_DIR.mkdir(parents=True, exist_ok=True)
    _path(name).write_text(json.dumps(facts, indent=1, default=str))
    return facts


# one script, section-delimited so parsing is deterministic
_SCRIPT = r"""
echo @@hostname; hostname -f 2>/dev/null || hostname
echo @@os; cat /etc/os-release 2>/dev/null | egrep '^(PRETTY_NAME|ID|VERSION_ID)='
echo @@kernel; uname -r
echo @@arch; uname -m
echo @@virt; systemd-detect-virt 2>/dev/null || echo unknown
echo @@product; (cat /sys/class/dmi/id/product_name 2>/dev/null; cat /sys/class/dmi/id/sys_vendor 2>/dev/null) | tr '\n' ' '
echo @@cpu; (grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2; echo cores=$(nproc 2>/dev/null))
echo @@mem; free -m 2>/dev/null | awk '/^Mem:/{print "total_mb="$2" used_mb="$3" free_mb="$4}'
echo @@disk; df -hPT -x tmpfs -x devtmpfs -x overlay 2>/dev/null | tail -n +2
echo @@ip; (ip -o -4 addr show 2>/dev/null | awk '{print $2" "$4}') || ifconfig -a 2>/dev/null | grep 'inet '
echo @@gw; ip route 2>/dev/null | awk '/^default/{print $3; exit}'
echo @@ports; (ss -tlnH 2>/dev/null || netstat -tln 2>/dev/null | tail -n +3) | awk '{print $4}' | sed 's/.*://' | sort -un | head -40 | tr '\n' ' '
echo @@services; systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | head -60 | tr '\n' ' '
echo @@pkgmgr; (command -v dnf >/dev/null && echo dnf) || (command -v yum >/dev/null && echo yum) || (command -v apt-get >/dev/null && echo apt) || (command -v zypper >/dev/null && echo zypper) || echo unknown
echo @@kernels; (rpm -q kernel 2>/dev/null || dpkg -l 'linux-image-*' 2>/dev/null | awk '/^ii/{print $2}') | tr '\n' ' '
echo @@selinux; getenforce 2>/dev/null || echo n/a
echo @@uptime; uptime -p 2>/dev/null || uptime
echo @@loadproc; (uptime | sed 's/.*load average/load average/'); echo procs=$(ps -e --no-headers 2>/dev/null | wc -l)
echo @@done
""".strip()


def _sections(text: str) -> dict:
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith("@@"):
            cur = line[2:].strip()
            out[cur] = ""
        elif cur is not None:
            out[cur] += line + "\n"
    return out


def _parse(sec: dict) -> dict:
    def g(k):
        return (sec.get(k) or "").strip()

    os_kv = {}
    for line in g("os").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            os_kv[k.strip()] = v.strip().strip('"')
    virt = g("virt") or "unknown"
    kind = "container" if virt in ("lxc", "docker", "podman", "systemd-nspawn") else \
           "physical" if virt in ("none", "", "unknown") else "virtual"
    if virt in ("none", ""):
        virt = "none"

    disks = []
    for line in g("disk").splitlines():
        parts = line.split()
        if len(parts) >= 7:
            disks.append({"fs": parts[0], "type": parts[1], "size": parts[2],
                          "used": parts[3], "avail": parts[4], "use%": parts[5],
                          "mount": parts[6]})
    ips = []
    for line in g("ip").splitlines():
        p = line.split()
        if len(p) >= 2 and p[0] != "lo":
            ips.append({"iface": p[0], "cidr": p[1]})

    cpu_txt = g("cpu")
    cpu_model = ""
    cores = None
    m = re.search(r"cores=(\d+)", cpu_txt)
    if m:
        cores = int(m.group(1))
    cm = re.search(r"^(.*?)(?:\n|$)", cpu_txt)
    if cm:
        cpu_model = cm.group(1).strip()
    mem = {}
    for kv in re.findall(r"(\w+)=(\d+)", g("mem")):
        mem[kv[0]] = int(kv[1])
    ports = [p for p in g("ports").split() if p.isdigit()]
    services = [s for s in g("services").split() if s.endswith(".service")]
    kernels = [k for k in g("kernels").split() if k]

    return {
        "hostname": g("hostname"),
        "os": os_kv.get("PRETTY_NAME") or os_kv.get("ID") or "unknown",
        "os_id": os_kv.get("ID", ""),
        "os_version": os_kv.get("VERSION_ID", ""),
        "os_family": _os_family(os_kv.get("ID", "")),
        "kernel": g("kernel"),
        "arch": g("arch"),
        "virtualization": virt,
        "machine_type": kind,             # physical | virtual | container
        "product": g("product"),
        "cpu_model": cpu_model,
        "cpu_cores": cores,
        "memory_mb": mem,
        "disks": disks,
        "ip_addresses": ips,
        "gateway": g("gw"),
        "listening_ports": ports,
        "running_services": services,
        "package_manager": g("pkgmgr"),
        "installed_kernels": kernels,
        "selinux": g("selinux"),
        "uptime": g("uptime"),
    }


def _os_family(os_id: str) -> str:
    i = (os_id or "").lower()
    if i in ("rhel", "centos", "rocky", "almalinux", "fedora", "ol", "oraclelinux"):
        return "rhel"
    if i in ("ubuntu", "debian", "raspbian", "linuxmint"):
        return "debian"
    if i in ("sles", "opensuse", "opensuse-leap", "suse"):
        return "suse"
    return i or "linux"


# Windows discovery: one PowerShell pass emitting a compact JSON object over
# WinRM. Read-only CIM/Get-* queries only.
_WIN_SCRIPT = r"""
$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='SilentlyContinue'
try {
 $os=Get-CimInstance Win32_OperatingSystem
 $cs=Get-CimInstance Win32_ComputerSystem
 $cpu=@(Get-CimInstance Win32_Processor)
 $cores=($cpu|Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
 # Win32_* CIM classes work on every supported Windows Server (no dependency
 # on the NetTCPIP/Storage modules, which older/Core installs may lack).
 $nics=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True")
 $ld=@(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3")
 $svc=@(Get-Service|Where-Object{$_.Status -eq 'Running'})
 $ports=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|Select-Object -ExpandProperty LocalPort -Unique)
 if(-not $ports){ $ports=@(netstat -an|Select-String 'LISTENING'|ForEach-Object{($_ -split '\s+')[2] -replace '.*:',''}|Where-Object{$_ -match '^\d+$'}|Sort-Object -Unique) }
 $hf=@(Get-HotFix -ErrorAction SilentlyContinue|Sort-Object InstalledOn -Descending|Select-Object -First 8)
 $pm=if(Get-Command winget -ErrorAction SilentlyContinue){'winget'}elseif(Get-Command choco -ErrorAction SilentlyContinue){'choco'}else{'windows'}
 $ips=@()
 foreach($n in $nics){ foreach($a in @($n.IPAddress)){ if($a -and $a -match '^\d+\.'){ $ips+=@{iface=$n.Description;ip=$a} } } }
 $gw=@($nics|ForEach-Object{$_.DefaultIPGateway}|Where-Object{$_ -and $_ -match '^\d+\.'})|Select-Object -First 1
 $o=[ordered]@{
  hostname=$(if($cs.Domain -and $cs.Domain -ne 'WORKGROUP'){"$($cs.DNSHostName).$($cs.Domain)"}else{$cs.Name})
  os=$os.Caption; os_version=$os.Version; build=$os.BuildNumber; arch=$os.OSArchitecture
  manufacturer=$cs.Manufacturer; model=$cs.Model
  cpu_model=($cpu|Select-Object -First 1 -ExpandProperty Name); cpu_cores=$cores
  total_mb=[int]($os.TotalVisibleMemorySize/1024); free_mb=[int]($os.FreePhysicalMemory/1024)
  last_boot=$(if($os.LastBootUpTime){$os.LastBootUpTime.ToString('s')}else{''})
  gateway=$gw
  ips=@($ips)
  disks=@($ld|ForEach-Object{@{mount=$_.DeviceID;label=$_.VolumeName;size_gb=[math]::Round($_.Size/1GB,1);free_gb=[math]::Round($_.FreeSpace/1GB,1)}})
  services=@($svc|ForEach-Object{$_.Name})
  ports=@($ports|ForEach-Object{[int]$_})
  hotfixes=@($hf|ForEach-Object{$_.HotFixID})
  pkgmgr=$pm
 }
 $o|ConvertTo-Json -Depth 5 -Compress
} catch {
 [ordered]@{discovery_error=$_.Exception.Message}|ConvertTo-Json -Compress
}
""".strip()


def _parse_windows(raw: dict) -> dict:
    total_mb = raw.get("total_mb")
    free_mb = raw.get("free_mb")
    used_mb = (total_mb - free_mb) if isinstance(total_mb, (int, float)) \
        and isinstance(free_mb, (int, float)) else None
    mem = {}
    if isinstance(total_mb, (int, float)):
        mem["total_mb"] = int(total_mb)
    if used_mb is not None:
        mem["used_mb"] = int(used_mb)
    if isinstance(free_mb, (int, float)):
        mem["free_mb"] = int(free_mb)

    ips = []
    for e in raw.get("ips") or []:
        if isinstance(e, dict) and e.get("ip"):
            ips.append({"iface": e.get("iface", ""),
                        "cidr": f"{e['ip']}/{e.get('prefix', '')}".rstrip("/")})
    disks = []
    for d in raw.get("disks") or []:
        if not isinstance(d, dict):
            continue
        size = d.get("size_gb") or 0
        free = d.get("free_gb") or 0
        pct = f"{round((size - free) / size * 100)}%" if size else "?"
        disks.append({"fs": d.get("label") or d.get("mount", ""), "type": "ntfs",
                      "size": f"{size}G", "used": f"{round(size - free, 1)}G",
                      "avail": f"{free}G", "use%": pct, "mount": d.get("mount", "")})
    model = " ".join(x for x in (raw.get("manufacturer"), raw.get("model")) if x).strip()
    virt = _win_virt(raw.get("manufacturer", ""), raw.get("model", ""))
    ports = [str(p) for p in (raw.get("ports") or []) if str(p).isdigit()]
    return {
        "hostname": raw.get("hostname") or "",
        "os": raw.get("os") or "Windows",
        "os_id": "windows",
        "os_version": str(raw.get("os_version") or ""),
        "os_family": "windows",
        "kernel": f"build {raw.get('build')}" if raw.get("build") else str(raw.get("os_version") or ""),
        "arch": raw.get("arch") or "",
        "virtualization": virt,
        "machine_type": "virtual" if virt != "none" else "physical",
        "product": model,
        "cpu_model": (raw.get("cpu_model") or "").strip(),
        "cpu_cores": raw.get("cpu_cores"),
        "memory_mb": mem,
        "disks": disks,
        "ip_addresses": ips,
        "gateway": raw.get("gateway") or "",
        "listening_ports": ports,
        "running_services": raw.get("services") or [],
        "package_manager": raw.get("pkgmgr") or "windows",
        "installed_kernels": raw.get("hotfixes") or [],   # latest hotfixes ~ patch level
        "selinux": "n/a",
        "uptime": f"since {raw.get('last_boot')}" if raw.get("last_boot") else "",
    }


def _win_virt(manufacturer: str, model: str) -> str:
    blob = f"{manufacturer} {model}".lower()
    if "vmware" in blob:
        return "vmware"
    if "microsoft" in blob and "virtual" in blob:
        return "hyperv"
    if "kvm" in blob or "qemu" in blob:
        return "kvm"
    if "xen" in blob:
        return "xen"
    if "virtualbox" in blob or "innotek" in blob:
        return "virtualbox"
    return "none"


async def _discover_windows(server: Server) -> dict:
    from . import winexec
    # Get-HotFix + several CIM queries can take a while; give it room.
    res = await winexec.run_ps(server, _WIN_SCRIPT, timeout=120)
    text = (res.get("output") or "").lstrip("﻿").strip()
    if not res.get("ok") and not text:
        return _save(server.name, {"ok": False, "ts": time.time(),
                                   "error": (res.get("output") or "WinRM discovery failed")[:300]})
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return _save(server.name, {"ok": False, "ts": time.time(),
                                   "error": f"unexpected discovery output: {text[:200] or '(empty)'}"})
    try:
        raw = json.loads(m.group())
    except json.JSONDecodeError as exc:
        return _save(server.name, {"ok": False, "ts": time.time(),
                                   "error": f"could not parse discovery JSON: {exc}: {text[:200]}"})
    if raw.get("discovery_error"):
        return _save(server.name, {"ok": False, "ts": time.time(),
                                   "error": f"PowerShell: {raw['discovery_error']}"[:300]})
    return _save(server.name, {"ok": True, "ts": time.time(), "facts": _parse_windows(raw)})


async def discover(server: Server) -> dict:
    """Gather facts over the server's transport, cache and return them.

    Windows hosts (platform: windows) are probed with PowerShell over WinRM;
    everything else over SSH. Both use read-only commands only.
    """
    if server.is_windows:
        return await _discover_windows(server)
    try:
        proc = await asyncio.create_subprocess_exec(
            *server.ssh_command().split(), _SCRIPT,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
        rc = proc.returncode
    except asyncio.TimeoutError:
        proc.kill()
        return _save(server.name, {"ok": False, "ts": time.time(),
                                   "error": f"discovery timed out after {TIMEOUT}s"})
    except OSError as exc:
        return _save(server.name, {"ok": False, "ts": time.time(), "error": str(exc)})
    text = out.decode(errors="replace")
    if "@@done" not in text:
        snippet = " ".join(text.split())[:200]
        return _save(server.name, {"ok": False, "ts": time.time(),
                                   "error": f"could not reach the server (exit {rc}): {snippet}"})
    facts = _parse(_sections(text))
    return _save(server.name, {"ok": True, "ts": time.time(), "facts": facts})


def facts_summary(name: str) -> str:
    """Compact text block for injecting discovered facts into AI prompts."""
    d = load_facts(name)
    if not d or not d.get("ok"):
        return ""
    f = d["facts"]
    parts = [
        f"Host {f.get('hostname') or name}: {f.get('os', 'unknown OS')} "
        f"(family {f.get('os_family')}, kernel {f.get('kernel')}, {f.get('arch')})",
        f"{f.get('machine_type')} ({f.get('virtualization')})"
        + (f" on {f['product'].strip()}" if f.get("product", "").strip() else ""),
        f"package manager: {f.get('package_manager')}; SELinux: {f.get('selinux')}",
    ]
    if f.get("cpu_cores"):
        parts.append(f"{f.get('cpu_cores')} vCPU, "
                     f"{(f.get('memory_mb') or {}).get('total_mb', '?')} MB RAM")
    ips = ", ".join(x["cidr"] for x in (f.get("ip_addresses") or [])[:6])
    if ips:
        parts.append(f"IPs: {ips}; gateway {f.get('gateway') or '?'}")
    disks = "; ".join(f"{d['mount']} {d['use%']} of {d['size']}"
                      for d in (f.get("disks") or [])[:8])
    if disks:
        parts.append(f"filesystems: {disks}")
    svc = ", ".join(s.replace(".service", "") for s in (f.get("running_services") or [])[:20])
    if svc:
        parts.append(f"running services: {svc}")
    if f.get("installed_kernels"):
        parts.append("installed kernels: " + ", ".join(f["installed_kernels"][:6]))
    if f.get("listening_ports"):
        parts.append("listening ports: " + ", ".join(f["listening_ports"][:20]))
    return "\n".join(parts)
