"""
env_fingerprint.py – Automated environment fingerprinting for incident response.

Captures a point-in-time snapshot of the target host's operating environment:
    • OS version, hostname, domain, current user, uptime
    • Running processes (name, PID, PPID, user, CPU%, memory)
    • Network interfaces and IP addresses
    • ARP table (IP ↔ MAC mappings)
    • Active TCP connections (local ↔ remote, state, owning PID)
    • Recent Windows Event Log entries (last 50 System events)

The snapshot is saved as a structured JSON file in ``data/logs/`` and
automatically logged to the custody chain.

All data is gathered from the local machine using ``psutil`` and standard
Windows commands — no network calls are made.
"""

import datetime
import json
import os
import platform
import subprocess
import time
from typing import Any, Dict, List, Optional

import psutil

import config


# ── Public API ───────────────────────────────────────────────────────

def capture_snapshot(custody_logger=None) -> Dict[str, Any]:
    """Capture a full environment fingerprint of the host.

    Parameters
    ----------
    custody_logger : CustodyLogger, optional
        If provided, the snapshot is recorded to the forensic audit trail.

    Returns
    -------
    dict
        Structured snapshot with sections: ``system``, ``processes``,
        ``network_interfaces``, ``arp_table``, ``tcp_connections``,
        ``recent_events``.
    """
    snapshot: Dict[str, Any] = {
        "captured_at": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(timespec="seconds"),
        "system": _get_system_info(),
        "processes": _get_processes(),
        "network_interfaces": _get_network_interfaces(),
        "arp_table": _get_arp_table(),
        "tcp_connections": _get_tcp_connections(),
        "recent_events": _get_recent_events(),
    }

    # Persist to disk.
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(config.LOGS_DIR, f"fingerprint_{ts}.json")
    os.makedirs(config.LOGS_DIR, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False, default=str)

    snapshot["_saved_to"] = out_path

    if custody_logger:
        proc_count = len(snapshot.get("processes", []))
        iface_count = len(snapshot.get("network_interfaces", []))
        conn_count = len(snapshot.get("tcp_connections", []))
        custody_logger.record(
            "env_fingerprint", "env_fingerprint",
            target=out_path,
            detail=(f"Processes: {proc_count}, "
                    f"Interfaces: {iface_count}, "
                    f"TCP connections: {conn_count}"),
        )

    return snapshot


def format_snapshot(snapshot: Dict[str, Any]) -> str:
    """Convert a snapshot dict into a human-readable multi-section string.

    This is what gets displayed in the GUI textbox.
    """
    lines: List[str] = []
    _sep = "-" * 60

    # ── System ───────────────────────────────────────────────────
    lines.append("SYSTEM INFORMATION")
    lines.append(_sep)
    sys_info = snapshot.get("system", {})
    for key in ["hostname", "os", "os_version", "architecture",
                "domain", "current_user", "uptime", "boot_time"]:
        val = sys_info.get(key, "N/A")
        label = key.replace("_", " ").title()
        lines.append(f"  {label:20s}: {val}")
    lines.append("")

    # ── Processes ─────────────────────────────────────────────────
    procs = snapshot.get("processes", [])
    lines.append(f"RUNNING PROCESSES ({len(procs)} total)")
    lines.append(_sep)
    lines.append(f"  {'PID':>7s}  {'PPID':>7s}  {'CPU%':>5s}  "
                 f"{'MEM MB':>7s}  {'USER':20s}  NAME")
    lines.append(f"  {'---':>7s}  {'----':>7s}  {'----':>5s}  "
                 f"{'------':>7s}  {'----':20s}  ----")
    for p in procs[:100]:  # cap display at 100
        lines.append(
            f"  {p.get('pid', '?'):>7}  {p.get('ppid', '?'):>7}  "
            f"{p.get('cpu_percent', 0):>5.1f}  "
            f"{p.get('memory_mb', 0):>7.1f}  "
            f"{str(p.get('username', 'N/A'))[:20]:20s}  "
            f"{p.get('name', 'N/A')}"
        )
    if len(procs) > 100:
        lines.append(f"  ... and {len(procs) - 100} more")
    lines.append("")

    # ── Network Interfaces ───────────────────────────────────────
    ifaces = snapshot.get("network_interfaces", [])
    lines.append(f"NETWORK INTERFACES ({len(ifaces)} total)")
    lines.append(_sep)
    for iface in ifaces:
        lines.append(f"  [{iface.get('name', '?')}]")
        for addr in iface.get("addresses", []):
            lines.append(f"    {addr.get('family', '?'):6s}  {addr.get('address', 'N/A')}")
    lines.append("")

    # ── ARP Table ────────────────────────────────────────────────
    arp = snapshot.get("arp_table", [])
    lines.append(f"ARP TABLE ({len(arp)} entries)")
    lines.append(_sep)
    for entry in arp[:50]:
        lines.append(f"  {entry.get('ip', '?'):18s}  {entry.get('mac', '?'):20s}  "
                     f"{entry.get('type', '?')}")
    if len(arp) > 50:
        lines.append(f"  ... and {len(arp) - 50} more")
    lines.append("")

    # ── TCP Connections ──────────────────────────────────────────
    conns = snapshot.get("tcp_connections", [])
    lines.append(f"ACTIVE TCP CONNECTIONS ({len(conns)} total)")
    lines.append(_sep)
    lines.append(f"  {'LOCAL':30s}  {'REMOTE':30s}  {'STATE':14s}  PID")
    for c in conns[:80]:
        lines.append(
            f"  {c.get('local', '?'):30s}  {c.get('remote', '?'):30s}  "
            f"{c.get('status', '?'):14s}  {c.get('pid', '?')}"
        )
    if len(conns) > 80:
        lines.append(f"  ... and {len(conns) - 80} more")
    lines.append("")

    # ── Recent Events ────────────────────────────────────────────
    events = snapshot.get("recent_events", [])
    lines.append(f"RECENT SYSTEM EVENTS ({len(events)} entries)")
    lines.append(_sep)
    for evt in events:
        lines.append(f"  [{evt.get('level', '?'):8s}]  "
                     f"{evt.get('time', '?'):22s}  "
                     f"Source: {evt.get('source', '?'):20s}  "
                     f"ID: {evt.get('event_id', '?')}")
        if evt.get("message"):
            # Show first line of the message only
            msg_line = evt["message"].split("\n")[0][:120]
            lines.append(f"             {msg_line}")
    lines.append("")

    # ── Footer ───────────────────────────────────────────────────
    saved = snapshot.get("_saved_to", "N/A")
    lines.append(f"Snapshot saved to: {saved}")
    lines.append(f"Captured at: {snapshot.get('captured_at', 'N/A')}")

    return "\n".join(lines)


# ── Internal data gatherers ──────────────────────────────────────────

def _get_system_info() -> Dict[str, str]:
    """Gather OS, hostname, user, uptime."""
    boot = psutil.boot_time()
    uptime_seconds = time.time() - boot
    hours, remainder = divmod(int(uptime_seconds), 3600)
    minutes, seconds = divmod(remainder, 60)

    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "domain": os.environ.get("USERDOMAIN", "N/A"),
        "current_user": os.environ.get("USERNAME", "N/A"),
        "uptime": f"{hours}h {minutes}m {seconds}s",
        "boot_time": datetime.datetime.fromtimestamp(
            boot, tz=datetime.timezone.utc
        ).isoformat(timespec="seconds"),
    }


def _get_processes() -> List[Dict[str, Any]]:
    """Snapshot all running processes."""
    procs = []
    for p in psutil.process_iter(
        ["pid", "ppid", "name", "username", "cpu_percent", "memory_info"]
    ):
        try:
            info = p.info
            mem = info.get("memory_info")
            procs.append({
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name", "N/A"),
                "username": info.get("username", "N/A"),
                "cpu_percent": info.get("cpu_percent", 0.0),
                "memory_mb": round(mem.rss / (1024 * 1024), 1) if mem else 0.0,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return procs


def _get_network_interfaces() -> List[Dict[str, Any]]:
    """List network interfaces and their addresses."""
    result = []
    for name, addrs in psutil.net_if_addrs().items():
        iface: Dict[str, Any] = {"name": name, "addresses": []}
        for addr in addrs:
            family = str(addr.family).split(".")[-1]  # e.g. "AF_INET"
            iface["addresses"].append({
                "family": family,
                "address": addr.address,
                "netmask": addr.netmask,
            })
        result.append(iface)
    return result


def _get_arp_table() -> List[Dict[str, str]]:
    """Parse the ARP table via ``arp -a`` command."""
    try:
        result = subprocess.run(
            ["arp", "-a"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            creationflags=(
                subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
                if platform.system() == "Windows" else 0
            ),
        )
        if result.returncode != 0:
            return []

        entries = []
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            # Windows arp -a format: "  192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic"
            parts = line.split()
            if len(parts) >= 3 and "." in parts[0]:
                entries.append({
                    "ip": parts[0],
                    "mac": parts[1],
                    "type": parts[2] if len(parts) > 2 else "unknown",
                })
        return entries
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []


def _get_tcp_connections() -> List[Dict[str, Any]]:
    """List active TCP connections with owning PIDs."""
    conns = []
    for c in psutil.net_connections(kind="tcp"):
        local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A"
        remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"
        conns.append({
            "local": local,
            "remote": remote,
            "status": c.status,
            "pid": c.pid,
        })
    return conns


def _get_recent_events() -> List[Dict[str, str]]:
    """Fetch the last 50 System event log entries via ``wevtutil``.

    Only runs on Windows.  Returns an empty list on other platforms
    or if the command fails.
    """
    if platform.system() != "Windows":
        return []

    try:
        result = subprocess.run(
            [
                "wevtutil", "qe", "System",
                "/c:50", "/rd:true", "/f:text",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
        )
        if result.returncode != 0:
            return []

        events = []
        current: Dict[str, str] = {}
        for line in result.stdout.decode("utf-8", errors="replace").replace("\x00", "").splitlines():
            line = line.strip()
            if not line:
                if current:
                    events.append(current)
                    current = {}
                continue

            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()

                if key == "event":
                    current = {}
                elif key == "log name":
                    current["log"] = value
                elif key == "source":
                    current["source"] = value
                elif key == "date":
                    current["time"] = value
                elif key == "event id":
                    current["event_id"] = value
                elif key == "level":
                    current["level"] = value
                elif key == "description":
                    current["message"] = value

        if current:
            events.append(current)

        return events

    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []


# ── Quick self-test ──────────────────────────────────────────────────
if __name__ == "__main__":
    print("Capturing environment fingerprint...")
    snap = capture_snapshot()
    print()
    print(format_snapshot(snap))
    print()
    print(f"Saved to: {snap.get('_saved_to', 'N/A')}")
