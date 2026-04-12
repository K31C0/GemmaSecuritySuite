"""
network_scanner.py – Lightweight network diagnostics toolkit.

Provides the NetworkTools class with:
  • quick_ping(host)          – ICMP ping via subprocess
  • scan_ports(host, ports)   – TCP connect-scan via socket
  • run_network_diagnostics() – runs both on a background thread
"""

import platform
import socket
import subprocess
import threading
from typing import Callable, Dict, List, Optional, Tuple


# Common ports to probe when no custom list is supplied.
DEFAULT_PORTS: List[int] = [22, 53, 80, 443, 445, 3389, 8080, 8443]

# Per-port timeout for the TCP connect scan (seconds).
_CONNECT_TIMEOUT = 1.5


class NetworkTools:
    """Collection of non-blocking network diagnostic helpers.

    All heavy work can be dispatched to a background thread via
    :meth:`run_network_diagnostics` so a GUI caller never blocks.
    """

    def __init__(self, connect_timeout: float = _CONNECT_TIMEOUT) -> None:
        self._connect_timeout = connect_timeout
        self._thread: Optional[threading.Thread] = None
        self._busy = False

    # ------------------------------------------------------------------
    #  Ping
    # ------------------------------------------------------------------

    def quick_ping(self, host: str, count: int = 2) -> Tuple[bool, str]:
        """Send ICMP echo requests to *host*.

        Parameters
        ----------
        host : str
            Hostname or IP address.
        count : int
            Number of echo requests (``-n`` on Windows, ``-c`` elsewhere).

        Returns
        -------
        (alive, raw_output) : tuple[bool, str]
            *alive* is ``True`` when the host responds to at least one
            request.  *raw_output* is the decoded stdout/stderr from
            the ping process.
        """
        is_windows = platform.system().lower() == "windows"
        flag = "-n" if is_windows else "-c"

        try:
            result = subprocess.run(
                ["ping", flag, str(count), host],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=count * 5 + 5,     # generous upper bound
                creationflags=(
                    subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
                    if is_windows else 0
                ),
            )
            raw = result.stdout.decode("utf-8", errors="replace")
            alive = result.returncode == 0
        except FileNotFoundError:
            raw = "Error: 'ping' command not found on this system."
            alive = False
        except subprocess.TimeoutExpired:
            raw = f"Error: ping to {host} timed out."
            alive = False
        except Exception as exc:
            raw = f"Error: {exc}"
            alive = False

        return alive, raw

    # ------------------------------------------------------------------
    #  Port scan
    # ------------------------------------------------------------------

    def scan_ports(
        self,
        host: str,
        ports: Optional[List[int]] = None,
    ) -> Dict[int, str]:
        """Attempt a TCP connect to each port in *ports*.

        Parameters
        ----------
        host : str
            Target hostname or IP address.
        ports : list[int], optional
            Ports to probe.  Defaults to :data:`DEFAULT_PORTS`.

        Returns
        -------
        dict[int, str]
            Mapping of ``{port: "open" | "closed" | "error: …"}``.
        """
        if ports is None:
            ports = DEFAULT_PORTS

        results: Dict[int, str] = {}

        for port in sorted(ports):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self._connect_timeout)
                    err = s.connect_ex((host, port))
                    results[port] = "open" if err == 0 else "closed"
            except socket.timeout:
                results[port] = "closed"
            except socket.gaierror:
                results[port] = "error: DNS resolution failed"
            except OSError as exc:
                results[port] = f"error: {exc}"

        return results

    # ------------------------------------------------------------------
    #  Combined diagnostics (threaded)
    # ------------------------------------------------------------------

    @property
    def is_busy(self) -> bool:
        """``True`` while a background diagnostic is running."""
        return self._busy

    def run_network_diagnostics(
        self,
        host: str,
        callback: Callable[[str], None],
        ports: Optional[List[int]] = None,
    ) -> None:
        """Run a full ping + port scan on a background thread.

        Parameters
        ----------
        host : str
            Target hostname or IP address.
        callback : callable(str) -> None
            Invoked **on the background thread** with a single
            formatted results string once both tests complete.
            GUI callers should marshal this onto the main thread
            (e.g. via ``app.after(0, callback, text)``).
        ports : list[int], optional
            Custom port list; falls back to :data:`DEFAULT_PORTS`.
        """
        if self._busy:
            callback("A scan is already in progress.")
            return

        self._busy = True
        self._thread = threading.Thread(
            target=self._diagnostics_worker,
            args=(host, callback, ports),
            daemon=True,
            name="NetworkTools-Diag",
        )
        self._thread.start()

    # ------------------------------------------------------------------
    #  Internal worker
    # ------------------------------------------------------------------

    def _diagnostics_worker(
        self,
        host: str,
        callback: Callable[[str], None],
        ports: Optional[List[int]],
    ) -> None:
        lines: list[str] = []

        try:
            # ── Ping ─────────────────────────────────────────────────
            lines.append(f"=== Ping: {host} ===\n")
            alive, raw = self.quick_ping(host)
            status = "REACHABLE" if alive else "UNREACHABLE"
            lines.append(f"Status: {status}\n")
            lines.append(raw.strip() + "\n")

            # ── Port scan ────────────────────────────────────────────
            lines.append(f"\n=== Port Scan: {host} ===\n")
            port_results = self.scan_ports(host, ports)

            # Determine column width for tidy output.
            for port, state in port_results.items():
                svc = _well_known_service(port)
                label = f"  {port:>5}/tcp  ({svc})" if svc else f"  {port:>5}/tcp"
                lines.append(f"{label:<30} {state}\n")

            open_count = sum(1 for v in port_results.values() if v == "open")
            lines.append(f"\nOpen ports: {open_count}/{len(port_results)}\n")

        except Exception as exc:
            lines.append(f"\nDiagnostics error: {exc}\n")
        finally:
            self._busy = False

        callback("".join(lines))


# ------------------------------------------------------------------
#  Utility
# ------------------------------------------------------------------

_SERVICES: Dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def _well_known_service(port: int) -> str:
    """Return a human-friendly service name for *port*, or ``""``."""
    return _SERVICES.get(port, "")


# ------------------------------------------------------------------
#  Quick self-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    import time

    tools = NetworkTools()

    # Synchronous usage
    print("--- Synchronous ping ---")
    alive, raw = tools.quick_ping("8.8.8.8")
    print(f"Alive: {alive}\n{raw}\n")

    print("--- Synchronous port scan ---")
    results = tools.scan_ports("8.8.8.8", [53, 80, 443])
    for p, s in results.items():
        print(f"  {p}: {s}")

    # Threaded usage
    print("\n--- Threaded diagnostics ---")
    done = threading.Event()

    def on_result(text: str) -> None:
        print(text)
        done.set()

    tools.run_network_diagnostics("8.8.8.8", callback=on_result, ports=[53, 80, 443])
    done.wait(timeout=30)
