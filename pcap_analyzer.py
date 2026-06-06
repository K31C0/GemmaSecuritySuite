"""
pcap_analyzer.py – Offline PCAP traffic analysis for forensic investigations.

Uses **dpkt** (pure Python, PyInstaller-friendly) to parse .pcap files and
extract security-relevant artefacts:

    • DNS queries  — resolved hostnames (potential C2 domains)
    • HTTP cleartext — URLs, headers, POST bodies (data exfiltration)
    • TLS SNI fields — encrypted destinations (domain fronting detection)
    • Beaconing patterns — periodic outbound connections (C2 check-in)

All findings are returned as typed dataclasses and can be serialised to
a human-readable summary suitable for injection into an LLM prompt.

Dependency: ``dpkt`` (pip install dpkt) — pure Python, no C extensions.
"""

import collections
import datetime
import os
import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False


# ── Data classes ─────────────────────────────────────────────────────

@dataclass
class DnsQuery:
    """A single DNS query extracted from the capture."""
    timestamp: str
    src_ip: str
    dst_ip: str
    query_name: str
    query_type: str   # "A", "AAAA", "MX", "CNAME", etc.
    response_ips: List[str] = field(default_factory=list)


@dataclass
class HttpRequest:
    """A cleartext HTTP request extracted from the capture."""
    timestamp: str
    src_ip: str
    dst_ip: str
    method: str       # GET, POST, etc.
    host: str
    uri: str
    user_agent: str
    content_type: str
    body_preview: str  # first 512 chars of POST body


@dataclass
class TlsSni:
    """A TLS ClientHello SNI field extracted from the capture."""
    timestamp: str
    src_ip: str
    dst_ip: str
    server_name: str


@dataclass
class BeaconPattern:
    """A suspected beaconing pattern — periodic outbound connections."""
    dst_ip: str
    dst_port: int
    connection_count: int
    avg_interval_seconds: float
    std_dev_seconds: float
    first_seen: str
    last_seen: str


# ── DNS record type mapping ──────────────────────────────────────────

_DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


# ── Helpers ──────────────────────────────────────────────────────────

def _inet_to_str(inet: bytes) -> str:
    """Convert a packed IP address to a dotted-quad or IPv6 string."""
    try:
        if len(inet) == 4:
            return socket.inet_ntoa(inet)
        elif len(inet) == 16:
            return socket.inet_ntop(socket.AF_INET6, inet)
    except Exception:
        pass
    return "?.?.?.?"


def _ts_to_str(ts: float) -> str:
    """Convert a Unix timestamp to a human-readable UTC string."""
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _parse_tls_sni(tcp_data: bytes) -> Optional[str]:
    """Extract the SNI hostname from a TLS ClientHello message.

    Returns None if the data does not contain a valid ClientHello or
    the SNI extension is not present.
    """
    try:
        # TLS record header: ContentType(1) + Version(2) + Length(2)
        if len(tcp_data) < 5:
            return None
        content_type = tcp_data[0]
        if content_type != 22:  # Handshake
            return None

        # Handshake header starts at offset 5
        # HandshakeType(1) + Length(3) + ...
        if len(tcp_data) < 6:
            return None
        handshake_type = tcp_data[5]
        if handshake_type != 1:  # ClientHello
            return None

        # Skip to extensions — variable-length fields make this tricky.
        # Use a simple scan for the SNI extension (type 0x0000).
        # The SNI extension format:
        #   ExtType(2=0x0000) + ExtLen(2) + SNIListLen(2)
        #   + SNIType(1=0x00) + SNILen(2) + hostname
        data = tcp_data[5:]  # from handshake type onward
        # Search for the SNI extension marker
        idx = 0
        while idx < len(data) - 9:
            # Look for extension type 0x0000 (server_name)
            if data[idx] == 0x00 and data[idx + 1] == 0x00:
                # Candidate — verify structure
                ext_len = struct.unpack("!H", data[idx + 2:idx + 4])[0]
                if ext_len > 0 and idx + 4 + ext_len <= len(data):
                    sni_list_start = idx + 4
                    # SNI list length (2 bytes), then SNI type (1 byte, 0=hostname)
                    if sni_list_start + 5 <= len(data):
                        sni_type = data[sni_list_start + 2]
                        if sni_type == 0x00:
                            name_len = struct.unpack(
                                "!H",
                                data[sni_list_start + 3:sni_list_start + 5],
                            )[0]
                            name_start = sni_list_start + 5
                            if name_start + name_len <= len(data):
                                hostname = data[name_start:name_start + name_len]
                                try:
                                    return hostname.decode("ascii")
                                except UnicodeDecodeError:
                                    return hostname.decode("latin-1")
            idx += 1
    except Exception:
        pass
    return None


# ── Main analyser class ──────────────────────────────────────────────

class PcapAnalyzer:
    """Offline PCAP traffic analyser for incident response.

    Usage::

        analyzer = PcapAnalyzer()
        analyzer.load("capture.pcap")
        dns = analyzer.extract_dns_queries()
        http = analyzer.extract_http_cleartext()
        sni = analyzer.extract_tls_sni()
        beacons = analyzer.detect_beaconing()
        print(analyzer.summarize())

    Parameters
    ----------
    custody_logger : CustodyLogger, optional
        If provided, key analysis events are logged to the forensic
        chain of custody.
    """

    def __init__(self, custody_logger=None) -> None:
        self._custody = custody_logger
        self._packets: list = []          # list of (timestamp, buf) tuples
        self._path: Optional[str] = None
        self._total_bytes: int = 0
        self._link_type: int = 1          # default to Ethernet (DLT_EN10MB)

        # Cached results — populated by extract_* methods.
        self._dns_queries: Optional[List[DnsQuery]] = None
        self._http_requests: Optional[List[HttpRequest]] = None
        self._tls_sni: Optional[List[TlsSni]] = None
        self._beacons: Optional[List[BeaconPattern]] = None

    # ── Loading ──────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        """``True`` if dpkt is installed and a PCAP file is loaded."""
        return DPKT_AVAILABLE and len(self._packets) > 0

    @property
    def packet_count(self) -> int:
        return len(self._packets)

    @property
    def file_path(self) -> Optional[str]:
        return self._path

    def load(self, pcap_path: str) -> int:
        """Read a ``.pcap`` file and store packets in memory.

        Parameters
        ----------
        pcap_path : str
            Path to a standard ``.pcap`` file (libpcap format).

        Returns
        -------
        int
            Number of packets loaded.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        RuntimeError
            If dpkt is not installed.
        ValueError
            If the file cannot be parsed.
        """
        if not DPKT_AVAILABLE:
            raise RuntimeError(
                "dpkt is not installed. Install with: pip install dpkt"
            )

        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        self._packets.clear()
        self._dns_queries = None
        self._http_requests = None
        self._tls_sni = None
        self._beacons = None
        self._total_bytes = 0
        self._path = pcap_path

        try:
            with open(pcap_path, "rb") as fh:
                pcap_reader = dpkt.pcap.Reader(fh)
                self._link_type = pcap_reader.datalink()
                for ts, buf in pcap_reader:
                    self._packets.append((ts, buf))
                    self._total_bytes += len(buf)
        except Exception as exc:
            raise ValueError(
                f"Failed to parse PCAP file: {exc}"
            ) from exc

        if self._custody:
            self._custody.record(
                "pcap_loaded", "pcap_analyzer",
                target=pcap_path,
                detail=f"{len(self._packets)} packets, "
                       f"{self._total_bytes:,} bytes",
            )

        return len(self._packets)

    # ── IP extraction helper ─────────────────────────────────────────

    def _extract_ip(self, buf: bytes):
        """Extract the IP layer from a raw packet buffer.

        Returns (ip_obj, src_ip_str, dst_ip_str) or (None, None, None).
        """
        try:
            if self._link_type == 1:  # Ethernet
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    return ip, _inet_to_str(ip.src), _inet_to_str(ip.dst)
                elif isinstance(eth.data, dpkt.ip6.IP6):
                    ip6 = eth.data
                    return ip6, _inet_to_str(ip6.src), _inet_to_str(ip6.dst)
            elif self._link_type == 101:  # Raw IP
                # Try IPv4 first
                version = (buf[0] >> 4) & 0xF
                if version == 4:
                    ip = dpkt.ip.IP(buf)
                    return ip, _inet_to_str(ip.src), _inet_to_str(ip.dst)
                elif version == 6:
                    ip6 = dpkt.ip6.IP6(buf)
                    return ip6, _inet_to_str(ip6.src), _inet_to_str(ip6.dst)
        except Exception:
            pass
        return None, None, None

    # ── DNS extraction ───────────────────────────────────────────────

    def extract_dns_queries(self) -> List[DnsQuery]:
        """Extract all DNS queries from the loaded capture.

        Returns a cached result on subsequent calls.
        """
        if self._dns_queries is not None:
            return self._dns_queries

        results: List[DnsQuery] = []

        for ts, buf in self._packets:
            ip, src, dst = self._extract_ip(buf)
            if ip is None:
                continue

            # DNS runs over UDP port 53 (and sometimes TCP 53)
            transport = ip.data
            if not isinstance(transport, (dpkt.udp.UDP, dpkt.tcp.TCP)):
                continue

            if transport.dport != 53 and transport.sport != 53:
                continue

            try:
                dns_data = transport.data
                if isinstance(transport, dpkt.tcp.TCP):
                    # TCP DNS has a 2-byte length prefix
                    if len(dns_data) < 2:
                        continue
                    dns_data = dns_data[2:]

                dns = dpkt.dns.DNS(dns_data)
            except Exception:
                continue

            # We care about queries (QR=0) and responses (QR=1).
            for qd in dns.qd:
                qtype = _DNS_TYPES.get(qd.type, f"TYPE{qd.type}")
                qname = qd.name if isinstance(qd.name, str) else qd.name.decode("utf-8", errors="replace")

                # Collect response IPs if this is a response
                response_ips = []
                if dns.qr == 1:  # response
                    for an in dns.an:
                        if an.type == dpkt.dns.DNS_A:
                            try:
                                response_ips.append(socket.inet_ntoa(an.rdata))
                            except Exception:
                                pass
                        elif an.type == dpkt.dns.DNS_AAAA:
                            try:
                                response_ips.append(
                                    socket.inet_ntop(socket.AF_INET6, an.rdata))
                            except Exception:
                                pass

                results.append(DnsQuery(
                    timestamp=_ts_to_str(ts),
                    src_ip=src,
                    dst_ip=dst,
                    query_name=qname,
                    query_type=qtype,
                    response_ips=response_ips,
                ))

        self._dns_queries = results

        if self._custody:
            self._custody.record(
                "pcap_dns_extracted", "pcap_analyzer",
                detail=f"{len(results)} DNS queries found",
            )

        return results

    # ── HTTP cleartext extraction ────────────────────────────────────

    def extract_http_cleartext(self) -> List[HttpRequest]:
        """Extract cleartext HTTP requests from the loaded capture.

        Only captures HTTP requests (not responses). POST body is
        truncated to the first 512 characters.
        """
        if self._http_requests is not None:
            return self._http_requests

        results: List[HttpRequest] = []

        for ts, buf in self._packets:
            ip, src, dst = self._extract_ip(buf)
            if ip is None:
                continue

            transport = ip.data
            if not isinstance(transport, dpkt.tcp.TCP):
                continue

            # Common HTTP ports
            if transport.dport not in (80, 8080, 8000, 8888):
                continue

            tcp_data = transport.data
            if not tcp_data:
                continue

            try:
                http_req = dpkt.http.Request(tcp_data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
            except Exception:
                continue

            body = ""
            if http_req.body:
                raw_body = http_req.body
                if isinstance(raw_body, bytes):
                    raw_body = raw_body.decode("utf-8", errors="replace")
                body = raw_body[:512]

            results.append(HttpRequest(
                timestamp=_ts_to_str(ts),
                src_ip=src,
                dst_ip=dst,
                method=http_req.method,
                host=http_req.headers.get("host", dst),
                uri=http_req.uri,
                user_agent=http_req.headers.get("user-agent", ""),
                content_type=http_req.headers.get("content-type", ""),
                body_preview=body,
            ))

        self._http_requests = results

        if self._custody:
            self._custody.record(
                "pcap_http_extracted", "pcap_analyzer",
                detail=f"{len(results)} HTTP requests found",
            )

        return results

    # ── TLS SNI extraction ───────────────────────────────────────────

    def extract_tls_sni(self) -> List[TlsSni]:
        """Extract TLS ClientHello SNI fields from the capture.

        This reveals which hostnames were contacted over HTTPS without
        needing to decrypt the traffic.
        """
        if self._tls_sni is not None:
            return self._tls_sni

        results: List[TlsSni] = []
        seen = set()  # deduplicate by (src, dst, hostname)

        for ts, buf in self._packets:
            ip, src, dst = self._extract_ip(buf)
            if ip is None:
                continue

            transport = ip.data
            if not isinstance(transport, dpkt.tcp.TCP):
                continue

            tcp_data = transport.data
            if not tcp_data or len(tcp_data) < 6:
                continue

            hostname = _parse_tls_sni(tcp_data)
            if hostname:
                key = (src, dst, hostname)
                if key not in seen:
                    seen.add(key)
                    results.append(TlsSni(
                        timestamp=_ts_to_str(ts),
                        src_ip=src,
                        dst_ip=dst,
                        server_name=hostname,
                    ))

        self._tls_sni = results

        if self._custody:
            self._custody.record(
                "pcap_tls_sni_extracted", "pcap_analyzer",
                detail=f"{len(results)} unique TLS SNI hostnames found",
            )

        return results

    # ── Beaconing detection ──────────────────────────────────────────

    def detect_beaconing(
        self,
        threshold_seconds: float = 60.0,
        min_connections: int = 5,
    ) -> List[BeaconPattern]:
        """Detect periodic outbound connection patterns (C2 beaconing).

        A beacon is defined as repeated connections to the same
        (dst_ip, dst_port) with regular timing intervals.

        Parameters
        ----------
        threshold_seconds : float
            Maximum standard deviation of intervals to flag as beaconing.
        min_connections : int
            Minimum number of connections to consider.
        """
        if self._beacons is not None:
            return self._beacons

        # Group outbound TCP SYN packets by (dst_ip, dst_port)
        connections: dict[tuple, list] = collections.defaultdict(list)

        for ts, buf in self._packets:
            ip, src, dst = self._extract_ip(buf)
            if ip is None:
                continue

            transport = ip.data
            if not isinstance(transport, dpkt.tcp.TCP):
                continue

            # Only count SYN packets (connection initiations)
            if transport.flags & dpkt.tcp.TH_SYN and not (transport.flags & dpkt.tcp.TH_ACK):
                key = (dst, transport.dport)
                connections[key].append(ts)

        results: List[BeaconPattern] = []

        for (dst_ip, dst_port), timestamps in connections.items():
            if len(timestamps) < min_connections:
                continue

            timestamps.sort()
            intervals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]

            if not intervals:
                continue

            avg = sum(intervals) / len(intervals)
            variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5

            if std_dev <= threshold_seconds:
                results.append(BeaconPattern(
                    dst_ip=dst_ip if isinstance(dst_ip, str) else _inet_to_str(dst_ip),
                    dst_port=dst_port,
                    connection_count=len(timestamps),
                    avg_interval_seconds=round(avg, 2),
                    std_dev_seconds=round(std_dev, 2),
                    first_seen=_ts_to_str(timestamps[0]),
                    last_seen=_ts_to_str(timestamps[-1]),
                ))

        # Sort by most suspicious (lowest std dev) first
        results.sort(key=lambda b: b.std_dev_seconds)
        self._beacons = results

        if self._custody:
            self._custody.record(
                "pcap_beaconing_detected", "pcap_analyzer",
                detail=f"{len(results)} beaconing pattern(s) flagged",
            )

        return results

    # ── Summary for LLM ──────────────────────────────────────────────

    def summarize(self) -> str:
        """Generate a formatted text summary of all PCAP findings.

        Suitable for injection into an LLM prompt for AI-assisted
        forensic analysis.
        """
        sections: List[str] = []

        # Header
        sections.append("=" * 70)
        sections.append("PCAP TRAFFIC ANALYSIS REPORT")
        sections.append("=" * 70)
        sections.append(f"File:    {self._path or 'N/A'}")
        sections.append(f"Packets: {len(self._packets):,}")
        sections.append(f"Size:    {self._total_bytes:,} bytes")
        sections.append("")

        # DNS Queries
        dns = self.extract_dns_queries()
        sections.append(f"─── DNS Queries ({len(dns)}) " + "─" * 40)
        if dns:
            # Deduplicate by query name for the summary
            seen_names: dict[str, list] = {}
            for q in dns:
                if q.query_name not in seen_names:
                    seen_names[q.query_name] = []
                if q.response_ips:
                    seen_names[q.query_name].extend(q.response_ips)

            for name, ips in sorted(seen_names.items()):
                unique_ips = list(dict.fromkeys(ips))  # preserve order
                ip_str = f" → {', '.join(unique_ips)}" if unique_ips else ""
                sections.append(f"  {name}{ip_str}")
        else:
            sections.append("  No DNS queries found.")
        sections.append("")

        # HTTP Requests
        http = self.extract_http_cleartext()
        sections.append(f"─── HTTP Cleartext Requests ({len(http)}) " + "─" * 30)
        if http:
            for req in http[:50]:  # cap at 50 for summary
                sections.append(
                    f"  [{req.timestamp}] {req.method} http://{req.host}{req.uri}"
                )
                if req.user_agent:
                    sections.append(f"    User-Agent: {req.user_agent[:80]}")
                if req.body_preview:
                    sections.append(f"    Body: {req.body_preview[:200]}")
        else:
            sections.append("  No cleartext HTTP requests found.")
        sections.append("")

        # TLS SNI
        sni = self.extract_tls_sni()
        sections.append(f"─── TLS SNI Hostnames ({len(sni)}) " + "─" * 35)
        if sni:
            for s in sni:
                sections.append(
                    f"  {s.server_name}  ({s.src_ip} → {s.dst_ip})"
                )
        else:
            sections.append("  No TLS ClientHello SNI fields found.")
        sections.append("")

        # Beaconing
        beacons = self.detect_beaconing()
        sections.append(f"─── Beaconing Patterns ({len(beacons)}) " + "─" * 33)
        if beacons:
            for b in beacons:
                sections.append(
                    f"  ⚠ {b.dst_ip}:{b.dst_port}  —  "
                    f"{b.connection_count} connections, "
                    f"avg interval {b.avg_interval_seconds}s "
                    f"(σ={b.std_dev_seconds}s)"
                )
                sections.append(
                    f"    First: {b.first_seen}  Last: {b.last_seen}"
                )
        else:
            sections.append("  No beaconing patterns detected.")
        sections.append("")
        sections.append("=" * 70)

        return "\n".join(sections)

    # ── Forensic data for report integration ─────────────────────────

    def get_report_data(self) -> dict:
        """Return all analysis results as a dict for report generation."""
        return {
            "file_path": self._path,
            "packet_count": len(self._packets),
            "total_bytes": self._total_bytes,
            "dns_queries": self.extract_dns_queries(),
            "http_requests": self.extract_http_cleartext(),
            "tls_sni": self.extract_tls_sni(),
            "beacons": self.detect_beaconing(),
            "summary": self.summarize(),
        }


# ── Quick self-test ──────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    print(f"dpkt available: {DPKT_AVAILABLE}")
    if not DPKT_AVAILABLE:
        print("Install dpkt with: pip install dpkt")
        sys.exit(1)

    # Test with a file if provided on command line
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
        print(f"\nLoading: {pcap_file}")
        analyzer = PcapAnalyzer()
        count = analyzer.load(pcap_file)
        print(f"Loaded {count} packets.\n")
        print(analyzer.summarize())
    else:
        # Verify the class instantiates correctly
        analyzer = PcapAnalyzer()
        print(f"PcapAnalyzer created OK (no file loaded)")
        print(f"  available: {analyzer.available}")
        print(f"  packet_count: {analyzer.packet_count}")
        print()

        # Create a minimal test PCAP in memory to verify parsing works
        print("Creating synthetic test PCAP...")
        import io
        import struct as st

        # Minimal libpcap file header
        pcap_header = st.pack(
            "<IHHiIII",
            0xa1b2c3d4,  # magic
            2, 4,         # version
            0,            # timezone
            0,            # sigfigs
            65535,        # snaplen
            1,            # linktype (Ethernet)
        )

        # Build a minimal Ethernet + IP + UDP + DNS packet
        # DNS query for "example.com"
        dns_payload = dpkt.dns.DNS(
            id=0x1234,
            op=dpkt.dns.DNS_QUERY,
            qd=[dpkt.dns.DNS.Q(name="example.com", type=dpkt.dns.DNS_A)],
        )
        dns_bytes = bytes(dns_payload)

        udp = dpkt.udp.UDP(
            sport=12345,
            dport=53,
            data=dns_bytes,
        )
        udp.ulen = len(udp)

        ip_pkt = dpkt.ip.IP(
            src=socket.inet_aton("10.0.0.1"),
            dst=socket.inet_aton("8.8.8.8"),
            p=dpkt.ip.IP_PROTO_UDP,
            data=udp,
        )
        ip_pkt.len = len(ip_pkt)

        eth = dpkt.ethernet.Ethernet(
            dst=b"\xff" * 6,
            src=b"\x00" * 6,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_pkt,
        )
        eth_bytes = bytes(eth)

        # PCAP packet record header
        import time
        ts_int = int(time.time())
        pkt_header = st.pack("<IIII", ts_int, 0, len(eth_bytes), len(eth_bytes))

        # Write to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(pcap_header)
            tmp.write(pkt_header)
            tmp.write(eth_bytes)
            tmp_path = tmp.name

        try:
            count = analyzer.load(tmp_path)
            print(f"  Loaded {count} packet(s) from synthetic PCAP")
            dns_results = analyzer.extract_dns_queries()
            print(f"  DNS queries found: {len(dns_results)}")
            for q in dns_results:
                print(f"    -> {q.query_name} ({q.query_type})")
            http_results = analyzer.extract_http_cleartext()
            print(f"  HTTP requests found: {len(http_results)}")
            sni_results = analyzer.extract_tls_sni()
            print(f"  TLS SNI hostnames found: {len(sni_results)}")
            beacons = analyzer.detect_beaconing()
            print(f"  Beaconing patterns: {len(beacons)}")
            print()
            print("[OK] Self-test passed.")
        finally:
            os.unlink(tmp_path)
