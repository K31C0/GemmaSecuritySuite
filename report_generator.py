"""
report_generator.py – Automated incident response report generation.

Collects data from all toolkit modules and produces a professional,
self-contained HTML report.  Optionally generates PDF via WeasyPrint
if it is installed (graceful fallback to HTML-only).

Report sections:
    1. Executive Summary (session metadata, analyst, hostname)
    2. Environment Fingerprint snapshot
    3. YARA Scan Results
    4. AI Analysis Outputs (script audit, phishing, log analysis)
    5. Chat History Transcript
    6. Evidence Vault Manifest
    7. Custody Chain Log Summary
    8. Appendix: Full Custody Log

Reports are saved to ``data/exports/``.
"""

import datetime
import html
import json
import os
from typing import Any, Dict, List, Optional

import config

# Optional PDF support via WeasyPrint.
try:
    import weasyprint
    _PDF_AVAILABLE = True
except ImportError:
    _PDF_AVAILABLE = False


# ── HTML Template ────────────────────────────────────────────────────

_CSS = """\
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0f1117;
    color: #e0e0e0;
    padding: 40px;
    line-height: 1.6;
}
.report-container {
    max-width: 1100px;
    margin: 0 auto;
    background: #1a1d27;
    border-radius: 12px;
    padding: 48px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.5);
}
h1 {
    font-size: 28px;
    color: #00d4aa;
    border-bottom: 2px solid #00d4aa40;
    padding-bottom: 12px;
    margin-bottom: 24px;
}
h2 {
    font-size: 20px;
    color: #7c8aff;
    margin: 32px 0 12px 0;
    padding-bottom: 6px;
    border-bottom: 1px solid #7c8aff30;
}
h3 {
    font-size: 16px;
    color: #a0a8c0;
    margin: 16px 0 8px 0;
}
.meta-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px 32px;
    margin: 12px 0 20px 0;
}
.meta-item {
    display: flex;
    gap: 8px;
}
.meta-label {
    color: #808898;
    font-size: 13px;
    min-width: 140px;
}
.meta-value {
    color: #e0e0e0;
    font-size: 13px;
    font-weight: 600;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
    font-size: 13px;
}
th {
    background: #252a36;
    color: #7c8aff;
    padding: 10px 12px;
    text-align: left;
    font-weight: 600;
    border-bottom: 2px solid #7c8aff30;
}
td {
    padding: 8px 12px;
    border-bottom: 1px solid #2a2f3c;
    vertical-align: top;
}
tr:hover { background: #1e2230; }
.severity-critical {
    color: #ff4d6a;
    font-weight: 700;
}
.severity-high {
    color: #ff9f43;
    font-weight: 700;
}
.severity-medium {
    color: #ffc048;
}
.severity-low, .severity-test {
    color: #00d4aa;
}
pre {
    background: #12141c;
    border: 1px solid #2a2f3c;
    border-radius: 6px;
    padding: 16px;
    overflow-x: auto;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    line-height: 1.5;
    color: #c8ccd8;
    margin: 8px 0;
    white-space: pre-wrap;
    word-wrap: break-word;
}
.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
}
.badge-critical { background: #ff4d6a20; color: #ff4d6a; }
.badge-high     { background: #ff9f4320; color: #ff9f43; }
.badge-medium   { background: #ffc04820; color: #ffc048; }
.badge-low      { background: #00d4aa20; color: #00d4aa; }
.badge-info     { background: #7c8aff20; color: #7c8aff; }
.section-empty {
    color: #606878;
    font-style: italic;
    padding: 12px 0;
}
.footer {
    margin-top: 40px;
    padding-top: 16px;
    border-top: 1px solid #2a2f3c;
    color: #606878;
    font-size: 12px;
    text-align: center;
}
@media print {
    body { background: #fff; color: #222; padding: 20px; }
    .report-container { box-shadow: none; background: #fff; }
    h1 { color: #006644; }
    h2 { color: #334488; }
    pre { background: #f4f4f4; color: #222; border-color: #ddd; }
    th { background: #eee; color: #334488; }
    td { border-color: #ddd; }
}
"""


class IncidentReport:
    """Collects data from all toolkit modules and generates reports.

    Usage::

        report = IncidentReport()
        report.set_session_info(analyst="SOC-1", case_id="IR-2026-042")
        report.add_env_fingerprint(snapshot_dict)
        report.add_yara_results(matches_list)
        report.add_ai_analysis("Script Audit", result_text)
        report.add_chat_history(transcript_text)
        report.add_vault_manifest(items_list)
        report.add_custody_entries(entries_list)

        html_path = report.generate_html()
        pdf_path  = report.generate_pdf()   # if WeasyPrint available
    """

    def __init__(self, custody_logger=None) -> None:
        self._custody = custody_logger
        self._session: Dict[str, str] = {}
        self._env_snapshot: Optional[Dict[str, Any]] = None
        self._yara_matches: List[Dict[str, Any]] = []
        self._ai_analyses: List[Dict[str, str]] = []
        self._chat_history: str = ""
        self._vault_items: List[Dict[str, Any]] = []
        self._custody_entries: List[Dict[str, Any]] = []

    # ── Data collection ──────────────────────────────────────────────

    def set_session_info(
        self,
        analyst: str = "SYSTEM",
        case_id: str = "",
        notes: str = "",
    ) -> None:
        """Set session-level metadata."""
        import platform
        self._session = {
            "analyst": analyst,
            "case_id": case_id or "N/A",
            "hostname": platform.node(),
            "generated_at": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(timespec="seconds"),
            "toolkit_version": "1.0",
            "notes": notes,
        }

    def add_env_fingerprint(self, snapshot: Dict[str, Any]) -> None:
        """Add environment fingerprint data."""
        self._env_snapshot = snapshot

    def add_yara_results(self, matches: List[Any]) -> None:
        """Add YARA scan results (list of YaraMatch or dicts)."""
        for m in matches:
            if hasattr(m, "rule_name"):
                self._yara_matches.append({
                    "rule_name": m.rule_name,
                    "tags": m.tags,
                    "meta": m.meta,
                    "strings_matched": m.strings_matched,
                    "namespace": m.namespace,
                })
            else:
                self._yara_matches.append(m)

    def add_ai_analysis(self, title: str, content: str) -> None:
        """Add an AI analysis result section."""
        self._ai_analyses.append({"title": title, "content": content})

    def add_chat_history(self, transcript: str) -> None:
        """Add the chat assistant transcript."""
        self._chat_history = transcript

    def add_vault_manifest(self, items: List[Any]) -> None:
        """Add evidence vault manifest items."""
        for item in items:
            if hasattr(item, "item_id"):
                self._vault_items.append({
                    "item_id": item.item_id,
                    "original_name": item.original_name,
                    "stored_at": item.stored_at,
                    "sha256_plaintext": item.sha256_plaintext,
                    "size_bytes": item.size_bytes,
                    "analyst_notes": item.analyst_notes,
                })
            else:
                self._vault_items.append(item)

    def add_custody_entries(self, entries: List[Dict[str, Any]]) -> None:
        """Add custody chain log entries."""
        self._custody_entries = entries

    def load_custody_from_file(self, log_path: str) -> None:
        """Load custody entries from a JSONL file."""
        if not os.path.isfile(log_path):
            return
        entries = []
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        self._custody_entries = entries

    # ── Report generation ────────────────────────────────────────────

    def generate_html(self, output_path: Optional[str] = None) -> str:
        """Generate a self-contained HTML report.

        Parameters
        ----------
        output_path : str, optional
            Where to save the HTML file.  Defaults to
            ``data/exports/report_YYYYMMDD_HHMMSS.html``.

        Returns
        -------
        str
            Absolute path to the generated HTML file.
        """
        if not self._session:
            self.set_session_info()

        if output_path is None:
            ts = datetime.datetime.now(
                datetime.timezone.utc
            ).strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(
                config.EXPORTS_DIR, f"report_{ts}.html"
            )

        os.makedirs(os.path.dirname(os.path.abspath(output_path)),
                     exist_ok=True)

        html_content = self._render_html()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        if self._custody:
            self._custody.record(
                "report_generated", "report_generator",
                target=output_path,
                detail=f"HTML report, {len(html_content)} bytes",
            )

        return os.path.abspath(output_path)

    def generate_pdf(self, output_path: Optional[str] = None) -> Optional[str]:
        """Generate a PDF report via WeasyPrint.

        Returns ``None`` if WeasyPrint is not installed.
        """
        if not _PDF_AVAILABLE:
            return None

        if not self._session:
            self.set_session_info()

        if output_path is None:
            ts = datetime.datetime.now(
                datetime.timezone.utc
            ).strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(
                config.EXPORTS_DIR, f"report_{ts}.pdf"
            )

        os.makedirs(os.path.dirname(os.path.abspath(output_path)),
                     exist_ok=True)

        html_content = self._render_html()
        weasyprint.HTML(string=html_content).write_pdf(output_path)

        if self._custody:
            self._custody.record(
                "report_generated", "report_generator",
                target=output_path,
                detail="PDF report via WeasyPrint",
            )

        return os.path.abspath(output_path)

    @staticmethod
    def pdf_available() -> bool:
        """Check if PDF generation is supported."""
        return _PDF_AVAILABLE

    # ── HTML rendering ───────────────────────────────────────────────

    def _render_html(self) -> str:
        """Build the full HTML document string."""
        sections = []
        sections.append(self._render_header())
        sections.append(self._render_session())
        sections.append(self._render_env_fingerprint())
        sections.append(self._render_yara())
        sections.append(self._render_ai_analyses())
        sections.append(self._render_chat())
        sections.append(self._render_vault())
        sections.append(self._render_custody_summary())
        sections.append(self._render_custody_full())
        sections.append(self._render_footer())

        body = "\n".join(sections)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Incident Report - {_esc(self._session.get('case_id', 'N/A'))}</title>
    <style>{_CSS}</style>
</head>
<body>
<div class="report-container">
{body}
</div>
</body>
</html>"""

    def _render_header(self) -> str:
        return f"""<h1>Incident Response Report</h1>"""

    def _render_session(self) -> str:
        s = self._session
        return f"""<h2>1. Executive Summary</h2>
<div class="meta-grid">
  <div class="meta-item"><span class="meta-label">Case ID</span>
    <span class="meta-value">{_esc(s.get('case_id', 'N/A'))}</span></div>
  <div class="meta-item"><span class="meta-label">Analyst</span>
    <span class="meta-value">{_esc(s.get('analyst', 'SYSTEM'))}</span></div>
  <div class="meta-item"><span class="meta-label">Hostname</span>
    <span class="meta-value">{_esc(s.get('hostname', 'N/A'))}</span></div>
  <div class="meta-item"><span class="meta-label">Generated At</span>
    <span class="meta-value">{_esc(s.get('generated_at', 'N/A'))}</span></div>
  <div class="meta-item"><span class="meta-label">Toolkit Version</span>
    <span class="meta-value">{_esc(s.get('toolkit_version', 'N/A'))}</span></div>
  <div class="meta-item"><span class="meta-label">Notes</span>
    <span class="meta-value">{_esc(s.get('notes', '')) or 'None'}</span></div>
</div>"""

    def _render_env_fingerprint(self) -> str:
        if not self._env_snapshot:
            return """<h2>2. Environment Fingerprint</h2>
<p class="section-empty">No environment snapshot captured.</p>"""

        snap = self._env_snapshot
        sys_info = snap.get("system", {})

        rows = ""
        for key in ["hostname", "os", "os_version", "architecture",
                     "domain", "current_user", "uptime", "boot_time"]:
            val = sys_info.get(key, "N/A")
            label = key.replace("_", " ").title()
            rows += f"""<tr><td>{_esc(label)}</td>
                        <td>{_esc(str(val))}</td></tr>\n"""

        procs = snap.get("processes", [])
        conns = snap.get("tcp_connections", [])
        ifaces = snap.get("network_interfaces", [])

        return f"""<h2>2. Environment Fingerprint</h2>
<h3>System Information</h3>
<table><tr><th>Property</th><th>Value</th></tr>
{rows}</table>
<h3>Summary</h3>
<div class="meta-grid">
  <div class="meta-item"><span class="meta-label">Running Processes</span>
    <span class="meta-value">{len(procs)}</span></div>
  <div class="meta-item"><span class="meta-label">Network Interfaces</span>
    <span class="meta-value">{len(ifaces)}</span></div>
  <div class="meta-item"><span class="meta-label">TCP Connections</span>
    <span class="meta-value">{len(conns)}</span></div>
  <div class="meta-item"><span class="meta-label">ARP Entries</span>
    <span class="meta-value">{len(snap.get('arp_table', []))}</span></div>
</div>"""

    def _render_yara(self) -> str:
        if not self._yara_matches:
            return """<h2>3. YARA Scan Results</h2>
<p class="section-empty">No YARA matches detected.</p>"""

        rows = ""
        for m in self._yara_matches:
            sev = m.get("meta", {}).get("severity", "unknown")
            sev_class = f"severity-{sev}" if sev else ""
            badge_class = f"badge-{sev}" if sev in (
                "critical", "high", "medium", "low"
            ) else "badge-info"
            tags = ", ".join(m.get("tags", [])) or "none"
            desc = m.get("meta", {}).get("description", "N/A")
            strings = ", ".join(m.get("strings_matched", [])[:5]) or "N/A"
            rows += f"""<tr>
  <td><strong>{_esc(m.get('rule_name', '?'))}</strong></td>
  <td><span class="badge {badge_class}">{_esc(sev)}</span></td>
  <td>{_esc(desc)}</td>
  <td>{_esc(tags)}</td>
  <td><code>{_esc(strings)}</code></td>
</tr>\n"""

        return f"""<h2>3. YARA Scan Results</h2>
<p>{len(self._yara_matches)} rule(s) matched.</p>
<table>
<tr><th>Rule</th><th>Severity</th><th>Description</th>
    <th>Tags</th><th>Strings</th></tr>
{rows}</table>"""

    def _render_ai_analyses(self) -> str:
        if not self._ai_analyses:
            return """<h2>4. AI Analysis Results</h2>
<p class="section-empty">No AI analyses performed.</p>"""

        blocks = ""
        for a in self._ai_analyses:
            blocks += f"""<h3>{_esc(a['title'])}</h3>
<pre>{_esc(a['content'])}</pre>\n"""

        return f"""<h2>4. AI Analysis Results</h2>
{blocks}"""

    def _render_chat(self) -> str:
        if not self._chat_history:
            return """<h2>5. Chat History</h2>
<p class="section-empty">No chat session recorded.</p>"""

        return f"""<h2>5. Chat History</h2>
<pre>{_esc(self._chat_history)}</pre>"""

    def _render_vault(self) -> str:
        if not self._vault_items:
            return """<h2>6. Evidence Vault</h2>
<p class="section-empty">No evidence items stored.</p>"""

        rows = ""
        for v in self._vault_items:
            rows += f"""<tr>
  <td><code>{_esc(v.get('item_id', '?'))}</code></td>
  <td>{_esc(v.get('original_name', '?'))}</td>
  <td>{v.get('size_bytes', 0):,}</td>
  <td><code>{_esc(v.get('sha256_plaintext', '?')[:16])}...</code></td>
  <td>{_esc(v.get('stored_at', '?'))}</td>
  <td>{_esc(v.get('analyst_notes', '') or 'None')}</td>
</tr>\n"""

        return f"""<h2>6. Evidence Vault</h2>
<p>{len(self._vault_items)} item(s) in vault.</p>
<table>
<tr><th>ID</th><th>Original Name</th><th>Size</th>
    <th>SHA-256</th><th>Stored At</th><th>Notes</th></tr>
{rows}</table>"""

    def _render_custody_summary(self) -> str:
        if not self._custody_entries:
            return """<h2>7. Custody Chain Summary</h2>
<p class="section-empty">No custody log entries.</p>"""

        # Count actions by type.
        action_counts: Dict[str, int] = {}
        for e in self._custody_entries:
            action = e.get("action", "unknown")
            action_counts[action] = action_counts.get(action, 0) + 1

        rows = ""
        for action, count in sorted(action_counts.items()):
            rows += f"<tr><td>{_esc(action)}</td><td>{count}</td></tr>\n"

        first_ts = self._custody_entries[0].get("ts", "?")
        last_ts = self._custody_entries[-1].get("ts", "?")

        return f"""<h2>7. Custody Chain Summary</h2>
<div class="meta-grid">
  <div class="meta-item"><span class="meta-label">Total Events</span>
    <span class="meta-value">{len(self._custody_entries)}</span></div>
  <div class="meta-item"><span class="meta-label">First Event</span>
    <span class="meta-value">{_esc(first_ts)}</span></div>
  <div class="meta-item"><span class="meta-label">Last Event</span>
    <span class="meta-value">{_esc(last_ts)}</span></div>
</div>
<h3>Actions by Type</h3>
<table><tr><th>Action</th><th>Count</th></tr>
{rows}</table>"""

    def _render_custody_full(self) -> str:
        if not self._custody_entries:
            return ""

        rows = ""
        for e in self._custody_entries[-100:]:  # Last 100 entries
            rows += f"""<tr>
  <td>{_esc(str(e.get('seq', '?')))}</td>
  <td>{_esc(e.get('ts', '?'))}</td>
  <td>{_esc(e.get('action', '?'))}</td>
  <td>{_esc(e.get('module', '?'))}</td>
  <td>{_esc(e.get('target', '') or '')}</td>
  <td>{_esc(e.get('detail', '') or '')}</td>
</tr>\n"""

        note = ""
        if len(self._custody_entries) > 100:
            note = (f"<p><em>Showing last 100 of "
                    f"{len(self._custody_entries)} entries.</em></p>")

        return f"""<h2>8. Appendix: Full Custody Log</h2>
{note}
<table>
<tr><th>#</th><th>Timestamp</th><th>Action</th>
    <th>Module</th><th>Target</th><th>Detail</th></tr>
{rows}</table>"""

    def _render_footer(self) -> str:
        now = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(timespec="seconds")
        return f"""<div class="footer">
Generated by GemmaSecuritySuite v1.0 &mdash; {_esc(now)} UTC<br>
This report is auto-generated. Verify all findings independently.
</div>"""


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text)) if text else ""


# ── Quick self-test ──────────────────────────────────────────────────
if __name__ == "__main__":
    report = IncidentReport()
    report.set_session_info(analyst="TestAnalyst", case_id="IR-2026-TEST",
                            notes="Automated self-test run")

    # Fake env fingerprint
    report.add_env_fingerprint({
        "system": {
            "hostname": "IR-LAPTOP",
            "os": "Windows",
            "os_version": "10.0.22631",
            "architecture": "AMD64",
            "domain": "WORKGROUP",
            "current_user": "analyst",
            "uptime": "5h 23m 10s",
            "boot_time": "2026-06-06T01:00:00+00:00",
        },
        "processes": [{"pid": i} for i in range(150)],
        "network_interfaces": [{"name": f"eth{i}"} for i in range(3)],
        "tcp_connections": [{"local": f"0.0.0.0:{p}"} for p in range(50)],
        "arp_table": [{"ip": f"192.168.1.{i}"} for i in range(10)],
    })

    # Fake YARA results
    report.add_yara_results([
        {
            "rule_name": "Suspicious_PowerShell_Download",
            "tags": ["malware", "powershell"],
            "meta": {"description": "Detects PowerShell download cradles",
                     "severity": "high", "author": "GSS"},
            "strings_matched": ["$dl1", "$enc3"],
            "namespace": "community/ir_essentials.yar",
        },
        {
            "rule_name": "Suspicious_Credential_Access",
            "tags": ["credential"],
            "meta": {"description": "Detects credential harvesting",
                     "severity": "critical"},
            "strings_matched": ["$m1", "$lsass"],
            "namespace": "community/ir_essentials.yar",
        },
    ])

    # Fake AI analysis
    report.add_ai_analysis("Script Audit",
                           "The script uses Invoke-WebRequest to download "
                           "a payload from a remote C2 server and executes "
                           "it via IEX. HIGH RISK.")

    # Fake chat
    report.add_chat_history("Admin: What ports is mimikatz using?\n"
                            "IT-Copilot: Mimikatz typically uses...\n")

    # Fake vault
    report.add_vault_manifest([
        {
            "item_id": "abc123def456",
            "original_name": "malware.exe",
            "stored_at": "2026-06-06T06:00:00+00:00",
            "sha256_plaintext": "e3b0c44298fc1c149afbf4c8996fb924"
                                "27ae41e4649b934ca495991b7852b855",
            "size_bytes": 45056,
            "analyst_notes": "Suspicious DLL from compromised host",
        },
    ])

    # Fake custody
    report.add_custody_entries([
        {"seq": 1, "ts": "2026-06-06T06:00:00Z", "action": "app_start",
         "module": "main", "target": None, "detail": "GSS v1"},
        {"seq": 2, "ts": "2026-06-06T06:01:00Z", "action": "script_audit_start",
         "module": "script_auditor", "target": None,
         "detail": "Script length: 500 chars"},
        {"seq": 3, "ts": "2026-06-06T06:01:05Z", "action": "yara_match",
         "module": "yara_scanner", "target": None,
         "detail": "Suspicious_PowerShell_Download"},
        {"seq": 4, "ts": "2026-06-06T06:02:00Z", "action": "evidence_stored",
         "module": "evidence_vault", "target": "malware.exe",
         "detail": "Stored as abc123.vault"},
        {"seq": 5, "ts": "2026-06-06T06:05:00Z", "action": "app_stop",
         "module": "main", "target": None, "detail": "5 events logged"},
    ])

    # Generate
    path = report.generate_html()
    print(f"HTML report: {path}")
    print(f"PDF support: {IncidentReport.pdf_available()}")
    print(f"File size:   {os.path.getsize(path):,} bytes")
