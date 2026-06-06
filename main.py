"""
main.py – Entry point for Gemma AI Security Suite.

Wires together:
  • ModelManager   (downloader.py)   – model download / check
  • AppGUI         (gui_manager.py)  – all UI frames
  • LocalAI        (ai_inference.py) – script audit via local model
  • CustodyLogger  (custody_logger.py) – forensic audit trail
"""

from ai_inference import LocalAI
from custody_logger import CustodyLogger
from downloader import ModelManager
from gui_manager import AppGUI
from typing import Optional

import config
import os
import sys


def main() -> None:
    # Ensure the portable data/ directory tree exists on the USB drive
    # before any module tries to read or write files.
    config.ensure_dirs()

    # Initialise the forensic chain-of-custody logger before anything
    # else so that every action in this session is recorded.
    custody = CustodyLogger()
    custody.log_app_start()

    import health_monitor
    monitor = health_monitor.HealthMonitor(custody_logger=custody)
    health_monitor.monitor = monitor
    monitor.register("custody_logger", custody.health_check, custody.recover)

    app = AppGUI()
    app.custody_logger = custody     # inject for GUI-internal callbacks
    mgr = ModelManager()
    local_ai = LocalAI()          # persistent instance, shared across audits
    monitor.register("ai_inference", local_ai.health_check, local_ai.reload_model)

    from session_manager import SessionManager
    session = SessionManager(
        get_state_fn=app.get_ui_state,
        restore_state_fn=app.restore_ui_state,
        custody_logger=custody,
    )
    session.load()
    session.start_autosave(interval=30.0)

    # Global Exception Handler
    def global_exception_handler(exc_type, exc_value, exc_traceback):
        import traceback
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
            
        tb_str = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        custody.record("fatal_crash", "main", detail=f"{exc_type.__name__}: {exc_value}\n{tb_str}")
        
        # Try to save session state before dying
        try:
            session.save()
        except Exception:
            pass
            
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    sys.excepthook = global_exception_handler
    
    # Health monitor UI wiring
    def _on_health_change(status: health_monitor.ModuleHealth) -> None:
        target_cards = []
        if status.name == "ai_inference":
            target_cards = ["chat_assistant", "script_auditor", "regex_wizard", "phishing_analyzer", "main"]
        elif status.name == "yara_scanner":
            target_cards = ["script_auditor"]
        elif status.name == "pcap_analyzer":
            target_cards = ["pcap_analyzer"]
        elif status.name == "evidence_vault":
            target_cards = ["evidence_vault"]
            
        is_degraded = status.status in ("degraded", "failed")
        
        # Update UI safely
        for card in target_cards:
            app.after(0, app.update_dashboard_card, card, is_degraded, status.message)
            
        # Show toast for state changes
        level = "error" if status.status == "failed" else "warning" if status.status == "degraded" else "success"
        app.after(0, app.show_toast, f"[{status.name}] {status.status.upper()}: {status.message}", level)

    monitor.on_status_change = _on_health_change

    # ==================================================================
    #  Download wiring
    # ==================================================================

    def on_progress(pct: float) -> None:
        app.after(0, _update_progress, pct)

    def on_done(success: bool, error: Optional[str]) -> None:
        if success:
            app.after(0, _download_succeeded)
        else:
            app.after(0, _download_failed, error)

    def _update_progress(pct: float) -> None:
        app.set_setup_progress(pct / 100.0)
        app.set_setup_status(f"Downloading model\u2026 {pct:.1f}%")

    def _download_succeeded() -> None:
        app.set_setup_progress(1.0)
        app.set_setup_status("Ready!")
        app.after(600, lambda: app.show_frame("dashboard"))

    def _download_failed(error: Optional[str]) -> None:
        app.set_setup_status(f"Download failed: {error or 'unknown error'}")
        app.after(3000, lambda: app.show_frame("dashboard"))

    def _start() -> None:
        # Run hardware detection first and show results on setup screen.
        from hardware_profiler import detect_hardware
        import threading

        def _detect_and_continue():
            profile = detect_hardware()
            summary = profile.summary

            def _show_and_proceed():
                app.set_setup_status(f"Detected: {summary}")
                app.after(1200, _check_model)

            app.after(0, _show_and_proceed)

        def _check_model():
            if mgr.file_exists():
                app.set_setup_progress(1.0)
                app.set_setup_status("Model already present. Launching...")
                app.after(400, lambda: app.show_frame("dashboard"))
            else:
                app.set_setup_status("Starting download\u2026")
                mgr.ensure_file(
                    progress_callback=on_progress,
                    done_callback=on_done,
                )

        # Kick off hardware detection on a background thread.
        threading.Thread(
            target=_detect_and_continue, daemon=True,
            name="HardwareDetect"
        ).start()
    # ==================================================================
    #  Environment Fingerprint wiring
    # ==================================================================

    def _capture_env_snapshot() -> None:
        """Run environment fingerprinting on a background thread."""
        app.write_env_output("Capturing environment snapshot...\n", clear=True)
        app.env_capture_button.configure(state="disabled")

        def _worker():
            try:
                from env_fingerprint import capture_snapshot, format_snapshot
                snapshot = capture_snapshot(custody_logger=custody)
                formatted = format_snapshot(snapshot)
                app.after(0, app.write_env_output,
                          formatted + "\n", True)
            except Exception as exc:
                custody.record("env_fingerprint_error", "env_fingerprint",
                               detail=str(exc))
                app.after(0, app.write_env_output,
                          f"Error capturing snapshot: {exc}\n", True)
            finally:
                app.after(0, lambda: app.env_capture_button.configure(
                    state="normal"))

        import threading
        threading.Thread(target=_worker, daemon=True,
                         name="EnvFingerprint").start()

    app.env_capture_button.configure(command=_capture_env_snapshot)

    # ==================================================================
    #  Evidence Vault wiring
    # ==================================================================

    from evidence_vault import Vault
    vault = Vault(custody_logger=custody)
    monitor.register("evidence_vault", vault.health_check, vault.recover)

    def _refresh_vault_list() -> None:
        """Refresh the vault item list display."""
        items = vault.list_items()
        if not items:
            app.write_vault_list("No items in vault.\n\n"
                                  "Use 'Store File' to encrypt and store "
                                  "evidence files.", clear=True)
            app.vault_status_label.configure(text="No items in vault.")
            return

        lines = []
        lines.append(f"{'ID':18s}  {'ORIGINAL NAME':30s}  {'SIZE':>10s}  "
                      f"{'STORED AT':26s}  NOTES")
        lines.append("-" * 110)
        for it in items:
            size_str = f"{it.size_bytes:,} B"
            lines.append(
                f"{it.item_id:18s}  {it.original_name:30s}  {size_str:>10s}  "
                f"{it.stored_at:26s}  {it.analyst_notes or ''}"
            )
        app.write_vault_list("\n".join(lines), clear=True)
        app.vault_status_label.configure(
            text=f"{len(items)} item(s) in vault."
        )

    def _store_evidence() -> None:
        """Open file picker, encrypt and store the selected file."""
        from tkinter import filedialog
        pw = app.vault_password_entry.get().strip()
        if not pw:
            app.write_vault_list(
                "ERROR: Please enter a password first.\n", clear=True)
            return

        file_path = filedialog.askopenfilename(
            title="Select evidence file to store",
            parent=app,
        )
        if not file_path:
            return

        notes = app.vault_notes_entry.get().strip()
        app.vault_store_button.configure(state="disabled")

        def _worker():
            try:
                item = vault.store(file_path, pw, notes)
                app.after(0, _refresh_vault_list)
                app.after(0, app.vault_notes_entry.delete, 0, "end")
            except Exception as exc:
                custody.record("evidence_store_error", "evidence_vault",
                               detail=str(exc))
                app.after(0, app.write_vault_list,
                          f"ERROR: {exc}\n", True)
            finally:
                app.after(0, lambda: app.vault_store_button.configure(
                    state="normal"))

        import threading
        threading.Thread(target=_worker, daemon=True,
                         name="VaultStore").start()

    def _extract_evidence() -> None:
        """Extract the first item ID found in the vault list selection."""
        from tkinter import filedialog
        pw = app.vault_password_entry.get().strip()
        if not pw:
            app.write_vault_list(
                "ERROR: Please enter the vault password.\n", clear=True)
            return

        # Get the list content to find an item ID
        items = vault.list_items()
        if not items:
            app.write_vault_list(
                "No items to extract.\n", clear=True)
            return

        # Use the last stored item (most recent) — user can refine later
        item = items[-1]

        dest_path = filedialog.asksaveasfilename(
            title="Save extracted evidence as...",
            initialfile=item.original_name,
            parent=app,
        )
        if not dest_path:
            return

        app.vault_extract_button.configure(state="disabled")

        def _worker():
            try:
                sha = vault.extract(item.item_id, pw, dest_path)
                app.after(0, app.write_vault_list,
                          f"\nExtracted: {item.original_name} -> {dest_path}\n"
                          f"SHA-256 verified: {sha}\n", False)
            except ValueError as exc:
                custody.record("evidence_extract_error", "evidence_vault",
                               detail=str(exc))
                app.after(0, app.write_vault_list,
                          f"\nERROR: {exc}\n", False)
            except Exception as exc:
                app.after(0, app.write_vault_list,
                          f"\nERROR: {exc}\n", False)
            finally:
                app.after(0, lambda: app.vault_extract_button.configure(
                    state="normal"))

        import threading
        threading.Thread(target=_worker, daemon=True,
                         name="VaultExtract").start()

    app.vault_store_button.configure(command=_store_evidence)
    app.vault_extract_button.configure(command=_extract_evidence)
    app.vault_refresh_button.configure(command=_refresh_vault_list)

    # Load initial vault list.
    _refresh_vault_list()

    # ==================================================================
    #  Incident Report Generator wiring
    # ==================================================================

    from report_generator import IncidentReport

    def _generate_report(fmt: str = "html") -> None:
        """Collect data from all modules and generate a report."""
        app.write_report_output(f"Generating {fmt.upper()} report...\n",
                                 clear=True)
        app.report_html_button.configure(state="disabled")
        app.report_pdf_button.configure(state="disabled")

        def _worker():
            try:
                report = IncidentReport(custody_logger=custody)

                # Session info from GUI fields.
                case_id = app.report_case_entry.get().strip() or "N/A"
                analyst = app.report_analyst_entry.get().strip() or "SYSTEM"
                notes = app.report_notes_entry.get().strip()
                report.set_session_info(
                    analyst=analyst, case_id=case_id, notes=notes)

                # Environment fingerprint — capture fresh if not done yet.
                try:
                    from env_fingerprint import capture_snapshot
                    snap = capture_snapshot(custody_logger=custody)
                    report.add_env_fingerprint(snap)
                except Exception:
                    pass

                # YARA results — re-scan current script input if any.
                try:
                    script_text = app.script_input_textbox.get(
                        "1.0", "end").strip()
                    if script_text and yara_engine.available:
                        matches = yara_engine.scan_buffer(
                            script_text.encode("utf-8", errors="replace"))
                        report.add_yara_results(matches)
                except Exception:
                    pass

                # AI analysis outputs from textboxes.
                try:
                    audit_text = app.audit_results_textbox.get(
                        "1.0", "end").strip()
                    if audit_text:
                        report.add_ai_analysis("Script Audit", audit_text)
                except Exception:
                    pass

                try:
                    phishing_text = app.phishing_results_textbox.get(
                        "1.0", "end").strip()
                    if phishing_text:
                        report.add_ai_analysis(
                            "Phishing Analysis", phishing_text)
                except Exception:
                    pass

                try:
                    log_text = app.output_textbox.get("1.0", "end").strip()
                    if log_text:
                        report.add_ai_analysis("Log Analysis", log_text)
                except Exception:
                    pass

                # Chat history.
                try:
                    chat_text = app.chat_history_textbox.get(
                        "1.0", "end").strip()
                    if chat_text:
                        report.add_chat_history(chat_text)
                except Exception:
                    pass

                # Evidence vault.
                try:
                    vault_items = vault.list_items()
                    if vault_items:
                        report.add_vault_manifest(vault_items)
                except Exception:
                    pass

                # PCAP analysis.
                try:
                    if pcap_engine.available:
                        report.add_pcap_analysis(pcap_engine.get_report_data())
                except Exception:
                    pass

                # Custody chain.
                try:
                    report.load_custody_from_file(custody.path)
                except Exception:
                    pass

                # Generate.
                if fmt == "pdf":
                    path = report.generate_pdf()
                    if path is None:
                        app.after(0, app.write_report_output,
                                  "PDF generation requires WeasyPrint.\n"
                                  "Install with: pip install weasyprint\n"
                                  "Or use 'Generate HTML Report' instead.\n",
                                  True)
                        return
                else:
                    path = report.generate_html()

                size = os.path.getsize(path)
                msg = (f"Report generated successfully!\n\n"
                       f"  Format: {fmt.upper()}\n"
                       f"  Path:   {path}\n"
                       f"  Size:   {size:,} bytes\n\n"
                       f"Opening in default browser...")
                app.after(0, app.write_report_output, msg, True)

                # Open in default browser / viewer.
                import webbrowser
                webbrowser.open(f"file:///{path.replace(os.sep, '/')}")

            except Exception as exc:
                custody.record("report_error", "report_generator",
                               detail=str(exc))
                app.after(0, app.write_report_output,
                          f"Error generating report: {exc}\n", True)
            finally:
                app.after(0, lambda: app.report_html_button.configure(
                    state="normal"))
                app.after(0, lambda: app.report_pdf_button.configure(
                    state="normal"))

        import threading
        threading.Thread(target=_worker, daemon=True,
                         name="ReportGen").start()

    app.report_html_button.configure(
        command=lambda: _generate_report("html"))
    app.report_pdf_button.configure(
        command=lambda: _generate_report("pdf"))

    # ==================================================================
    #  PCAP Analyzer wiring
    # ==================================================================

    from pcap_analyzer import PcapAnalyzer, DPKT_AVAILABLE
    pcap_engine = PcapAnalyzer(custody_logger=custody)
    monitor.register("pcap_analyzer", pcap_engine.health_check)

    def _load_pcap() -> None:
        """Open file picker, load and analyse a PCAP file."""
        from tkinter import filedialog as pcap_fd
        pcap_path = pcap_fd.askopenfilename(
            title="Select PCAP File",
            filetypes=[
                ("PCAP files", "*.pcap *.cap"),
                ("All files", "*.*"),
            ],
            parent=app,
        )
        if not pcap_path:
            return

        if not DPKT_AVAILABLE:
            app.write_pcap_output(
                "ERROR: dpkt is not installed.\n"
                "Install with: pip install dpkt\n", clear=True)
            return

        app.pcap_status_label.configure(
            text=f"Loading: {os.path.basename(pcap_path)}...")
        app.write_pcap_output("Loading PCAP file...\n", clear=True)
        app.pcap_load_button.configure(state="disabled")

        def _worker():
            try:
                count = pcap_engine.load(pcap_path)
                summary = pcap_engine.summarize()

                # Gather stats
                dns_count = len(pcap_engine.extract_dns_queries())
                http_count = len(pcap_engine.extract_http_cleartext())
                sni_count = len(pcap_engine.extract_tls_sni())
                beacon_count = len(pcap_engine.detect_beaconing())

                def _update_ui():
                    app.pcap_status_label.configure(
                        text=f"Loaded: {os.path.basename(pcap_path)} "
                             f"— {count:,} packets")
                    app.update_pcap_stats(count, dns_count, http_count, sni_count)
                    app.write_pcap_output(summary + "\n", clear=True)

                    if beacon_count > 0:
                        app.write_pcap_output(
                            f"\n⚠  {beacon_count} beaconing pattern(s) detected!"
                            f" Review the report above.\n")

                app.after(0, _update_ui)

            except Exception as exc:
                custody.record("pcap_load_error", "pcap_analyzer",
                               detail=str(exc))
                app.after(0, app.write_pcap_output,
                          f"Error loading PCAP: {exc}\n", True)
                app.after(0, lambda: app.pcap_status_label.configure(
                    text="Error loading PCAP file."))
            finally:
                app.after(0, lambda: app.pcap_load_button.configure(
                    state="normal"))

        import threading
        threading.Thread(target=_worker, daemon=True,
                         name="PcapLoad").start()

    def _ai_analyze_pcap() -> None:
        """Send PCAP summary to Gemma for AI-assisted forensic analysis."""
        if not pcap_engine.available:
            app.write_pcap_output(
                "\nPlease load a PCAP file first.\n", False)
            return

        if local_ai.is_busy:
            app.write_pcap_output(
                "\nAn analysis is already running. Please wait.\n", False)
            return

        summary = pcap_engine.summarize()
        custody.record("pcap_ai_analysis_start", "pcap_analyzer",
                       detail=f"Summary length: {len(summary)} chars")

        app.write_pcap_output(
            "\n" + "─" * 70 + "\n"
            "Sending to Gemma AI for forensic analysis...\n", False)
        app.pcap_ai_button.configure(state="disabled")

        def _on_result(result: str) -> None:
            custody.record("pcap_ai_analysis_complete", "pcap_analyzer",
                           detail=f"Result length: {len(result)} chars")
            app.after(0, app.write_pcap_output,
                      "\n─── AI Forensic Analysis " + "─" * 45 + "\n\n"
                      + result + "\n", False)
            app.after(0, lambda: app.pcap_ai_button.configure(state="normal"))

        def _on_error(msg: str) -> None:
            custody.record("pcap_ai_analysis_error", "pcap_analyzer",
                           detail=msg)
            app.after(0, app.write_pcap_output,
                      f"\nAI Analysis error: {msg}\n", False)
            app.after(0, lambda: app.pcap_ai_button.configure(state="normal"))

        local_ai.analyze(
            text=summary,
            system_prompt=(
                "You are a senior SOC analyst performing forensic traffic analysis. "
                "Review this PCAP analysis report and provide:\n"
                "1. Executive summary of findings\n"
                "2. Suspicious indicators (C2, exfiltration, lateral movement)\n"
                "3. Recommended next steps for the incident responder\n\n"
            ),
            on_complete=_on_result,
            on_error=_on_error,
        )

    app.pcap_load_button.configure(command=_load_pcap)
    app.pcap_ai_button.configure(command=_ai_analyze_pcap)

    # Initialise the YARA engine once at startup.
    from yara_scanner import YaraEngine
    yara_engine = YaraEngine()
    monitor.register("yara_scanner", yara_engine.health_check, yara_engine.recover)
    if yara_engine.available:
        custody.record("yara_engine_init", "yara_scanner",
                       detail=f"Loaded {yara_engine.rule_count} rule file(s)")
    elif yara_engine.errors:
        custody.record("yara_engine_warning", "yara_scanner",
                       detail="; ".join(yara_engine.errors))

    def _audit_script() -> None:
        """Grab the pasted script, run YARA pre-scan, then send to AI.
        Results are piped back to the GUI's audit output textbox."""
        script = app.script_input_textbox.get("1.0", "end").strip()
        if not script:
            app._write_audit_result(
                "Please paste a script above first.\n", clear=True)
            return

        if local_ai.is_busy:
            app._write_audit_result(
                "An analysis is already running. Please wait.\n", clear=True)
            return

        custody.record("script_audit_start", "script_auditor",
                       detail=f"Script length: {len(script)} chars")

        # ── YARA Pre-Scan (runs synchronously — fast) ────────────
        yara_header = ""
        yara_context = ""
        if yara_engine.available:
            matches = yara_engine.scan_buffer(script.encode("utf-8", errors="replace"))
            yara_header = YaraEngine.format_matches(matches) + "\n\n"

            if matches:
                custody.record(
                    "yara_match", "yara_scanner",
                    detail=", ".join(m.rule_name for m in matches),
                )
                # Provide YARA findings as additional context for the LLM.
                rule_names = [m.rule_name for m in matches]
                yara_context = (
                    f"YARA signature scan detected the following rules: "
                    f"{rule_names}. Factor these detections into your analysis.\n\n"
                )
        else:
            yara_header = "YARA Pre-Scan: Engine unavailable (no rules loaded).\n\n"

        # Show YARA results immediately, then "Analyzing..."
        app._write_audit_result(yara_header, clear=True)
        app._write_audit_result("Analyzing script with Gemma AI...\n")
        app.audit_button.configure(state="disabled")

        def _on_result(result: str) -> None:
            custody.record("script_audit_complete", "script_auditor",
                           detail=f"Result length: {len(result)} chars")
            app.after(0, app._write_audit_result,
                      yara_header + f"\n{result}\n", True)
            app.after(0, lambda: app.audit_button.configure(state="normal"))

        def _on_error(msg: str) -> None:
            custody.record("script_audit_error", "script_auditor",
                           detail=msg)
            app.after(0, app._write_audit_result,
                      f"\nAudit error: {msg}\n", False)
            app.after(0, lambda: app.audit_button.configure(state="normal"))

        local_ai.analyze(
            text=script,
            system_prompt=(
                "Analyze this script for security risks and explain what it does:\n\n"
                + yara_context
            ),
            on_complete=_on_result,
            on_error=_on_error,
        )

    # Override the GUI's built-in stub with our wired version.
    app.audit_button.configure(command=_audit_script)

    # ==================================================================
    #  Regex Wizard wiring
    # ==================================================================

    def _run_regex_wizard() -> None:
        text = app.regex_input_textbox.get("1.0", "end").strip()
        if not text:
            app._write_regex_result(
                "Please enter plain English or Regex above first.\n", clear=True)
            return

        if local_ai.is_busy:
            app._write_regex_result(
                "An analysis is already running. Please wait.\n", clear=True)
            return

        custody.record("regex_wizard_start", "regex_wizard",
                       detail=f"Input length: {len(text)} chars")

        app._write_regex_result(
            "Analyzing with Gemma AI...\n", clear=True)
        app.regex_button.configure(state="disabled")

        def _on_result(result: str) -> None:
            custody.record("regex_wizard_complete", "regex_wizard")
            app.after(0, app._write_regex_result, f"\n{result}\n", True)
            app.after(0, lambda: app.regex_button.configure(state="normal"))

        def _on_error(msg: str) -> None:
            custody.record("regex_wizard_error", "regex_wizard", detail=msg)
            app.after(0, app._write_regex_result,
                      f"\nAnalysis error: {msg}\n", True)
            app.after(0, lambda: app.regex_button.configure(state="normal"))

        local_ai.analyze(
            text=text,
            system_prompt="Act as a Regex expert. Translate this plain English to a Regular Expression, or explain this Regex string:\n\n",
            on_complete=_on_result,
            on_error=_on_error,
        )

    app.regex_button.configure(command=_run_regex_wizard)

    # ==================================================================
    #  Phishing Analyzer wiring
    # ==================================================================

    def _run_phishing_analyzer() -> None:
        text = app.phishing_input_textbox.get("1.0", "end").strip()
        if not text:
            app._write_phishing_result(
                "Please paste raw email headers and body above first.\n", clear=True)
            return

        if local_ai.is_busy:
            app._write_phishing_result(
                "An analysis is already running. Please wait.\n", clear=True)
            return

        custody.record("phishing_analysis_start", "phishing_analyzer",
                       detail=f"Email length: {len(text)} chars")

        app._write_phishing_result(
            "Analyzing with Gemma AI...\n", clear=True)
        app.phishing_button.configure(state="disabled")

        def _on_result(result: str) -> None:
            custody.record("phishing_analysis_complete", "phishing_analyzer")
            app.after(0, app._write_phishing_result, f"\n{result}\n", True)
            app.after(0, lambda: app.phishing_button.configure(state="normal"))

        def _on_error(msg: str) -> None:
            custody.record("phishing_analysis_error", "phishing_analyzer",
                           detail=msg)
            app.after(0, app._write_phishing_result,
                      f"\nAnalysis error: {msg}\n", True)
            app.after(0, lambda: app.phishing_button.configure(state="normal"))

        local_ai.analyze(
            text=text,
            system_prompt="Act as a SOC analyst evaluating an email. Analyze these raw email headers and body text for phishing indicators and SPF/DKIM failures:\n\n",
            on_complete=_on_result,
            on_error=_on_error,
        )

    app.phishing_button.configure(command=_run_phishing_analyzer)

    # ==================================================================
    #  Log Analyzer wiring
    # ==================================================================

    def _run_log_analyzer() -> None:
        text = app.output_textbox.get("1.0", "end").strip()
        if not text or text.startswith("Parse error") or text.startswith("No "):
            app.write_output("\nPlease load a valid log file first.\n")
            return

        if local_ai.is_busy:
            app.write_output("\nAn analysis is already running. Please wait.\n")
            return

        # Truncate to last 20,000 chars to avoid overflowing the context window.
        text = text[-20000:]

        custody.record("log_analysis_start", "log_analyzer",
                       detail=f"Log text length: {len(text)} chars")

        app.write_output("\nRunning AI analysis on logs...\n")
        app.analyze_button.configure(state="disabled")

        def _on_result(result: str) -> None:
            custody.record("log_analysis_complete", "log_analyzer")
            app.after(0, app.write_output, f"\n{result}\n")
            app.after(0, lambda: app.analyze_button.configure(state="normal"))

        def _on_error(msg: str) -> None:
            custody.record("log_analysis_error", "log_analyzer", detail=msg)
            app.after(0, app.write_output, f"\nAI Error: {msg}\n")
            app.after(0, lambda: app.analyze_button.configure(state="normal"))

        local_ai.analyze(
            text=text,
            system_prompt="You are a cybersecurity expert. Summarize these errors and suggest fixes:\n\n",
            on_complete=_on_result,
            on_error=_on_error,
        )

    app.analyze_button.configure(command=_run_log_analyzer)

    # ==================================================================
    #  Chat Assistant wiring
    # ==================================================================

    def _run_chat_assistant() -> None:
        msg = app.chat_input_entry.get().strip()
        if not msg:
            return

        if local_ai.is_busy:
            app._write_chat_message("⚠  An analysis is already running. Please wait.")
            return

        custody.record("chat_message", "chat_assistant",
                       detail=f"User message: {len(msg)} chars")

        # Show the user's message immediately.
        app._write_chat_message(f"Admin:\n{msg}\n")
        app._write_chat_message("─" * 60 + "\n")

        # Clear the input field.
        app.chat_input_entry.delete(0, "end")

        # Disable the send button while waiting.
        app.chat_send_button.configure(state="disabled")

        # Grab the full conversation history for context.
        history = app.chat_history_textbox.get("1.0", "end").strip()
        # Truncate history to avoid overflow.
        history = history[-20000:]

        def _on_result(result: str) -> None:
            custody.record("chat_response", "chat_assistant",
                           detail=f"Response: {len(result)} chars")
            # Strip unwanted markdown fences generated by Gemma
            clean_res = result.strip("` \n")
            app.after(0, app._write_chat_message, f"IT-Copilot:\n{clean_res}\n")
            app.after(0, app._write_chat_message, "─" * 60 + "\n")
            app.after(0, lambda: app.chat_send_button.configure(state="normal"))

        def _on_error(msg: str) -> None:
            custody.record("chat_error", "chat_assistant", detail=msg)
            app.after(0, app._write_chat_message, f"⚠  Error: {msg}\n")
            app.after(0, lambda: app.chat_send_button.configure(state="normal"))

        local_ai.analyze(
            text=history,
            system_prompt="You are an expert IT Systems Administrator. Keep answers highly technical and concise. Do not use conversational filler.\n\n",
            on_complete=_on_result,
            on_error=_on_error,
        )

    app.chat_send_button.configure(command=_run_chat_assistant)
    app.chat_input_entry.bind("<Return>", lambda e: _run_chat_assistant())

    # ==================================================================
    #  Launch
    # ==================================================================

    def _on_close() -> None:
        """Graceful shutdown: close custody log with integrity hash."""
        monitor.stop_watchdog()
        session.stop_autosave()
        custody.log_app_stop()
        custody.close()
        app.destroy()

    app.protocol("WM_DELETE_WINDOW", _on_close)

    monitor.start_watchdog()
    app.after(300, _start)
    app.mainloop()


if __name__ == "__main__":
    main()
