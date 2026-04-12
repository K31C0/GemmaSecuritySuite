"""
main.py – Entry point for Gemma AI Security Suite.

Wires together:
  • ModelManager  (downloader.py)  – model download / check
  • AppGUI        (gui_manager.py) – all UI frames
  • LocalAI       (ai_inference.py)– script audit via local model
"""

from ai_inference import LocalAI
from downloader import ModelManager
from gui_manager import AppGUI
from typing import Optional


def main() -> None:
    app = AppGUI()
    mgr = ModelManager()
    local_ai = LocalAI()          # persistent instance, shared across audits

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
        if mgr.file_exists():
            app.set_setup_progress(1.0)
            app.set_setup_status("Model already present.")
            app.after(400, lambda: app.show_frame("dashboard"))
        else:
            app.set_setup_status("Starting download\u2026")
            mgr.ensure_file(
                progress_callback=on_progress,
                done_callback=on_done,
            )

    # ==================================================================
    #  Script Auditor wiring
    # ==================================================================

    def _audit_script() -> None:
        """Grab the pasted script, prepend the analysis prompt, and
        send the combined text to LocalAI.  Results are piped back
        to the GUI's audit output textbox via app.after()."""
        script = app.script_input_textbox.get("1.0", "end").strip()
        if not script:
            app._write_audit_result(
                "Please paste a script above first.\n", clear=True)
            return

        if local_ai.is_busy:
            app._write_audit_result(
                "An analysis is already running. Please wait.\n", clear=True)
            return

        app._write_audit_result(
            "Analyzing script with Gemma AI...\n", clear=True)
        app.audit_button.configure(state="disabled")

        def _on_result(result: str) -> None:
            app.after(0, app._write_audit_result, f"\n{result}\n", True)
            app.after(0, lambda: app.audit_button.configure(state="normal"))

        def _on_error(msg: str) -> None:
            app.after(0, app._write_audit_result,
                      f"\nAudit error: {msg}\n", True)
            app.after(0, lambda: app.audit_button.configure(state="normal"))

        local_ai.analyze(
            text=script,
            system_prompt="Analyze this script for security risks and explain what it does:\n\n",
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

        app._write_regex_result(
            "Analyzing with Gemma AI...\n", clear=True)
        app.regex_button.configure(state="disabled")

        def _on_result(result: str) -> None:
            app.after(0, app._write_regex_result, f"\n{result}\n", True)
            app.after(0, lambda: app.regex_button.configure(state="normal"))

        def _on_error(msg: str) -> None:
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

        app._write_phishing_result(
            "Analyzing with Gemma AI...\n", clear=True)
        app.phishing_button.configure(state="disabled")

        def _on_result(result: str) -> None:
            app.after(0, app._write_phishing_result, f"\n{result}\n", True)
            app.after(0, lambda: app.phishing_button.configure(state="normal"))

        def _on_error(msg: str) -> None:
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

        app.write_output("\nRunning AI analysis on logs...\n")
        app.analyze_button.configure(state="disabled")

        def _on_result(result: str) -> None:
            app.after(0, app.write_output, f"\n{result}\n")
            app.after(0, lambda: app.analyze_button.configure(state="normal"))

        def _on_error(msg: str) -> None:
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
            # Strip unwanted markdown fences generated by Gemma
            clean_res = result.strip("` \n")
            app.after(0, app._write_chat_message, f"IT-Copilot:\n{clean_res}\n")
            app.after(0, app._write_chat_message, "─" * 60 + "\n")
            app.after(0, lambda: app.chat_send_button.configure(state="normal"))

        def _on_error(msg: str) -> None:
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

    app.after(300, _start)
    app.mainloop()


if __name__ == "__main__":
    main()
