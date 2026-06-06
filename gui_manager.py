"""
gui_manager.py – CustomTkinter front-end for Gemma AI Security Suite.

Provides the AppGUI class with six switchable frames:
  • Setup Screen       – progress bar + status label (shown during model download)
  • Dashboard          – 2×2 grid of tool cards
  • Log Analyzer       – load CSV, output area, analyze button
  • File Hash Verifier – select file, MD5/SHA-256 display
  • Network Diagnostics– IP/host entry, ping + port scan results
  • IP Reputation      – IP entry, geo/ISP/ASN display
"""

import customtkinter as ctk
import random
import threading
import tkinter as tk
from tkinter import filedialog
from typing import Optional


# ── Colour / Theme Constants  (Gemma AI) ─────────────────────────
BG_DARK         = "#070914"
SURFACE         = "#121626"
SURFACE_ALT     = "#1E243A"
ACCENT          = "#00E5FF"      # cyan
ACCENT_HOVER    = "#00B8D4"
HIGHLIGHT       = "#B388FF"      # purple
HIGHLIGHT_HOVER = "#9C6AFF"
TEXT_PRIMARY    = "#E8EAF6"
TEXT_SECONDARY  = "#8C93B5"
BORDER_SUBTLE   = "#1A2340"

# Animated background line colours (low-opacity feel via muted shades).
_LINE_COLOURS = ["#0D3D47", "#122044", "#0A4F5C", "#1B1640", "#0E5466"]


class AppGUI(ctk.CTk):
    """Top-level application window.

    Parameters
    ----------
    title : str
        Window title.
    geometry : str
        Initial window size, e.g. ``"900x560"``.
    """

    def __init__(
        self,
        title: str = "Gemma AI – Security Suite",
        geometry: str = "960x620",
    ) -> None:
        super().__init__()

        # ── Window chrome ────────────────────────────────────────────
        self.title(title)
        self.geometry(geometry)
        self.minsize(800, 540)
        self.configure(fg_color=BG_DARK)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # ── Container that holds whichever frame is active ───────────
        self._container = ctk.CTkFrame(self, fg_color="transparent")
        self._container.pack(fill="both", expand=True)
        self._container.grid_rowconfigure(0, weight=1)
        self._container.grid_columnconfigure(0, weight=1)

        # ── Build all frames (stacked on top of each other) ──────────
        self._frames: dict[str, ctk.CTkFrame] = {}

        # Optional forensic logger — set by main.py after construction.
        self.custody_logger = None

        self._build_setup_screen()
        self._build_dashboard()
        self._build_main_app()
        self._build_hash_checker()
        self._build_network_scanner()
        self._build_ip_lookup()
        self._build_script_auditor()
        self._build_regex_wizard()
        self._build_phishing_analyzer()
        self._build_chat_assistant()
        self._build_env_fingerprint()
        self._build_evidence_vault()
        self._build_report_generator()

        # Start on the setup screen.
        self._current_frame: Optional[str] = None
        self.show_frame("setup")

    # ==================================================================
    #  Shared helpers
    # ==================================================================

    def show_frame(self, name: str) -> None:
        """Raise the frame identified by *name*."""
        frame = self._frames.get(name)
        if frame is None:
            raise ValueError(f"Unknown frame: {name!r}  (valid: {list(self._frames)})")
        frame.tkraise()
        self._current_frame = name

    @staticmethod
    def _make_toolbar(parent, title_text: str, back_target: str | None = None):
        """Build a standard toolbar and return (toolbar_frame, spacer_col)."""
        toolbar = ctk.CTkFrame(parent, fg_color=SURFACE, corner_radius=8,
                               height=56, border_width=1, border_color=BORDER_SUBTLE)
        toolbar.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 0))
        toolbar.grid_columnconfigure(2, weight=1)
        return toolbar

    @staticmethod
    def _make_back_button(toolbar, gui_ref, target: str = "dashboard"):
        """Add a transparent ⬅ Dashboard button to col 0 of *toolbar*."""
        btn = ctk.CTkButton(
            toolbar,
            text="\u2B05  Dashboard",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color="transparent",
            hover_color=SURFACE_ALT,
            text_color=TEXT_SECONDARY,
            corner_radius=8, height=36, width=120, border_width=0,
            command=lambda: gui_ref.show_frame(target),
        )
        btn.grid(row=0, column=0, padx=(12, 4), pady=12)
        return btn

    @staticmethod
    def _make_toolbar_title(toolbar, text: str):
        lbl = ctk.CTkLabel(
            toolbar, text=text,
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color=TEXT_PRIMARY,
        )
        lbl.grid(row=0, column=1, padx=(4, 0), pady=12)
        return lbl

    @staticmethod
    def _make_info_box(parent, text: str, row: int = 1):
        """Render a subtle guidance banner below the toolbar."""
        info = ctk.CTkFrame(parent, fg_color=SURFACE_ALT, corner_radius=8)
        info.grid(row=row, column=0, sticky="ew", padx=16, pady=(8, 0))
        lbl = ctk.CTkLabel(
            info, text=text,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_SECONDARY,
        )
        lbl.grid(row=0, column=0, padx=16, pady=8, sticky="w")
        return info

    # ==================================================================
    #  Setup Screen
    # ==================================================================

    def _build_setup_screen(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["setup"] = frame

        frame.grid_rowconfigure(0, weight=1)
        frame.grid_rowconfigure(4, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            frame, text="\U0001f6e1\ufe0f  Gemma Security Suite",
            font=ctk.CTkFont(family="Segoe UI", size=28, weight="bold"),
            text_color=TEXT_PRIMARY,
        )
        header.grid(row=1, column=0, pady=(0, 8))

        self.setup_status_label = ctk.CTkLabel(
            frame, text="Preparing resources\u2026",
            font=ctk.CTkFont(family="Segoe UI", size=14),
            text_color=TEXT_SECONDARY,
        )
        self.setup_status_label.grid(row=2, column=0, pady=(0, 18))

        self.setup_progress_bar = ctk.CTkProgressBar(
            frame, width=420, height=12, corner_radius=6,
            fg_color=SURFACE_ALT, progress_color=ACCENT, border_width=0,
        )
        self.setup_progress_bar.set(0)
        self.setup_progress_bar.grid(row=3, column=0)

    def set_setup_progress(self, value: float) -> None:
        self.setup_progress_bar.set(max(0.0, min(value, 1.0)))

    def set_setup_status(self, text: str) -> None:
        self.setup_status_label.configure(text=text)

    # ==================================================================
    #  Dashboard Screen
    # ==================================================================

    def _build_dashboard(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["dashboard"] = frame

        # Use place() geometry so the canvas and content can layer.
        # Canvas fills the entire frame as the bottom layer.
        self._dash_canvas = tk.Canvas(
            frame, bg=BG_DARK, highlightthickness=0,
        )
        self._dash_canvas.place(x=0, y=0, relwidth=1, relheight=1)

        # Content overlay (transparent frame placed on top of canvas).
        overlay = ctk.CTkFrame(frame, fg_color="transparent")
        overlay.place(x=0, y=0, relwidth=1, relheight=1)
        overlay.grid_columnconfigure(0, weight=1)
        overlay.grid_rowconfigure(0, weight=1)  # top spacer
        overlay.grid_rowconfigure(3, weight=1)  # bottom spacer

        # ── Title ────────────────────────────────────────────────────
        title = ctk.CTkLabel(
            overlay, text="Gemma AI  Security Suite",
            font=ctk.CTkFont(family="Segoe UI", size=32, weight="bold"),
            text_color=TEXT_PRIMARY,
        )
        title.grid(row=1, column=0, pady=(48, 8))

        subtitle = ctk.CTkLabel(
            overlay, text="Local AI-Powered Security Operations",
            font=ctk.CTkFont(family="Segoe UI", size=14),
            text_color=TEXT_SECONDARY,
        )
        subtitle.grid(row=2, column=0, pady=(0, 28))

        # ── Tool Cards Container (Responsive grid) ─────────
        cards = ctk.CTkFrame(overlay, fg_color="transparent")
        cards.grid(row=3, column=0, padx=40, sticky="nsew")
        cards.grid_columnconfigure((0, 1, 2, 3), weight=1)

        # Row 0: IT Support Co-Pilot (Featured, spanning all columns)
        btn_copilot = ctk.CTkButton(
            cards, text="\ud83d\udcac  IT Support Co-Pilot",
            font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"),
            fg_color=HIGHLIGHT, hover_color=HIGHLIGHT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=90, border_width=0,
            command=lambda: self.show_frame("chat_assistant"),
        )
        btn_copilot.grid(row=0, column=0, columnspan=4, sticky="nsew", padx=12, pady=(10, 20))

        # Row 1: four regular cards across
        card_row1 = [
            ("\U0001f4ca  Log Analyzer",        "main",         0),
            ("\U0001f510  File Hash Verifier",   "hash_checker", 1),
            ("\U0001f310  Network Diagnostics",  "net_scanner",  2),
            ("\U0001f30d  IP Reputation Lookup", "ip_lookup",    3),
        ]
        for text, target, col in card_row1:
            btn = ctk.CTkButton(
                cards, text=text,
                font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
                fg_color=SURFACE, hover_color=SURFACE_ALT,
                text_color=TEXT_PRIMARY, corner_radius=8,
                height=110,
                border_width=1, border_color=BORDER_SUBTLE,
                command=lambda t=target: self.show_frame(t),
            )
            btn.grid(row=1, column=col, sticky="nsew", padx=12, pady=10)

        # Row 2: three regular cards across
        card_row2 = [
            ("\U0001f4dc  Script Auditor",       "script_auditor",    0),
            ("\u26a1  Regex Wizard",            "regex_wizard",      1),
            ("\ud83c\udfa3  Phishing Analyzer", "phishing_analyzer", 2),
        ]
        
        # Center the 3 buttons in the 4-column grid by spanning the middle ones or using a sub-frame
        # Sub-frame ensures they are perfectly centered
        row2_frame = ctk.CTkFrame(cards, fg_color="transparent")
        row2_frame.grid(row=2, column=0, columnspan=4, sticky="nsew", pady=10)
        row2_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        # We place them in columns 0, 1, 2 but shift them with padding or a container
        # Since the first row is 4 equal cols, a 3-col row looks best inside its own 3-col grid
        row2_centered = ctk.CTkFrame(row2_frame, fg_color="transparent")
        row2_centered.pack(expand=True, fill="both")
        row2_centered.grid_columnconfigure((0, 1, 2), weight=1)

        for i, (text, target, _) in enumerate(card_row2):
            btn = ctk.CTkButton(
                row2_centered, text=text,
                font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
                fg_color=SURFACE, hover_color=SURFACE_ALT,
                text_color=TEXT_PRIMARY, corner_radius=8,
                height=110,
                border_width=1, border_color=BORDER_SUBTLE,
                command=lambda t=target: self.show_frame(t),
            )
            btn.grid(row=0, column=i, sticky="nsew", padx=12, pady=0)

        # Row 3: forensic tools
        row3_frame = ctk.CTkFrame(cards, fg_color="transparent")
        row3_frame.grid(row=3, column=0, columnspan=4, sticky="nsew", pady=10)
        row3_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        row3_centered = ctk.CTkFrame(row3_frame, fg_color="transparent")
        row3_centered.pack(expand=True, fill="both")
        row3_centered.grid_columnconfigure((0, 1, 2), weight=1)

        forensic_cards = [
            ("\U0001f50d  Environment Snapshot", "env_fingerprint",  0),
            ("\U0001f512  Evidence Vault",       "evidence_vault",   1),
            ("\U0001f4cb  Incident Report",      "report_gen",       2),
        ]
        for text, target, col in forensic_cards:
            btn = ctk.CTkButton(
                row3_centered, text=text,
                font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
                fg_color=SURFACE, hover_color=SURFACE_ALT,
                text_color=TEXT_PRIMARY, corner_radius=8,
                height=110,
                border_width=1, border_color=BORDER_SUBTLE,
                command=lambda t=target: self.show_frame(t),
            )
            btn.grid(row=0, column=col, sticky="nsew", padx=12, pady=0)

        # ── Seed animated background lines ───────────────────────────
        self._bg_lines: list[dict] = []
        self._dash_canvas.update_idletasks()       # ensure winfo is valid
        self._init_bg_lines()
        self._animate_background()

    # ------------------------------------------------------------------
    #  Dashboard background animation
    # ------------------------------------------------------------------

    def _init_bg_lines(self) -> None:
        """Create the initial set of animated horizontal lines."""
        canvas = self._dash_canvas
        w = max(canvas.winfo_width(), 960)
        h = max(canvas.winfo_height(), 620)

        for _ in range(5):
            y = random.randint(40, h - 40)
            length = random.randint(120, 360)
            x = random.randint(-length, w)
            speed = random.uniform(1.2, 3.0)
            colour = random.choice(_LINE_COLOURS)
            line_id = canvas.create_line(
                x, y, x + length, y,
                fill=colour, width=2, smooth=True,
            )
            self._bg_lines.append({
                "id": line_id, "x": float(x), "y": y,
                "length": length, "speed": speed, "colour": colour,
            })

    def _animate_background(self) -> None:
        """Move every line rightward; wrap to the left edge when off-screen."""
        canvas = self._dash_canvas
        try:
            w = max(canvas.winfo_width(), 960)
            h = max(canvas.winfo_height(), 620)
        except tk.TclError:
            return  # widget destroyed

        for line in self._bg_lines:
            line["x"] += line["speed"]
            x = line["x"]
            # If the line's left edge is past the right edge, reset.
            if x > w:
                line["x"] = -line["length"]
                line["y"] = random.randint(40, h - 40)
                line["colour"] = random.choice(_LINE_COLOURS)
                x = line["x"]
            canvas.coords(
                line["id"],
                x, line["y"], x + line["length"], line["y"],
            )
            canvas.itemconfig(line["id"], fill=line["colour"])

        self.after(30, self._animate_background)

    # ==================================================================
    #  Environment Fingerprint
    # ==================================================================

    def _build_env_fingerprint(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["env_fingerprint"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)

        # ── Toolbar ──────────────────────────────────────────────────
        toolbar = self._make_toolbar(frame, "\U0001f50d  Environment Snapshot")
        self._make_back_button(toolbar, self)
        self._make_toolbar_title(toolbar, "\U0001f50d  Environment Snapshot")

        self.env_capture_button = ctk.CTkButton(
            toolbar, text="\U0001f4f7  Capture Snapshot",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=36, border_width=0,
        )
        self.env_capture_button.grid(row=0, column=3, padx=(8, 12), pady=12)

        # ── Info box ─────────────────────────────────────────────────
        self._make_info_box(
            frame,
            "\U0001f6c8  Captures a full snapshot of the host: OS, processes, "
            "network interfaces, ARP table, TCP connections, and recent events.",
        )

        # ── Separator ────────────────────────────────────────────────
        ctk.CTkFrame(frame, fg_color=BORDER_SUBTLE, height=1).grid(
            row=2, column=0, sticky="ew", padx=24, pady=8)

        # ── Results textbox ──────────────────────────────────────────
        self.env_output_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, wrap="none",
            state="disabled", activate_scrollbars=True,
        )
        self.env_output_textbox.grid(row=3, column=0, sticky="nsew",
                                      padx=16, pady=(4, 16))

    def write_env_output(self, text: str, clear: bool = False) -> None:
        """Write text to the environment snapshot output textbox."""
        self.env_output_textbox.configure(state="normal")
        if clear:
            self.env_output_textbox.delete("1.0", "end")
        self.env_output_textbox.insert("end", text)
        self.env_output_textbox.configure(state="disabled")
        self.env_output_textbox.see("end")

    # ==================================================================
    #  Evidence Vault
    # ==================================================================

    def _build_evidence_vault(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["evidence_vault"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(5, weight=1)  # item list row

        # -- Toolbar --
        toolbar = self._make_toolbar(frame, "\U0001f512  Evidence Vault")
        self._make_back_button(toolbar, self)
        self._make_toolbar_title(toolbar, "\U0001f512  Evidence Vault")

        # -- Info box --
        self._make_info_box(
            frame,
            "\U0001f6c8  AES-256-GCM encrypted storage for malicious files "
            "and forensic evidence. Files are password-protected and "
            "integrity-verified.",
        )

        # -- Separator --
        ctk.CTkFrame(frame, fg_color=BORDER_SUBTLE, height=1).grid(
            row=2, column=0, sticky="ew", padx=24, pady=8)

        # -- Controls row --
        controls = ctk.CTkFrame(frame, fg_color="transparent")
        controls.grid(row=3, column=0, sticky="ew", padx=16, pady=(4, 8))
        controls.grid_columnconfigure(1, weight=1)

        # Password field
        pw_label = ctk.CTkLabel(
            controls, text="Password:",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_SECONDARY,
        )
        pw_label.grid(row=0, column=0, padx=(0, 8), pady=4)

        self.vault_password_entry = ctk.CTkEntry(
            controls, show="*",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=6, height=36,
            placeholder_text="Enter vault password...",
        )
        self.vault_password_entry.grid(row=0, column=1, sticky="ew",
                                        padx=4, pady=4)

        # Store button
        self.vault_store_button = ctk.CTkButton(
            controls, text="\U0001f4e5  Store File",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=36, border_width=0,
        )
        self.vault_store_button.grid(row=0, column=2, padx=(8, 4), pady=4)

        # Extract button
        self.vault_extract_button = ctk.CTkButton(
            controls, text="\U0001f4e4  Extract Selected",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=SURFACE, hover_color=SURFACE_ALT,
            text_color=TEXT_PRIMARY, corner_radius=8,
            height=36, border_width=1, border_color=BORDER_SUBTLE,
        )
        self.vault_extract_button.grid(row=0, column=3, padx=(4, 0), pady=4)

        # Refresh button
        self.vault_refresh_button = ctk.CTkButton(
            controls, text="\U0001f504",
            font=ctk.CTkFont(size=16),
            fg_color=SURFACE, hover_color=SURFACE_ALT,
            text_color=TEXT_PRIMARY, corner_radius=8,
            width=36, height=36, border_width=1, border_color=BORDER_SUBTLE,
        )
        self.vault_refresh_button.grid(row=0, column=4, padx=(8, 0), pady=4)

        # -- Notes entry --
        notes_row = ctk.CTkFrame(frame, fg_color="transparent")
        notes_row.grid(row=4, column=0, sticky="ew", padx=16, pady=(0, 4))
        notes_row.grid_columnconfigure(1, weight=1)

        notes_label = ctk.CTkLabel(
            notes_row, text="Notes:",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_SECONDARY,
        )
        notes_label.grid(row=0, column=0, padx=(0, 8), pady=4)

        self.vault_notes_entry = ctk.CTkEntry(
            notes_row,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=6, height=36,
            placeholder_text="Analyst notes for this evidence item...",
        )
        self.vault_notes_entry.grid(row=0, column=1, sticky="ew", pady=4)

        # -- Item list (scrollable textbox) --
        self.vault_list_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, wrap="none",
            state="disabled", activate_scrollbars=True,
        )
        self.vault_list_textbox.grid(row=5, column=0, sticky="nsew",
                                      padx=16, pady=(4, 8))

        # -- Status bar --
        self.vault_status_label = ctk.CTkLabel(
            frame, text="No items in vault.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_SECONDARY, anchor="w",
        )
        self.vault_status_label.grid(row=6, column=0, sticky="ew",
                                      padx=20, pady=(0, 12))

    def write_vault_list(self, text: str, clear: bool = False) -> None:
        """Write text to the vault item list textbox."""
        self.vault_list_textbox.configure(state="normal")
        if clear:
            self.vault_list_textbox.delete("1.0", "end")
        self.vault_list_textbox.insert("end", text)
        self.vault_list_textbox.configure(state="disabled")

    # ==================================================================
    #  Incident Report Generator
    # ==================================================================

    def _build_report_generator(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["report_gen"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(5, weight=1)

        # -- Toolbar --
        toolbar = self._make_toolbar(frame, "\U0001f4cb  Incident Report")
        self._make_back_button(toolbar, self)
        self._make_toolbar_title(toolbar, "\U0001f4cb  Incident Report")

        # -- Info box --
        self._make_info_box(
            frame,
            "\U0001f6c8  Generates a comprehensive HTML incident report "
            "containing all findings, analyses, and custody chain data "
            "from this session.",
        )

        # -- Separator --
        ctk.CTkFrame(frame, fg_color=BORDER_SUBTLE, height=1).grid(
            row=2, column=0, sticky="ew", padx=24, pady=8)

        # -- Fields --
        fields = ctk.CTkFrame(frame, fg_color="transparent")
        fields.grid(row=3, column=0, sticky="ew", padx=16, pady=(4, 8))
        fields.grid_columnconfigure(1, weight=1)

        # Case ID
        ctk.CTkLabel(
            fields, text="Case ID:",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_SECONDARY,
        ).grid(row=0, column=0, padx=(0, 8), pady=4, sticky="e")

        self.report_case_entry = ctk.CTkEntry(
            fields,
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=6, height=36,
            placeholder_text="IR-2026-001",
        )
        self.report_case_entry.grid(row=0, column=1, sticky="ew", pady=4)

        # Analyst
        ctk.CTkLabel(
            fields, text="Analyst:",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_SECONDARY,
        ).grid(row=1, column=0, padx=(0, 8), pady=4, sticky="e")

        self.report_analyst_entry = ctk.CTkEntry(
            fields,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=6, height=36,
            placeholder_text="SOC Analyst",
        )
        self.report_analyst_entry.grid(row=1, column=1, sticky="ew", pady=4)

        # Notes
        ctk.CTkLabel(
            fields, text="Notes:",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_SECONDARY,
        ).grid(row=2, column=0, padx=(0, 8), pady=4, sticky="e")

        self.report_notes_entry = ctk.CTkEntry(
            fields,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=6, height=36,
            placeholder_text="Additional case notes...",
        )
        self.report_notes_entry.grid(row=2, column=1, sticky="ew", pady=4)

        # -- Buttons --
        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.grid(row=4, column=0, sticky="ew", padx=16, pady=(4, 8))

        self.report_html_button = ctk.CTkButton(
            btn_row, text="\U0001f4c4  Generate HTML Report",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=42, border_width=0,
        )
        self.report_html_button.pack(side="left", padx=(0, 12))

        self.report_pdf_button = ctk.CTkButton(
            btn_row, text="\U0001f4d1  Generate PDF",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            fg_color=SURFACE, hover_color=SURFACE_ALT,
            text_color=TEXT_PRIMARY, corner_radius=8,
            height=42, border_width=1, border_color=BORDER_SUBTLE,
        )
        self.report_pdf_button.pack(side="left", padx=(0, 12))

        # -- Output textbox --
        self.report_output_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, wrap="word",
            state="disabled", activate_scrollbars=True,
        )
        self.report_output_textbox.grid(row=5, column=0, sticky="nsew",
                                         padx=16, pady=(4, 16))

    def write_report_output(self, text: str, clear: bool = False) -> None:
        """Write text to the report output textbox."""
        self.report_output_textbox.configure(state="normal")
        if clear:
            self.report_output_textbox.delete("1.0", "end")
        self.report_output_textbox.insert("end", text)
        self.report_output_textbox.configure(state="disabled")
        self.report_output_textbox.see("end")

    # ==================================================================
    #  Log Analyzer (Main App)
    # ==================================================================

    def _build_main_app(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["main"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)   # textbox row

        # ── Toolbar ──────────────────────────────────────────────────
        toolbar = self._make_toolbar(frame, "\U0001f4ca  Log Analyzer")
        self._make_back_button(toolbar, self)
        self._make_toolbar_title(toolbar, "\U0001f4ca  Log Analyzer")

        self.load_file_button = ctk.CTkButton(
            toolbar, text="\U0001f4c2  Load Log File",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=36, border_width=0,
            command=self._on_load_file,
        )
        self.load_file_button.grid(row=0, column=3, padx=(8, 12), pady=12)

        # ── Info box ─────────────────────────────────────────────────
        self._make_info_box(
            frame,
            "\U0001f6c8  Scans Windows Event CSVs for Errors and Critical events.",
        )

        # ── Separator ────────────────────────────────────────────────
        ctk.CTkFrame(frame, fg_color=BORDER_SUBTLE, height=1).grid(
            row=2, column=0, sticky="ew", padx=24, pady=8)

        # ── Output text box ──────────────────────────────────────────
        self.output_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, wrap="word",
            state="disabled", activate_scrollbars=True,
        )
        self.output_textbox.grid(row=3, column=0, sticky="nsew", padx=16, pady=(4, 8))

        # ── Bottom action bar ────────────────────────────────────────
        action_bar = ctk.CTkFrame(frame, fg_color="transparent")
        action_bar.grid(row=4, column=0, sticky="ew", padx=16, pady=(0, 16))
        action_bar.grid_columnconfigure(0, weight=1)

        self.analyze_button = ctk.CTkButton(
            action_bar, text="\U0001f50d  Analyze",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            fg_color=HIGHLIGHT, hover_color=HIGHLIGHT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=42, width=180, border_width=0,
        )
        self.analyze_button.grid(row=0, column=1, padx=0)

    # -- Log Analyzer callbacks ----------------------------------------

    def _on_load_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Exported Event Log (CSV)",
            filetypes=[
                ("CSV files", "*.csv"),
                ("Text / Log files", "*.log *.txt"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        self._loaded_log_path = path
        self.write_output(f"Loaded: {path}\n", clear=True)
        # Parse immediately on a thread
        def _parse():
            try:
                from log_parser import parse_event_log, LogParseError
                rows = parse_event_log(path)
                if rows:
                    lines = []
                    lines.append(f"Found {len(rows)} Error/Critical event(s):\n\n")
                    for r in rows:
                        lvl = r.get('Level', '?')
                        ts  = r.get('Date and Time', r.get('Date', '?'))
                        src = r.get('Source', '?')
                        eid = r.get('Event ID', '?')
                        lines.append(f"  [{lvl}] {ts}  |  {src}  |  ID: {eid}\n")
                    self.after(0, self.write_output, "".join(lines))
                else:
                    self.after(0, self.write_output,
                              "No Error or Critical events found in this file.\n")
            except (LogParseError, FileNotFoundError) as exc:
                self.after(0, self.write_output, f"Parse error: {exc}\n")
            except Exception as exc:
                self.after(0, self.write_output, f"Unexpected error: {exc}\n")
        threading.Thread(target=_parse, daemon=True, name="LogParse").start()



    def write_output(self, text: str, clear: bool = False) -> None:
        self.output_textbox.configure(state="normal")
        if clear:
            self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", text)
        self.output_textbox.see("end")
        self.output_textbox.configure(state="disabled")

    def clear_output(self) -> None:
        self.write_output("", clear=True)

    # ==================================================================
    #  File Hash Verifier
    # ==================================================================

    def _build_hash_checker(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["hash_checker"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)

        # ── Toolbar ──────────────────────────────────────────────────
        toolbar = self._make_toolbar(frame, "\U0001f510  File Hash Verifier")
        self._make_back_button(toolbar, self)
        self._make_toolbar_title(toolbar, "\U0001f510  File Hash Verifier")

        self.verify_file_button = ctk.CTkButton(
            toolbar, text="\U0001f4c2  Select File",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=36, border_width=0,
            command=self._on_select_file_hash,
        )
        self.verify_file_button.grid(row=0, column=3, padx=(8, 12), pady=12)

        # ── Info box ─────────────────────────────────────────────────
        self._make_info_box(
            frame,
            "\U0001f6c8  Calculates MD5 and SHA-256 hashes to verify file integrity.",
        )

        # ── Separator ────────────────────────────────────────────────
        ctk.CTkFrame(frame, fg_color=BORDER_SUBTLE, height=1).grid(
            row=2, column=0, sticky="ew", padx=24, pady=8)

        # ── Hash results ─────────────────────────────────────────────
        content = ctk.CTkFrame(frame, fg_color="transparent")
        content.grid(row=3, column=0, sticky="nsew", padx=32, pady=(16, 32))
        content.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            content, text="MD5 Checksum",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color=TEXT_SECONDARY,
        ).grid(row=0, column=0, sticky="w", pady=(0, 4))

        self.md5_textbox = ctk.CTkEntry(
            content, font=ctk.CTkFont(family="Consolas", size=16),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, height=48, state="readonly",
        )
        self.md5_textbox.grid(row=1, column=0, sticky="ew", pady=(0, 24))

        ctk.CTkLabel(
            content, text="SHA-256 Checksum",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color=TEXT_SECONDARY,
        ).grid(row=2, column=0, sticky="w", pady=(0, 4))

        self.sha256_textbox = ctk.CTkEntry(
            content, font=ctk.CTkFont(family="Consolas", size=16),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, height=48, state="readonly",
        )
        self.sha256_textbox.grid(row=3, column=0, sticky="ew")

    def _on_select_file_hash(self) -> None:
        path = filedialog.askopenfilename(
            title="Select File to Hash",
            filetypes=[("All files", "*.*")],
        )
        if not path:
            return
        # Show "calculating" immediately
        for entry in (self.md5_textbox, self.sha256_textbox):
            entry.configure(state="normal")
            entry.delete(0, "end")
            entry.insert(0, "Calculating...")
            entry.configure(state="readonly")

        def _hash_worker():
            try:
                from hash_checker import compute_hashes, HashError
                result = compute_hashes(path)
                self.after(0, self._show_hash_result,
                           result["md5"], result["sha256"])
            except (HashError, FileNotFoundError) as exc:
                self.after(0, self._show_hash_result,
                           f"Error: {exc}", f"Error: {exc}")
            except Exception as exc:
                self.after(0, self._show_hash_result,
                           f"Error: {exc}", f"Error: {exc}")
        threading.Thread(target=_hash_worker, daemon=True,
                         name="HashCalc").start()

    def _show_hash_result(self, md5_val: str, sha256_val: str) -> None:
        self.md5_textbox.configure(state="normal")
        self.md5_textbox.delete(0, "end")
        self.md5_textbox.insert(0, md5_val)
        self.md5_textbox.configure(state="readonly")
        self.sha256_textbox.configure(state="normal")
        self.sha256_textbox.delete(0, "end")
        self.sha256_textbox.insert(0, sha256_val)
        self.sha256_textbox.configure(state="readonly")

    # ==================================================================
    #  Network Diagnostics
    # ==================================================================

    def _build_network_scanner(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["net_scanner"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(4, weight=1)   # results textbox row

        # ── Toolbar ──────────────────────────────────────────────────
        toolbar = self._make_toolbar(frame, "\U0001f310  Network Diagnostics")
        self._make_back_button(toolbar, self)
        self._make_toolbar_title(toolbar, "\U0001f310  Network Diagnostics")

        # ── Info box ─────────────────────────────────────────────────
        self._make_info_box(
            frame,
            "\U0001f6c8  Verifies host uptime via ICMP Ping and checks common ports (80, 443, 22, 3389).",
        )

        # ── Separator ────────────────────────────────────────────────
        ctk.CTkFrame(frame, fg_color=BORDER_SUBTLE, height=1).grid(
            row=2, column=0, sticky="ew", padx=24, pady=8)

        # ── Input row ────────────────────────────────────────────────
        input_row = ctk.CTkFrame(frame, fg_color="transparent")
        input_row.grid(row=3, column=0, sticky="ew", padx=16, pady=(4, 4))
        input_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            input_row, text="Target:",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color=TEXT_SECONDARY,
        ).grid(row=0, column=0, padx=(8, 8))

        self.net_host_entry = ctk.CTkEntry(
            input_row,
            placeholder_text="e.g. 8.8.8.8 or google.com",
            font=ctk.CTkFont(family="Consolas", size=14),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, height=40,
        )
        self.net_host_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8))

        self.net_run_button = ctk.CTkButton(
            input_row, text="\u25B6  Run Diagnostics",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=HIGHLIGHT, hover_color=HIGHLIGHT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=40, width=180, border_width=0,
            command=self._on_run_net_diag,
        )
        self.net_run_button.grid(row=0, column=2, padx=(0, 8))

        # ── Results textbox ──────────────────────────────────────────
        self.net_results_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, wrap="word",
            state="disabled", activate_scrollbars=True,
        )
        self.net_results_textbox.grid(row=4, column=0, sticky="nsew",
                                      padx=16, pady=(4, 16))

    def _on_run_net_diag(self) -> None:
        host = self.net_host_entry.get().strip()
        if not host:
            return
        self._write_net_results(f"Running diagnostics on {host}...\n", clear=True)
        self.net_run_button.configure(state="disabled")

        from network_scanner import NetworkTools
        tools = NetworkTools()

        def _callback(result_text: str):
            self.after(0, self._write_net_results, result_text, True)
            self.after(0, lambda: self.net_run_button.configure(state="normal"))

        tools.run_network_diagnostics(host, callback=_callback)

    def _write_net_results(self, text: str, clear: bool = False) -> None:
        self.net_results_textbox.configure(state="normal")
        if clear:
            self.net_results_textbox.delete("1.0", "end")
        self.net_results_textbox.insert("end", text)
        self.net_results_textbox.see("end")
        self.net_results_textbox.configure(state="disabled")

    # ==================================================================
    #  IP Reputation Lookup
    # ==================================================================

    def _build_ip_lookup(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["ip_lookup"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(4, weight=1)

        # ── Toolbar ──────────────────────────────────────────────────
        toolbar = self._make_toolbar(frame, "\U0001f30d  IP Reputation Lookup")
        self._make_back_button(toolbar, self)
        self._make_toolbar_title(toolbar, "\U0001f30d  IP Reputation Lookup")

        # ── Info box ─────────────────────────────────────────────────
        self._make_info_box(
            frame,
            "\U0001f6c8  Offline IP geolocation and ASN lookup via local IP2Location LITE database.",
        )

        # ── Separator ────────────────────────────────────────────────
        ctk.CTkFrame(frame, fg_color=BORDER_SUBTLE, height=1).grid(
            row=2, column=0, sticky="ew", padx=24, pady=8)

        # ── Input row ────────────────────────────────────────────────
        input_row = ctk.CTkFrame(frame, fg_color="transparent")
        input_row.grid(row=3, column=0, sticky="ew", padx=16, pady=(4, 4))
        input_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            input_row, text="IP Address:",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color=TEXT_SECONDARY,
        ).grid(row=0, column=0, padx=(8, 8))

        self.ip_entry = ctk.CTkEntry(
            input_row,
            placeholder_text="e.g. 8.8.8.8",
            font=ctk.CTkFont(family="Consolas", size=14),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, height=40,
        )
        self.ip_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8))

        self.ip_lookup_button = ctk.CTkButton(
            input_row, text="\U0001f50e  Lookup",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=HIGHLIGHT, hover_color=HIGHLIGHT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=40, width=140, border_width=0,
            command=self._on_ip_lookup,
        )
        self.ip_lookup_button.grid(row=0, column=2, padx=(0, 8))

        # ── Results grid ─────────────────────────────────────────────
        results = ctk.CTkFrame(frame, fg_color="transparent")
        results.grid(row=4, column=0, sticky="nsew", padx=32, pady=(16, 32))
        results.grid_columnconfigure(1, weight=1)

        self._ip_result_fields: dict[str, ctk.CTkEntry] = {}

        for idx, label_text in enumerate(["Country", "City", "ISP", "Organization (AS)"]):
            ctk.CTkLabel(
                results, text=label_text,
                font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
                text_color=TEXT_SECONDARY,
            ).grid(row=idx, column=0, sticky="w", padx=(0, 16), pady=8)

            entry = ctk.CTkEntry(
                results,
                font=ctk.CTkFont(family="Consolas", size=14),
                fg_color=SURFACE, text_color=TEXT_PRIMARY,
                border_color=BORDER_SUBTLE, border_width=1,
                corner_radius=8, height=42, state="readonly",
            )
            entry.grid(row=idx, column=1, sticky="ew", pady=8)

            key = label_text.split("(")[0].strip()  # "Organization (AS)" -> "Organization"
            self._ip_result_fields[key] = entry

        # ── Attribution (required by IP2Location LITE license) ───────
        ctk.CTkLabel(
            results, text="Data: IP2Location LITE \u2014 https://lite.ip2location.com",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_SECONDARY,
        ).grid(row=len(["Country", "City", "ISP", "Organization (AS)"]),
               column=0, columnspan=2, sticky="w", pady=(16, 0))

    def _on_ip_lookup(self) -> None:
        ip = self.ip_entry.get().strip()
        if not ip:
            return

        if self.custody_logger:
            self.custody_logger.record("ip_lookup_start", "ip_lookup",
                                       target=ip)

        # Show "Looking up..." immediately
        for field in self._ip_result_fields.values():
            field.configure(state="normal")
            field.delete(0, "end")
            field.insert(0, "Looking up...")
            field.configure(state="readonly")
        self.ip_lookup_button.configure(state="disabled")

        def _lookup_worker():
            try:
                from ip_lookup import lookup_ip
                data = lookup_ip(ip)
                if "Error" in data:
                    err = data["Error"]
                    if self.custody_logger:
                        self.custody_logger.record("ip_lookup_error",
                                                    "ip_lookup",
                                                    target=ip, detail=err)
                    self.after(0, self.set_ip_result, {
                        "Country": err, "City": "N/A",
                        "ISP": "N/A", "AS": "N/A",
                    })
                else:
                    if self.custody_logger:
                        self.custody_logger.record(
                            "ip_lookup_complete", "ip_lookup",
                            target=ip,
                            detail=f"{data.get('Country', '?')}, "
                                   f"{data.get('City', '?')}, "
                                   f"{data.get('ISP', '?')}")
                    self.after(0, self.set_ip_result, data)
            except Exception as exc:
                if self.custody_logger:
                    self.custody_logger.record("ip_lookup_error", "ip_lookup",
                                               target=ip, detail=str(exc))
                self.after(0, self.set_ip_result, {
                    "Country": f"Error: {exc}", "City": "N/A",
                    "ISP": "N/A", "AS": "N/A",
                })
            finally:
                self.after(0, lambda: self.ip_lookup_button.configure(state="normal"))

        threading.Thread(target=_lookup_worker, daemon=True,
                         name="IPLookup").start()

    def set_ip_result(self, data: dict[str, str]) -> None:
        """Populate the IP lookup result fields from a dict."""
        mapping = {
            "Country": "Country",
            "City": "City",
            "ISP": "ISP",
            "AS": "Organization",
        }
        for src_key, field_key in mapping.items():
            entry = self._ip_result_fields.get(field_key)
            if entry:
                entry.configure(state="normal")
                entry.delete(0, "end")
                entry.insert(0, data.get(src_key, "N/A"))
                entry.configure(state="readonly")

    # ==================================================================
    #  Script Auditor
    # ==================================================================

    def _build_script_auditor(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["script_auditor"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(4, weight=1)   # script input
        frame.grid_rowconfigure(6, weight=2)   # results output (bigger)

        # ── Toolbar ──────────────────────────────────────────────────
        toolbar = self._make_toolbar(frame, "\U0001f4dc  Script Auditor")
        self._make_back_button(toolbar, self)
        self._make_toolbar_title(toolbar, "\U0001f4dc  Script Auditor")

        # ── Info box ─────────────────────────────────────────────────
        self._make_info_box(
            frame,
            "\U0001f6c8  Uses local AI to analyze unknown PowerShell/Bash scripts for malicious behavior.",
        )

        # ── Separator ────────────────────────────────────────────────
        ctk.CTkFrame(frame, fg_color=BORDER_SUBTLE, height=1).grid(
            row=2, column=0, sticky="ew", padx=24, pady=8)

        # ── "Paste Script" label ─────────────────────────────────────
        ctk.CTkLabel(
            frame, text="Paste Script Below:",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=TEXT_SECONDARY,
        ).grid(row=3, column=0, sticky="w", padx=20, pady=(4, 2))

        # ── Script input textbox (editable) ──────────────────────────
        self.script_input_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, wrap="none",
            activate_scrollbars=True,
        )
        self.script_input_textbox.grid(row=4, column=0, sticky="nsew",
                                       padx=16, pady=(0, 4))

        # ── Audit button row ─────────────────────────────────────────
        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.grid(row=5, column=0, sticky="ew", padx=16, pady=4)
        btn_row.grid_columnconfigure(0, weight=1)

        self.audit_button = ctk.CTkButton(
            btn_row, text="\U0001f50d  Audit Script",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            fg_color=HIGHLIGHT, hover_color=HIGHLIGHT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=42, width=200, border_width=0,
            command=self._on_audit_script,
        )
        self.audit_button.grid(row=0, column=1, padx=0)

        # ── Results output (read-only) ───────────────────────────────
        self.audit_results_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, wrap="word",
            state="disabled", activate_scrollbars=True,
        )
        self.audit_results_textbox.grid(row=6, column=0, sticky="nsew",
                                        padx=16, pady=(0, 16))

    # -- Script Auditor callbacks --------------------------------------

    def _on_audit_script(self) -> None:
        script = self.script_input_textbox.get("1.0", "end").strip()
        if not script:
            self._write_audit_result("Please paste a script above first.\n",
                                     clear=True)
            return
        self._write_audit_result("Analyzing script with Gemma AI...\n",
                                 clear=True)
        self.audit_button.configure(state="disabled")

        from ai_inference import LocalAI
        ai = LocalAI()

        def _on_result(result: str):
            self.after(0, self._write_audit_result, f"\n{result}\n", True)
            self.after(0, lambda: self.audit_button.configure(state="normal"))

        def _on_error(msg: str):
            self.after(0, self._write_audit_result,
                       f"\nAudit error: {msg}\n", True)
            self.after(0, lambda: self.audit_button.configure(state="normal"))

        ai.analyze(script, on_complete=_on_result, on_error=_on_error)

    def _write_audit_result(self, text: str, clear: bool = False) -> None:
        self.audit_results_textbox.configure(state="normal")
        if clear:
            self.audit_results_textbox.delete("1.0", "end")
        self.audit_results_textbox.insert("end", text)
        self.audit_results_textbox.see("end")
        self.audit_results_textbox.configure(state="disabled")

    def _write_regex_result(self, text: str, clear: bool = False) -> None:
        self.regex_results_textbox.configure(state="normal")
        if clear:
            self.regex_results_textbox.delete("1.0", "end")
        self.regex_results_textbox.insert("end", text)
        self.regex_results_textbox.see("end")
        self.regex_results_textbox.configure(state="disabled")

    def _write_phishing_result(self, text: str, clear: bool = False) -> None:
        self.phishing_results_textbox.configure(state="normal")
        if clear:
            self.phishing_results_textbox.delete("1.0", "end")
        self.phishing_results_textbox.insert("end", text)
        self.phishing_results_textbox.see("end")
        self.phishing_results_textbox.configure(state="disabled")

    def _write_chat_message(self, text: str) -> None:
        self.chat_history_textbox.configure(state="normal")
        self.chat_history_textbox.insert("end", text + "\n")
        self.chat_history_textbox.see("end")
        self.chat_history_textbox.configure(state="disabled")

    # ==================================================================
    #  Regex Wizard
    # ==================================================================

    def _build_regex_wizard(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["regex_wizard"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(4, weight=1)   # input
        frame.grid_rowconfigure(6, weight=2)   # results output (bigger)

        # ── Toolbar ──────────────────────────────────────────────────
        toolbar = self._make_toolbar(frame, "\u26a1  Regex Wizard")
        self._make_back_button(toolbar, self)
        self._make_toolbar_title(toolbar, "\u26a1  Regex Wizard")

        # ── Info box ─────────────────────────────────────────────────
        self._make_info_box(
            frame,
            "\u2139\ufe0f  Translates plain English to Regular Expressions, or explains complex Regex strings.",
        )

        # ── Separator ────────────────────────────────────────────────
        ctk.CTkFrame(frame, fg_color=BORDER_SUBTLE, height=1).grid(
            row=2, column=0, sticky="ew", padx=24, pady=8)

        # ── "Input" label ────────────────────────────────────────────
        ctk.CTkLabel(
            frame, text="Enter Plain English or Regex below:",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=TEXT_SECONDARY,
        ).grid(row=3, column=0, sticky="w", padx=20, pady=(4, 2))

        # ── Input textbox (editable) ─────────────────────────────────
        self.regex_input_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, wrap="word",
            activate_scrollbars=True,
        )
        self.regex_input_textbox.grid(row=4, column=0, sticky="nsew",
                                      padx=16, pady=(0, 4))

        # ── Button row ───────────────────────────────────────────────
        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.grid(row=5, column=0, sticky="ew", padx=16, pady=4)
        btn_row.grid_columnconfigure(0, weight=1)

        self.regex_button = ctk.CTkButton(
            btn_row, text="\u26a1  Generate / Explain",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            fg_color=HIGHLIGHT, hover_color=HIGHLIGHT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=42, width=200, border_width=0,
        )
        self.regex_button.grid(row=0, column=1, padx=0)

        # ── Results output (read-only) ───────────────────────────────
        self.regex_results_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, wrap="word",
            state="disabled", activate_scrollbars=True,
        )
        self.regex_results_textbox.grid(row=6, column=0, sticky="nsew",
                                        padx=16, pady=(0, 16))

    # ==================================================================
    #  Phishing Analyzer
    # ==================================================================

    def _build_phishing_analyzer(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["phishing_analyzer"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(4, weight=1)   # input
        frame.grid_rowconfigure(6, weight=2)   # results output (bigger)

        # ── Toolbar ──────────────────────────────────────────────────
        toolbar = self._make_toolbar(frame, "\ud83c\udfa3  Phishing Analyzer")
        self._make_back_button(toolbar, self)
        self._make_toolbar_title(toolbar, "\ud83c\udfa3  Phishing Analyzer")

        # ── Info box ─────────────────────────────────────────────────
        self._make_info_box(
            frame,
            "\u2139\ufe0f  Analyzes raw email headers and body text for phishing indicators and SPF/DKIM failures.",
        )

        # ── Separator ────────────────────────────────────────────────
        ctk.CTkFrame(frame, fg_color=BORDER_SUBTLE, height=1).grid(
            row=2, column=0, sticky="ew", padx=24, pady=8)

        # ── "Paste Email" label ──────────────────────────────────────
        ctk.CTkLabel(
            frame, text="Paste Raw Email Source (Headers + Body) below:",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=TEXT_SECONDARY,
        ).grid(row=3, column=0, sticky="w", padx=20, pady=(4, 2))

        # ── Input textbox (editable) ─────────────────────────────────
        self.phishing_input_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, wrap="none",
            activate_scrollbars=True,
        )
        self.phishing_input_textbox.grid(row=4, column=0, sticky="nsew",
                                         padx=16, pady=(0, 4))

        # ── Button row ───────────────────────────────────────────────
        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.grid(row=5, column=0, sticky="ew", padx=16, pady=4)
        btn_row.grid_columnconfigure(0, weight=1)

        self.phishing_button = ctk.CTkButton(
            btn_row, text="\ud83d\udd0d  Analyze Email",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            fg_color=HIGHLIGHT, hover_color=HIGHLIGHT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=42, width=200, border_width=0,
        )
        self.phishing_button.grid(row=0, column=1, padx=0)

        # ── Results output (read-only) ───────────────────────────────
        self.phishing_results_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, wrap="word",
            state="disabled", activate_scrollbars=True,
        )
        self.phishing_results_textbox.grid(row=6, column=0, sticky="nsew",
                                           padx=16, pady=(0, 16))

    # ==================================================================
    #  Chat Assistant
    # ==================================================================

    def _build_chat_assistant(self) -> None:
        frame = ctk.CTkFrame(self._container, fg_color=BG_DARK, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self._frames["chat_assistant"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)   # chat history fills space

        # ── Toolbar ──────────────────────────────────────────────────
        toolbar = self._make_toolbar(frame, "\ud83d\udcac  IT Support Co-Pilot")
        self._make_back_button(toolbar, self)
        self._make_toolbar_title(toolbar, "\ud83d\udcac  IT Support Co-Pilot")

        # ── Chat history (read-only) ─────────────────────────────────
        self.chat_history_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=14),
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, wrap="word",
            state="disabled", activate_scrollbars=True,
        )
        self.chat_history_textbox.grid(row=2, column=0, sticky="nsew",
                                       padx=16, pady=(16, 8))

        # ── Input row ────────────────────────────────────────────────
        input_row = ctk.CTkFrame(frame, fg_color="transparent")
        input_row.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 16))
        input_row.grid_columnconfigure(0, weight=1)

        self.chat_input_entry = ctk.CTkEntry(
            input_row, font=ctk.CTkFont(family="Segoe UI", size=14),
            placeholder_text="Ask the IT Support Co-Pilot a question...",
            fg_color=SURFACE, text_color=TEXT_PRIMARY,
            border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=8, height=48,
        )
        self.chat_input_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.chat_send_button = ctk.CTkButton(
            input_row, text="Send \u27a4",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            fg_color=HIGHLIGHT, hover_color=HIGHLIGHT_HOVER,
            text_color="#ffffff", corner_radius=8,
            height=48, width=100, border_width=0,
        )
        self.chat_send_button.grid(row=0, column=1)

# ── Quick demo ────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = AppGUI()

    # Simulate a download finishing after 3 seconds, then flip to dashboard.
    def _fake_download(step: int = 0) -> None:
        steps = 50
        if step <= steps:
            pct = step / steps
            app.set_setup_progress(pct)
            app.set_setup_status(f"Downloading model\u2026 {pct * 100:.0f}%")
            app.after(60, _fake_download, step + 1)
        else:
            app.set_setup_status("Done!")
            app.after(400, lambda: app.show_frame("dashboard"))

    app.after(500, _fake_download)
    app.mainloop()
