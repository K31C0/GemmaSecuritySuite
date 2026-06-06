"""
config.py – Portable path resolution for GemmaSecuritySuite.

Provides a single source of truth for every file-system path the suite
touches.  All paths are resolved **relative to the toolkit root**,
ensuring zero writes to the host's %APPDATA%, registry, or temp dirs.

Resolution order for the base directory:
    1. GEMMA_SUITE_HOME environment variable  (explicit override)
    2. Directory containing the frozen .exe   (PyInstaller)
    3. Directory containing this source file  (development mode)

An optional ``config.ini`` placed in the toolkit root can override
individual sub-directory paths – useful when the analyst wants to
redirect evidence or logs to a separate partition.

USB directory layout::

    USB_ROOT/
    ├── config.ini              # optional overrides
    ├── GemmaSecuritySuite.exe
    └── data/
        ├── models/             # GGUF model files
        ├── databases/          # IP2Location BIN, etc.
        ├── logs/               # custody chain JSONL
        ├── evidence/           # encrypted vault
        ├── exports/            # PDF / HTML reports
        ├── playbooks/          # RAG source PDFs
        └── yara_rules/
            ├── community/      # bundled YARA-Rules repo
            └── custom/         # analyst's own .yar files
"""

import configparser
import os
import sys
from typing import Optional


# ── Base directory resolution ────────────────────────────────────────

def get_base_dir() -> str:
    """Return the root directory of the toolkit.

    The returned path is always an absolute, normalised directory that
    exists on disk (or can be created by :func:`ensure_dirs`).

    Resolution order:

    1. ``GEMMA_SUITE_HOME`` environment variable – allows the analyst
       to pin a specific location regardless of how the app is launched.
    2. The directory containing the frozen ``.exe`` when running under
       PyInstaller (``sys.frozen`` is ``True``).
    3. The directory containing *this* source file – standard
       development / ``python main.py`` workflow.
    """
    # 1. Explicit environment override
    env_home: Optional[str] = os.environ.get("GEMMA_SUITE_HOME")
    if env_home:
        return os.path.abspath(env_home)

    # 2. PyInstaller frozen executable
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))

    # 3. Development – resolve from this file's location
    return os.path.dirname(os.path.abspath(__file__))


# ── Path constants ───────────────────────────────────────────────────

BASE_DIR: str = get_base_dir()

# Top-level data directory that holds all mutable state.
DATA_DIR: str = os.path.join(BASE_DIR, "data")

# Sub-directories – each feature has a dedicated home.
MODELS_DIR:      str = os.path.join(DATA_DIR, "models")
DB_DIR:          str = os.path.join(DATA_DIR, "databases")
LOGS_DIR:        str = os.path.join(DATA_DIR, "logs")
EVIDENCE_DIR:    str = os.path.join(DATA_DIR, "evidence")
EXPORTS_DIR:     str = os.path.join(DATA_DIR, "exports")
PLAYBOOKS_DIR:   str = os.path.join(DATA_DIR, "playbooks")
YARA_RULES_DIR:  str = os.path.join(DATA_DIR, "yara_rules")
YARA_COMMUNITY:  str = os.path.join(YARA_RULES_DIR, "community")
YARA_CUSTOM:     str = os.path.join(YARA_RULES_DIR, "custom")

# Default model file path (Gemma 2 2B Instruct, Q4_K_M quantisation).
MODEL_FILE: str = os.path.join(MODELS_DIR, "gemma-2-2b-it.gguf")


# ── config.ini override ─────────────────────────────────────────────

def _apply_config_ini() -> None:
    """Read an optional ``config.ini`` from the toolkit root and
    override module-level path constants if custom values are provided.

    Expected INI format::

        [paths]
        models_dir   = E:\\CustomModels
        databases_dir = E:\\GeoDBs
        logs_dir     = E:\\IR_Logs
        evidence_dir = E:\\Evidence
        exports_dir  = E:\\Reports
        playbooks_dir = E:\\Playbooks

    Any key omitted from the file keeps its default value.
    """
    global DATA_DIR, MODELS_DIR, DB_DIR, LOGS_DIR, EVIDENCE_DIR
    global EXPORTS_DIR, PLAYBOOKS_DIR, YARA_RULES_DIR
    global YARA_COMMUNITY, YARA_CUSTOM, MODEL_FILE

    ini_path = os.path.join(BASE_DIR, "config.ini")
    if not os.path.isfile(ini_path):
        return

    cfg = configparser.ConfigParser()
    try:
        cfg.read(ini_path, encoding="utf-8")
    except (configparser.Error, OSError):
        # Silently ignore malformed INI – fall through to defaults.
        return

    if not cfg.has_section("paths"):
        return

    def _get(key: str, default: str) -> str:
        raw = cfg.get("paths", key, fallback="").strip()
        if not raw:
            return default
        # Allow relative paths (resolved against BASE_DIR).
        if not os.path.isabs(raw):
            raw = os.path.join(BASE_DIR, raw)
        return os.path.normpath(raw)

    DATA_DIR      = _get("data_dir",      DATA_DIR)
    MODELS_DIR    = _get("models_dir",     MODELS_DIR)
    DB_DIR        = _get("databases_dir",  DB_DIR)
    LOGS_DIR      = _get("logs_dir",       LOGS_DIR)
    EVIDENCE_DIR  = _get("evidence_dir",   EVIDENCE_DIR)
    EXPORTS_DIR   = _get("exports_dir",    EXPORTS_DIR)
    PLAYBOOKS_DIR = _get("playbooks_dir",  PLAYBOOKS_DIR)

    yara_override = _get("yara_rules_dir", YARA_RULES_DIR)
    if yara_override != YARA_RULES_DIR:
        YARA_RULES_DIR = yara_override
        YARA_COMMUNITY = os.path.join(YARA_RULES_DIR, "community")
        YARA_CUSTOM    = os.path.join(YARA_RULES_DIR, "custom")

    # Re-derive model file if models_dir changed.
    MODEL_FILE = os.path.join(MODELS_DIR, "gemma-2-2b-it.gguf")


# Apply overrides at import time so every other module sees the
# final resolved paths when it does ``from config import MODELS_DIR``.
_apply_config_ini()


# ── Directory creation ───────────────────────────────────────────────

# All directories that must exist before the suite can operate.
_REQUIRED_DIRS = [
    MODELS_DIR,
    DB_DIR,
    LOGS_DIR,
    EVIDENCE_DIR,
    EXPORTS_DIR,
    PLAYBOOKS_DIR,
    YARA_COMMUNITY,
    YARA_CUSTOM,
]


def ensure_dirs() -> None:
    """Create the ``data/`` directory tree if it does not already exist.

    Safe to call multiple times.  Uses ``os.makedirs(exist_ok=True)``
    so it never fails on directories that are already present.
    """
    for d in _REQUIRED_DIRS:
        os.makedirs(d, exist_ok=True)


# ── Quick self-test ──────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"BASE_DIR      : {BASE_DIR}")
    print(f"DATA_DIR      : {DATA_DIR}")
    print(f"MODELS_DIR    : {MODELS_DIR}")
    print(f"MODEL_FILE    : {MODEL_FILE}")
    print(f"DB_DIR        : {DB_DIR}")
    print(f"LOGS_DIR      : {LOGS_DIR}")
    print(f"EVIDENCE_DIR  : {EVIDENCE_DIR}")
    print(f"EXPORTS_DIR   : {EXPORTS_DIR}")
    print(f"PLAYBOOKS_DIR : {PLAYBOOKS_DIR}")
    print(f"YARA_COMMUNITY: {YARA_COMMUNITY}")
    print(f"YARA_CUSTOM   : {YARA_CUSTOM}")
    print()

    ini_path = os.path.join(BASE_DIR, "config.ini")
    print(f"config.ini    : {'FOUND' if os.path.isfile(ini_path) else 'not present'}")
    print(f"Frozen        : {getattr(sys, 'frozen', False)}")
    print()

    ensure_dirs()
    print("[OK] All directories created / verified.")
