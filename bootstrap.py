"""
bootstrap.py – Preflight check & crash-safe launcher for GemmaSecuritySuite.

This module runs **before** main.py and ensures the environment is sane:

    1. Python version   ≥ 3.10
    2. Directory tree    data/* exists and is writable
    3. Core dependencies importable (auto-installs if missing)
    4. Optional deps     warns but continues
    5. Model file        warns if missing (downloaded on first launch)
    6. Databases         warns if missing (IP lookup will degrade)
    7. Disk space        ≥ 500MB free on the toolkit drive
    8. Write permission  verified via temp file in data/

On success, it hands off to main.main() directly (no subprocess overhead).
On failure, it writes details to data/logs/bootstrap.log and exits with code 1.

Usage::

    python bootstrap.py        # called by Launch.bat
    Launch.bat                 # double-click to run everything

This file should NEVER be imported by other modules in the suite.
"""

import datetime
import importlib
import os
import shutil
import subprocess
import sys
import tempfile
import traceback

# Resolve all paths relative to this file (USB root / project root).
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_LOG_DIR = os.path.join(_SCRIPT_DIR, "data", "logs")
_LOG_PATH = os.path.join(_LOG_DIR, "bootstrap.log")

# ── Logging ──────────────────────────────────────────────────────────

_log_lines: list[str] = []


def _log(msg: str, level: str = "INFO") -> None:
    """Print and buffer a log message."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(f"  {line}")
    _log_lines.append(line)


def _flush_log() -> None:
    """Write buffered log lines to disk."""
    try:
        os.makedirs(_LOG_DIR, exist_ok=True)
        with open(_LOG_PATH, "w", encoding="utf-8") as f:
            f.write(f"GemmaSecuritySuite Bootstrap Log\n")
            f.write(f"Date: {datetime.datetime.now().isoformat()}\n")
            f.write(f"Python: {sys.version}\n")
            f.write(f"CWD: {os.getcwd()}\n")
            f.write("=" * 60 + "\n\n")
            for line in _log_lines:
                f.write(line + "\n")
    except Exception:
        pass  # If we can't even write a log, nothing else will work anyway.


# ── Preflight Checks ────────────────────────────────────────────────

def _check_python_version() -> bool:
    """Check 1: Python version >= 3.10."""
    ver = sys.version_info
    if ver >= (3, 10):
        _log(f"Python {ver.major}.{ver.minor}.{ver.micro} — OK")
        return True
    else:
        _log(
            f"Python {ver.major}.{ver.minor}.{ver.micro} is too old. "
            f"GemmaSecuritySuite requires Python 3.10 or later.",
            "FAIL",
        )
        return False


def _check_directories() -> bool:
    """Check 2: data/ directory tree exists and is writable."""
    # Import config to get the full directory list.
    # This also triggers config.ini resolution.
    try:
        sys.path.insert(0, _SCRIPT_DIR)
        import config
        config.ensure_dirs()
        _log(f"Directory tree verified: {config.DATA_DIR}")
        return True
    except Exception as exc:
        _log(f"Failed to create directory tree: {exc}", "FAIL")
        return False


def _check_core_dependencies() -> bool:
    """Check 3: All core packages are importable. Auto-install if missing."""
    core_packages = [
        ("customtkinter", "customtkinter"),
        ("llama-cpp-python", "llama_cpp"),
        ("psutil", "psutil"),
        ("IP2Location", "IP2Location"),
        ("cryptography", "cryptography"),
        ("dpkt", "dpkt"),
    ]

    missing = []
    for pip_name, import_name in core_packages:
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(pip_name)

    if not missing:
        _log(f"All {len(core_packages)} core dependencies present — OK")
        return True

    _log(f"Missing packages: {', '.join(missing)} — attempting install...")

    req_file = os.path.join(_SCRIPT_DIR, "requirements.txt")
    if not os.path.isfile(req_file):
        _log("requirements.txt not found — cannot auto-install", "FAIL")
        return False

    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "pip", "install",
                "-r", req_file,
                "--quiet",
                "--disable-pip-version-check",
            ],
            capture_output=True,
            text=True,
            timeout=300,  # 5-minute timeout for slow USB drives
        )

        if result.returncode == 0:
            _log("Packages installed successfully.")
        else:
            _log(f"pip install warnings/errors:\n{result.stderr}", "WARN")

        # Verify again after install
        still_missing = []
        for pip_name, import_name in core_packages:
            try:
                importlib.import_module(import_name)
            except ImportError:
                still_missing.append(pip_name)

        if still_missing:
            _log(
                f"Still missing after install: {', '.join(still_missing)}. "
                f"The app will launch but some features may not work.",
                "WARN",
            )
            # Don't fail — let the app handle missing deps gracefully
        else:
            _log("All packages verified after install — OK")

        return True

    except subprocess.TimeoutExpired:
        _log("pip install timed out after 5 minutes", "WARN")
        return True  # Don't block — let user try anyway
    except Exception as exc:
        _log(f"pip install failed: {exc}", "WARN")
        return True  # Don't block


def _check_optional_dependencies() -> None:
    """Check 4: Optional packages — warn but never fail."""
    optional = [
        ("yara-python", "yara", "YARA rule scanning"),
        ("weasyprint", "weasyprint", "PDF report generation"),
    ]

    for pip_name, import_name, feature in optional:
        try:
            importlib.import_module(import_name)
            _log(f"Optional: {pip_name} present ({feature}) — OK")
        except ImportError:
            _log(
                f"Optional: {pip_name} not installed — "
                f"{feature} will be unavailable",
                "WARN",
            )


def _check_model_file() -> None:
    """Check 5: AI model file present — warn if missing."""
    import config
    if os.path.isfile(config.MODEL_FILE):
        size_mb = os.path.getsize(config.MODEL_FILE) / (1024 * 1024)
        _log(f"Model file found: {os.path.basename(config.MODEL_FILE)} "
             f"({size_mb:.0f} MB) — OK")
    else:
        _log(
            f"Model file not found at: {config.MODEL_FILE}\n"
            f"         The model will be downloaded on first launch.",
            "WARN",
        )


def _check_databases() -> None:
    """Check 6: IP2Location databases present — warn if missing."""
    import config
    db_files = [
        "IP2LOCATION-LITE-DB11.BIN",
        "IP2LOCATION-LITE-ASN.BIN",
    ]
    for db in db_files:
        path = os.path.join(config.DB_DIR, db)
        if os.path.isfile(path):
            _log(f"Database found: {db} — OK")
        else:
            _log(
                f"Database not found: {db} — IP lookup will show 'N/A'",
                "WARN",
            )


def _check_disk_space() -> bool:
    """Check 7: At least 500MB free on the toolkit drive."""
    try:
        usage = shutil.disk_usage(_SCRIPT_DIR)
        free_mb = usage.free / (1024 * 1024)
        free_gb = free_mb / 1024

        if free_mb < 100:
            _log(
                f"CRITICAL: Only {free_mb:.0f} MB free on drive. "
                f"The suite needs at least 100 MB to operate.",
                "FAIL",
            )
            return False
        elif free_mb < 500:
            _log(
                f"Low disk space: {free_gb:.1f} GB free. "
                f"Some operations may fail.",
                "WARN",
            )
        else:
            _log(f"Disk space: {free_gb:.1f} GB free — OK")

        return True
    except Exception as exc:
        _log(f"Could not check disk space: {exc}", "WARN")
        return True  # Don't block on this


def _check_write_permission() -> bool:
    """Check 8: Verify data/ directory is writable (USB not read-only)."""
    import config
    test_file = os.path.join(config.DATA_DIR, ".write_test")
    try:
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        _log("Write permission verified — OK")
        return True
    except (OSError, PermissionError) as exc:
        _log(
            f"Cannot write to data directory: {exc}\n"
            f"         Is the USB drive read-only or full?",
            "FAIL",
        )
        return False


# ── Main Preflight ───────────────────────────────────────────────────

def run_preflight() -> bool:
    """Run all preflight checks. Returns True if the app can launch."""
    _log("=" * 50)
    _log("GemmaSecuritySuite Preflight")
    _log("=" * 50)
    _log("")

    # Critical checks — fail if any of these fail
    if not _check_python_version():
        return False

    if not _check_directories():
        return False

    if not _check_write_permission():
        return False

    if not _check_disk_space():
        return False

    # Core deps — attempt auto-install but don't block
    _check_core_dependencies()

    # Info checks — warn only
    _check_optional_dependencies()
    _check_model_file()
    _check_databases()

    _log("")
    _log("Preflight complete. Launching application...")
    _log("=" * 50)

    return True


# ── Entry Point ──────────────────────────────────────────────────────

def main() -> None:
    """Run preflight then hand off to the application."""
    success = False
    try:
        success = run_preflight()
    except Exception as exc:
        _log(f"Preflight crashed: {exc}", "FAIL")
        _log(traceback.format_exc(), "FAIL")
        _flush_log()
        sys.exit(1)

    _flush_log()

    if not success:
        _log("Preflight failed. Cannot launch.", "FAIL")
        _flush_log()
        sys.exit(1)

    # Hand off to the real application — no subprocess, direct call.
    try:
        # Ensure we're in the right directory for relative imports
        os.chdir(_SCRIPT_DIR)
        if _SCRIPT_DIR not in sys.path:
            sys.path.insert(0, _SCRIPT_DIR)

        from main import main as app_main
        app_main()

    except SystemExit:
        raise  # Allow normal exit
    except Exception as exc:
        _log(f"Application crashed: {exc}", "FAIL")
        _log(traceback.format_exc(), "FAIL")
        _flush_log()

        # Write crash report
        crash_path = os.path.join(
            _LOG_DIR,
            f"crash_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        )
        try:
            with open(crash_path, "w", encoding="utf-8") as f:
                f.write(f"GemmaSecuritySuite Crash Report\n")
                f.write(f"Time: {datetime.datetime.now().isoformat()}\n")
                f.write(f"Python: {sys.version}\n\n")
                f.write(traceback.format_exc())
            print(f"\n  Crash report saved to: {crash_path}")
        except Exception:
            pass

        sys.exit(1)


if __name__ == "__main__":
    main()
