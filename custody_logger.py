"""
custody_logger.py – Immutable chain-of-custody audit trail.

Provides a thread-safe, append-only JSONL logger that records every
significant action taken by the analyst or the toolkit.  This is the
forensic backbone of the suite — every module calls
``CustodyLogger.record()`` so there is a tamper-evident log of what
was done, when, by whom, and to what.

Design constraints (forensic integrity):
    * Append-only — the log file is never truncated or overwritten.
    * Self-integrity — on ``close()``, a SHA-256 hash of the entire
      log file is written to a ``.sha256`` sidecar file.
    * Thread-safe — all writes are serialised behind a
      ``threading.Lock``.
    * One session = one file — each launch creates a new file with a
      timestamped name.

Output format (one JSON object per line)::

    {"ts": "2026-06-05T20:10:45.123Z", "seq": 1, "action": "app_start",
     "module": "main", "target": null, "detail": "GemmaSecuritySuite v1",
     "sha256": null, "hostname": "IR-LAPTOP", "analyst": "SYSTEM"}

Files are written to ``config.LOGS_DIR`` (``data/logs/`` by default).
"""

import datetime
import hashlib
import json
import os
import platform
import threading
import time
from typing import Optional

import config
import health_monitor


class CustodyLogger:
    """Append-only JSONL logger for forensic chain-of-custody records.

    Usage::

        logger = CustodyLogger()
        logger.record("file_hashed", "hash_checker", "/evidence/malware.exe",
                       sha256="abc123...", detail="MD5 also computed")
        ...
        logger.close()  # writes .sha256 sidecar

    Parameters
    ----------
    logs_dir : str, optional
        Override directory for log files.  Defaults to ``config.LOGS_DIR``.
    """

    def __init__(self, logs_dir: Optional[str] = None) -> None:
        self._lock = threading.Lock()
        self._seq = 0
        self._closed = False
        self._hostname = platform.node() or "UNKNOWN"
        self._max_size_bytes = 50 * 1024 * 1024  # 50 MB rotation
        self._write_errors = 0

        self._dir = logs_dir or config.LOGS_DIR
        os.makedirs(self._dir, exist_ok=True)
        self._open_new_log()

    def _open_new_log(self) -> None:
        """Internal: Open a new log file with timestamp."""
        ts = datetime.datetime.now(datetime.timezone.utc)
        stamp = ts.strftime("%Y%m%d_%H%M%S")
        self._path = os.path.join(self._dir, f"custody_{stamp}.jsonl")
        self._sha_path = self._path + ".sha256"
        self._fh = open(self._path, "a", encoding="utf-8")
        
        # If we already have a sequence number, log that we rotated
        if self._seq > 0:
            self._write_entry({
                "ts": ts.isoformat(timespec="milliseconds"),
                "seq": self._seq + 1,
                "action": "log_rotated",
                "module": "custody_logger",
                "target": self._path,
                "detail": "Log rotated due to size limits",
                "sha256": None,
                "hostname": self._hostname,
                "analyst": "SYSTEM",
            })
            self._seq += 1

    # ── Public API ───────────────────────────────────────────────────

    def record(
        self,
        action: str,
        module: str,
        target: Optional[str] = None,
        *,
        sha256: Optional[str] = None,
        detail: Optional[str] = None,
        analyst: str = "SYSTEM",
    ) -> None:
        """Append a single custody record to the log.

        Parameters
        ----------
        action : str
            What happened (e.g. ``"file_hashed"``, ``"yara_scan"``,
            ``"evidence_stored"``).
        module : str
            Which module triggered this (e.g. ``"hash_checker"``).
        target : str, optional
            Path, IP, filename, or identifier of the object acted upon.
        sha256 : str, optional
            SHA-256 hash of the target, when applicable.
        detail : str, optional
            Free-text note (AI summary, error message, etc.).
        analyst : str
            Analyst identifier.  Defaults to ``"SYSTEM"`` for
            automated actions.
        """
        if self._closed:
            return

        now = datetime.datetime.now(datetime.timezone.utc)

        with self._lock:
            self._seq += 1
            entry = {
                "ts": now.isoformat(timespec="milliseconds"),
                "seq": self._seq,
                "action": action,
                "module": module,
                "target": target,
                "detail": detail,
                "sha256": sha256,
                "hostname": self._hostname,
                "analyst": analyst,
            }
            self._write_entry(entry)

    def _write_entry(self, entry: dict) -> None:
        """Internal: Serialize and write a single entry with retries."""
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        
        for attempt in range(3):
            try:
                self._fh.write(line)
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._write_errors = 0
                
                # Check for rotation
                if self._fh.tell() > self._max_size_bytes:
                    self._rotate_log()
                    
                return
            except OSError:
                time.sleep(0.1)
                
        # If we failed 3 times, we're in trouble. Try to recover by making a new file.
        self._write_errors += 1
        try:
            self._rotate_log()
            self._fh.write(line)
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._write_errors = 0
        except Exception:
            pass # We failed completely, health_monitor will pick it up
            
    def _rotate_log(self) -> None:
        """Internal: Finalize current log and start a new one."""
        old_path = self._path
        self.close(lock=False)
        self._closed = False
        self._open_new_log()

    @property
    def path(self) -> str:
        """Absolute path to the active log file."""
        return self._path

    @property
    def entry_count(self) -> int:
        """Number of entries written so far this session."""
        return self._seq

    def close(self, lock: bool = True) -> None:
        """Finalise the log: flush, compute SHA-256, write sidecar.

        Safe to call multiple times — subsequent calls are no-ops.
        """
        if self._closed:
            return

        if lock:
            self._lock.acquire()
            
        try:
            self._closed = True
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()
            except OSError:
                pass

            # Compute SHA-256 of the entire log file for tamper detection.
            sha = hashlib.sha256()
            with open(self._path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    sha.update(chunk)

            digest = sha.hexdigest()
            try:
                with open(self._sha_path, "w", encoding="utf-8") as f:
                    f.write(f"{digest}  {os.path.basename(self._path)}\n")
            except OSError:
                pass
                
        finally:
            if lock:
                self._lock.release()

    def __del__(self) -> None:
        """Best-effort cleanup if the caller forgets ``close()``."""
        try:
            self.close()
        except Exception:
            pass

    # ── Convenience helpers ──────────────────────────────────────────

    def log_app_start(self, version: str = "1.0") -> None:
        """Record application launch."""
        self.record(
            "app_start", "main",
            detail=f"GemmaSecuritySuite v{version}",
        )

    def log_app_stop(self) -> None:
        """Record graceful application shutdown."""
        self.record("app_stop", "main", detail=f"{self._seq} events logged")

    @staticmethod
    def verify_log(log_path: str) -> bool:
        """Check a completed log file against its ``.sha256`` sidecar.

        Parameters
        ----------
        log_path : str
            Path to the ``.jsonl`` file.

        Returns
        -------
        bool
            ``True`` if the hash matches, ``False`` if tampered or
            sidecar is missing.
        """
        sha_path = log_path + ".sha256"
        if not os.path.isfile(sha_path):
            return False

        # Read expected hash from sidecar.
        with open(sha_path, "r", encoding="utf-8") as f:
            expected = f.read().strip().split()[0]

        # Compute actual hash.
        sha = hashlib.sha256()
        with open(log_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha.update(chunk)

        return sha.hexdigest() == expected

    # ── Health Monitoring ──────────────────────────────────────────────

    def health_check(self) -> health_monitor.ModuleHealth:
        """Check if logger is functioning correctly."""
        with self._lock:
            if self._closed:
                return health_monitor.ModuleHealth(
                    name="custody_logger", status="healthy", message="Log closed cleanly"
                )
                
            if self._write_errors > 0:
                return health_monitor.ModuleHealth(
                    name="custody_logger",
                    status="degraded",
                    message=f"Experiencing write errors ({self._write_errors})",
                    can_recover=True,
                    recovery_action="Rotate to new file"
                )
                
            # Verify file is still writable by attempting to flush it
            try:
                self._fh.flush()
            except OSError as exc:
                return health_monitor.ModuleHealth(
                    name="custody_logger",
                    status="failed",
                    message=f"Log file unwritable: {exc}",
                    can_recover=True,
                    recovery_action="Rotate to new file"
                )
                
            return health_monitor.ModuleHealth(
                name="custody_logger",
                status="healthy",
                message=f"Logging normally ({self._seq} entries, {self._fh.tell() // 1024} KB)"
            )
            
    def recover(self) -> bool:
        """Attempt to recover from a bad state by rotating the log."""
        with self._lock:
            try:
                self._rotate_log()
                self._write_errors = 0
                return True
            except Exception:
                return False


# ── Quick self-test ──────────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile

    test_dir = os.path.join(config.LOGS_DIR, "_selftest")
    logger = CustodyLogger(logs_dir=test_dir)

    print(f"Log file: {logger.path}")
    print()

    # Simulate a session
    logger.log_app_start("1.0-test")
    logger.record("file_hashed", "hash_checker", "C:\\evidence\\malware.exe",
                   sha256="abc123def456", detail="MD5: 789xyz")
    logger.record("ip_lookup", "ip_lookup", "8.8.8.8",
                   detail="Country: United States, City: Mountain View")
    logger.record("yara_scan", "yara_scanner", "suspicious_script.ps1",
                   detail="Matched: Mimikatz_Memory_Rule")
    logger.record("ai_analysis", "ai_inference", "script_audit",
                   detail="AI flagged credential harvesting pattern")
    logger.log_app_stop()
    logger.close()

    # Display the log contents
    print("=== Log Contents ===")
    with open(logger.path, "r", encoding="utf-8") as f:
        for line in f:
            entry = json.loads(line)
            print(f"  [{entry['seq']:03d}] {entry['ts']}  "
                  f"{entry['action']:20s}  {entry['module']:15s}  "
                  f"{entry.get('target') or ''}")

    # Verify integrity
    print()
    sha_path = logger.path + ".sha256"
    with open(sha_path, "r", encoding="utf-8") as f:
        print(f"SHA-256 sidecar: {f.read().strip()}")

    valid = CustodyLogger.verify_log(logger.path)
    print(f"Integrity check: {'PASS' if valid else 'FAIL'}")

    # Simulate tampering
    with open(logger.path, "a", encoding="utf-8") as f:
        f.write('{"tampered": true}\n')
    tampered = CustodyLogger.verify_log(logger.path)
    print(f"After tampering: {'PASS' if tampered else 'FAIL (expected)'}")

    # Cleanup
    import shutil
    shutil.rmtree(test_dir)
    print(f"\nCleaned up: {test_dir}")
