"""
downloader.py – Threaded file downloader with progress callbacks.

Provides the ModelManager class which checks for local file existence
and downloads missing files on a background thread, reporting progress
through a user-supplied callback.
"""

import os
import threading
import urllib.request
from typing import Callable, Optional

# Real Gemma 2B IT GGUF model via Hugging Face.
DEFAULT_DOWNLOAD_URL = "https://huggingface.co/bartowski/gemma-2-2b-it-GGUF/resolve/main/gemma-2-2b-it-Q4_K_M.gguf?download=true"

# Default destination inside the user's AppData folder.
DEFAULT_DEST_DIR = os.path.join(os.environ.get("APPDATA", "."), "GemmaSecuritySuite", "models")
DEFAULT_DEST_FILE = os.path.join(DEFAULT_DEST_DIR, "gemma-2-2b-it.gguf")


class ModelManager:
    """Manages the lifecycle of a downloadable model file.

    Parameters
    ----------
    file_path : str, optional
        Absolute path where the file should reside.
        Defaults to ``%APPDATA%/LogPlatform/models/100MB.bin``.
    url : str, optional
        Remote URL to fetch when the file is missing.
        Defaults to a public 100 MB test file.
    """

    def __init__(
        self,
        file_path: str = DEFAULT_DEST_FILE,
        url: str = DEFAULT_DOWNLOAD_URL,
    ) -> None:
        self.file_path = file_path
        self.url = url

        # Internal state -------------------------------------------------------
        self._thread: Optional[threading.Thread] = None
        self._cancel_event = threading.Event()
        self._lock = threading.Lock()
        self._progress: float = 0.0
        self._downloading: bool = False
        self._error: Optional[str] = None

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def file_exists(self) -> bool:
        """Return ``True`` if the target file already exists on disk."""
        return os.path.isfile(self.file_path)

    @property
    def progress(self) -> float:
        """Current download progress (0.0 – 100.0), thread-safe read."""
        with self._lock:
            return self._progress

    @property
    def is_downloading(self) -> bool:
        """``True`` while a download is in progress."""
        with self._lock:
            return self._downloading

    @property
    def error(self) -> Optional[str]:
        """Error message from the last download attempt, or ``None``."""
        with self._lock:
            return self._error

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def ensure_file(
        self,
        progress_callback: Optional[Callable[[float], None]] = None,
        done_callback: Optional[Callable[[bool, Optional[str]], None]] = None,
    ) -> None:
        """Check for the file and download it in the background if missing.

        If the file already exists the *done_callback* fires immediately
        with ``(True, None)``.  Otherwise a background thread is spawned.

        Parameters
        ----------
        progress_callback : callable(float) -> None, optional
            Invoked repeatedly with a value between ``0.0`` and ``100.0``
            representing download completion.
        done_callback : callable(bool, str | None) -> None, optional
            Invoked once when the download finishes.
            ``(True, None)``  → success
            ``(False, msg)``  → failure with an error message
        """
        if self.file_exists():
            if progress_callback:
                progress_callback(100.0)
            if done_callback:
                done_callback(True, None)
            return

        with self._lock:
            if self._downloading:
                return  # Already in progress – silently ignore duplicate calls.
            self._downloading = True
            self._progress = 0.0
            self._error = None

        self._cancel_event.clear()
        self._thread = threading.Thread(
            target=self._download_worker,
            args=(progress_callback, done_callback),
            daemon=True,
            name="ModelManager-Download",
        )
        self._thread.start()

    def cancel(self) -> None:
        """Request cancellation of the current download (best-effort)."""
        self._cancel_event.set()

    def wait(self, timeout: Optional[float] = None) -> None:
        """Block until the download thread finishes (or *timeout* expires)."""
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    # ------------------------------------------------------------------
    # Internal worker
    # ------------------------------------------------------------------

    def _download_worker(
        self,
        progress_cb: Optional[Callable[[float], None]],
        done_cb: Optional[Callable[[bool, Optional[str]], None]],
    ) -> None:
        """Background worker – streams the remote file to disk."""
        try:
            # Ensure the destination directory tree exists.
            os.makedirs(os.path.dirname(self.file_path), exist_ok=True)

            # Use a .part suffix while downloading to avoid partial-file confusion.
            part_path = self.file_path + ".part"

            req = urllib.request.Request(self.url, headers={"User-Agent": "ModelManager/1.0"})
            with urllib.request.urlopen(req) as response:
                total = int(response.headers.get("Content-Length", 0))
                chunk_size = 1024 * 256  # 256 KB chunks
                downloaded = 0

                with open(part_path, "wb") as f:
                    while True:
                        if self._cancel_event.is_set():
                            self._cleanup_partial(part_path)
                            self._finish(False, "Download cancelled by user.", done_cb)
                            return

                        chunk = response.read(chunk_size)
                        if not chunk:
                            break

                        f.write(chunk)
                        downloaded += len(chunk)

                        if total > 0:
                            pct = min(downloaded / total * 100, 100.0)
                        else:
                            pct = 0.0  # Unknown size – stay at 0 until done.

                        with self._lock:
                            self._progress = pct

                        if progress_cb:
                            progress_cb(pct)

            # Atomically promote the partial file.
            if os.path.exists(self.file_path):
                os.remove(self.file_path)
            os.rename(part_path, self.file_path)

            with self._lock:
                self._progress = 100.0
            if progress_cb:
                progress_cb(100.0)

            self._finish(True, None, done_cb)

        except Exception as exc:
            self._cleanup_partial(self.file_path + ".part")
            self._finish(False, str(exc), done_cb)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _finish(
        self,
        success: bool,
        error_msg: Optional[str],
        done_cb: Optional[Callable[[bool, Optional[str]], None]],
    ) -> None:
        with self._lock:
            self._downloading = False
            self._error = error_msg
        if done_cb:
            done_cb(success, error_msg)

    @staticmethod
    def _cleanup_partial(path: str) -> None:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


# ----------------------------------------------------------------------
# Quick self-test / demo
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import time

    def on_progress(pct: float) -> None:
        bar_len = 40
        filled = int(bar_len * pct / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        print(f"\r  [{bar}] {pct:6.2f}%", end="", flush=True)

    def on_done(success: bool, error: Optional[str]) -> None:
        print()  # newline after progress bar
        if success:
            print("  ✔ Download complete.")
        else:
            print(f"  ✘ Download failed: {error}")

    mgr = ModelManager()
    print(f"Target : {mgr.file_path}")
    print(f"Exists : {mgr.file_exists()}")
    print(f"URL    : {mgr.url}\n")

    mgr.ensure_file(progress_callback=on_progress, done_callback=on_done)

    # Keep the main thread alive while the daemon thread works.
    while mgr.is_downloading:
        time.sleep(0.25)
