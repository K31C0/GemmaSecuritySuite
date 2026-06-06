"""
session_manager.py – Auto-save and state restoration.

Ensures that if the application crashes or is closed abruptly,
the analyst does not lose their current work (chat history, input fields).
Saves state periodically and on graceful exit to `data/session_state.json`.
"""

import json
import os
import threading
import time
from typing import Any, Callable, Dict, Optional

import config


class SessionManager:
    """Manages periodic auto-saving and restoration of UI state.
    
    Usage::
    
        session = SessionManager(
            get_state_fn=app.get_ui_state,
            restore_state_fn=app.restore_ui_state
        )
        session.load()
        session.start_autosave(interval=60.0)
    """

    def __init__(
        self,
        get_state_fn: Callable[[], Dict[str, Any]],
        restore_state_fn: Callable[[Dict[str, Any]], None],
        custody_logger=None,
    ) -> None:
        self._get_state = get_state_fn
        self._restore_state = restore_state_fn
        self._custody = custody_logger
        self._state_file = os.path.join(config.DATA_DIR, "session_state.json")
        self._stop_event = threading.Event()
        self._autosave_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def load(self) -> bool:
        """Attempt to load previous session state from disk.
        
        Returns True if state was restored successfully.
        """
        if not os.path.isfile(self._state_file):
            return False

        with self._lock:
            try:
                with open(self._state_file, "r", encoding="utf-8") as f:
                    state = json.load(f)
                    
                if not isinstance(state, dict):
                    return False
                    
                self._restore_state(state)
                
                if self._custody:
                    self._custody.record(
                        "session_restored", "session_manager",
                        detail="Restored UI state from previous session"
                    )
                return True
            except Exception as exc:
                if self._custody:
                    self._custody.record(
                        "session_restore_error", "session_manager",
                        detail=str(exc)
                    )
                return False

    def save(self) -> None:
        """Force an immediate save of the current state."""
        with self._lock:
            try:
                state = self._get_state()
                
                # Write to a temporary file first, then atomic rename
                # to prevent corruption if we crash during write
                temp_file = self._state_file + ".tmp"
                with open(temp_file, "w", encoding="utf-8") as f:
                    json.dump(state, f, ensure_ascii=False, indent=2)
                    
                os.replace(temp_file, self._state_file)
            except Exception as exc:
                if self._custody:
                    self._custody.record(
                        "session_save_error", "session_manager",
                        detail=str(exc)
                    )

    def start_autosave(self, interval: float = 60.0) -> None:
        """Start background thread to periodically save state."""
        if self._autosave_thread and self._autosave_thread.is_alive():
            return
            
        self._stop_event.clear()
        self._autosave_thread = threading.Thread(
            target=self._autosave_loop,
            args=(interval,),
            daemon=True,
            name="SessionAutosave",
        )
        self._autosave_thread.start()

    def stop_autosave(self) -> None:
        """Stop background autosave thread and do one final save."""
        self._stop_event.set()
        if self._autosave_thread:
            self._autosave_thread.join(timeout=2.0)
            
        # Final save on clean exit
        self.save()

    def clear(self) -> None:
        """Delete the saved session state from disk."""
        with self._lock:
            try:
                if os.path.isfile(self._state_file):
                    os.remove(self._state_file)
            except OSError:
                pass

    def _autosave_loop(self, interval: float) -> None:
        while not self._stop_event.is_set():
            for _ in range(int(interval * 10)):
                if self._stop_event.is_set():
                    break
                time.sleep(0.1)
                
            if not self._stop_event.is_set():
                self.save()
