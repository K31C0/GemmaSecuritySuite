"""
health_monitor.py – Centralized health registry & auto-recovery watchdog.

Monitors the health of all core modules in the suite. Runs a background
watchdog thread that periodically probes each registered module. If a
module degrades or fails, the watchdog attempts automatic recovery and
updates the global status.
"""

import datetime
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional


@dataclass
class ModuleHealth:
    """Represents the current health state of a single module."""
    name: str
    status: str          # "healthy", "degraded", "failed", "unknown"
    message: str = ""
    last_checked: str = ""
    can_recover: bool = False
    recovery_action: str = ""


class HealthMonitor:
    """Central registry for tracking module health and orchestrating recovery.
    
    Modules register themselves by providing a `health_check` callback and
    an optional `recovery` callback.
    """
    
    def __init__(self, custody_logger=None):
        self._custody = custody_logger
        self._registry: Dict[str, dict] = {}
        self._status: Dict[str, ModuleHealth] = {}
        self._lock = threading.Lock()
        self._watchdog_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.on_status_change: Optional[Callable[[ModuleHealth], None]] = None

    def register(
        self,
        name: str,
        check_fn: Callable[[], ModuleHealth],
        recover_fn: Optional[Callable[[], bool]] = None,
    ) -> None:
        """Register a module for health monitoring.
        
        Parameters
        ----------
        name : str
            Unique identifier for the module (e.g. "ai_inference")
        check_fn : callable
            Function that performs the health check and returns a ModuleHealth
        recover_fn : callable, optional
            Function that attempts to repair the module, returning True on success.
        """
        with self._lock:
            self._registry[name] = {
                "check": check_fn,
                "recover": recover_fn,
            }
            self._status[name] = ModuleHealth(
                name=name, status="unknown", message="Pending first check..."
            )

    def get_status(self, name: str) -> Optional[ModuleHealth]:
        """Get the current health status of a specific module."""
        with self._lock:
            return self._status.get(name)

    def get_all_statuses(self) -> List[ModuleHealth]:
        """Get a list of all current module health states."""
        with self._lock:
            return list(self._status.values())

    def force_check_all(self) -> None:
        """Force an immediate health check of all registered modules."""
        modules = list(self._registry.keys())
        for name in modules:
            self._check_module(name)

    def attempt_recovery(self, name: str) -> bool:
        """Manually trigger a recovery attempt for a degraded/failed module."""
        with self._lock:
            reg = self._registry.get(name)
            if not reg or not reg["recover"]:
                return False
            
            recover_fn = reg["recover"]

        try:
            success = recover_fn()
            
            if self._custody:
                self._custody.record(
                    "health_recovery_attempt", "health_monitor",
                    target=name,
                    detail=f"Success: {success}",
                )
                
            # Force a re-check after recovery attempt
            self._check_module(name)
            return success
        except Exception as exc:
            if self._custody:
                self._custody.record(
                    "health_recovery_error", "health_monitor",
                    target=name,
                    detail=str(exc),
                )
            return False

    def start_watchdog(self, interval_seconds: float = 30.0) -> None:
        """Start the background watchdog thread."""
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            return
            
        self._stop_event.clear()
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            args=(interval_seconds,),
            daemon=True,
            name="HealthWatchdog",
        )
        self._watchdog_thread.start()

    def stop_watchdog(self) -> None:
        """Stop the background watchdog thread."""
        self._stop_event.set()
        if self._watchdog_thread:
            self._watchdog_thread.join(timeout=2.0)

    def _watchdog_loop(self, interval: float) -> None:
        """The main loop for the background watchdog thread."""
        # Initial sleep so we don't slow down app startup
        time.sleep(5.0)
        
        while not self._stop_event.is_set():
            modules = list(self._registry.keys())
            for name in modules:
                if self._stop_event.is_set():
                    break
                self._check_module(name)
                
            # Sleep in chunks to allow prompt shutdown
            for _ in range(int(interval * 10)):
                if self._stop_event.is_set():
                    break
                time.sleep(0.1)

    def _check_module(self, name: str) -> None:
        """Run the health check for a single module and handle state changes."""
        with self._lock:
            reg = self._registry.get(name)
            old_status = self._status.get(name)
            
        if not reg or not old_status:
            return

        check_fn = reg["check"]
        try:
            new_status = check_fn()
            new_status.last_checked = datetime.datetime.now().strftime("%H:%M:%S")
            
            # If the module has a recover_fn, indicate that in the status
            if reg["recover"]:
                new_status.can_recover = True
                
        except Exception as exc:
            # Check function crashed!
            new_status = ModuleHealth(
                name=name,
                status="failed",
                message=f"Health check crashed: {exc}",
                last_checked=datetime.datetime.now().strftime("%H:%M:%S"),
                can_recover=bool(reg["recover"]),
                recovery_action="Check logs",
            )

        # Did the status change in a meaningful way?
        changed = False
        with self._lock:
            # We consider a change "meaningful" if the status code changes,
            # not just if the message updates (which might happen on every poll).
            if old_status.status != new_status.status:
                changed = True
            self._status[name] = new_status

        if changed:
            if self._custody:
                self._custody.record(
                    "health_status_change", "health_monitor",
                    target=name,
                    detail=f"{old_status.status} -> {new_status.status} ({new_status.message})",
                )
                
            if self.on_status_change:
                try:
                    self.on_status_change(new_status)
                except Exception:
                    pass

            # Auto-recovery logic
            if new_status.status in ("failed", "degraded") and new_status.can_recover:
                # Attempt recovery on a separate daemon thread to avoid blocking watchdog
                threading.Thread(
                    target=self.attempt_recovery,
                    args=(name,),
                    daemon=True,
                    name=f"Recover-{name}",
                ).start()


# Global singleton instance (initialized by main.py)
monitor: Optional[HealthMonitor] = None
