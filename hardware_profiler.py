"""
hardware_profiler.py – Auto-detect host hardware for optimal LLM configuration.

Probes the target machine at startup and returns a :class:`HardwareProfile`
that describes available compute resources.  This profile is then translated
into optimal ``llama-cpp-python`` parameters by :func:`get_llama_kwargs`.

Detection order:
    1. NVIDIA GPU via ``nvidia-smi`` (CUDA offloading)
    2. CPU core count via ``os.cpu_count()``
    3. Available system RAM via ``psutil``

The profiler never installs drivers or modifies system state — it only
reads what is already available on the host.
"""

import os
import platform
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class HardwareProfile:
    """Snapshot of the host machine's compute capabilities.

    Attributes
    ----------
    cpu_cores : int
        Logical CPU core count (includes hyper-threads).
    ram_total_mb : int
        Total system RAM in megabytes.
    ram_available_mb : int
        Currently available (free) RAM in megabytes.
    cuda_available : bool
        ``True`` if an NVIDIA GPU with ``nvidia-smi`` was detected.
    gpu_name : str
        Human-readable GPU model name, or ``"N/A"``.
    vram_total_mb : int
        Total GPU VRAM in megabytes, or ``0`` if no GPU.
    vram_free_mb : int
        Free GPU VRAM in megabytes, or ``0`` if no GPU.
    driver_version : str
        NVIDIA driver version string, or ``"N/A"``.
    os_name : str
        Operating system identifier (e.g. ``"Windows-10"``).
    """
    cpu_cores:        int  = 0
    ram_total_mb:     int  = 0
    ram_available_mb: int  = 0
    cuda_available:   bool = False
    gpu_name:         str  = "N/A"
    vram_total_mb:    int  = 0
    vram_free_mb:     int  = 0
    driver_version:   str  = "N/A"
    os_name:          str  = "Unknown"

    @property
    def summary(self) -> str:
        """One-line human-readable summary for the setup screen."""
        if self.cuda_available:
            return (
                f"CUDA: {self.gpu_name} "
                f"({self.vram_free_mb:,}MB free VRAM) | "
                f"CPU: {self.cpu_cores} cores | "
                f"RAM: {self.ram_available_mb:,}MB free"
            )
        return (
            f"CPU-only: {self.cpu_cores} cores | "
            f"RAM: {self.ram_available_mb:,}MB free"
        )


# ── Detection ────────────────────────────────────────────────────────

def detect_hardware() -> HardwareProfile:
    """Probe the host and return a populated :class:`HardwareProfile`.

    This function is safe to call on any machine — it catches all
    exceptions internally and returns a best-effort profile.
    """
    profile = HardwareProfile()

    # ── OS ────────────────────────────────────────────────────────
    profile.os_name = f"{platform.system()}-{platform.release()}"

    # ── CPU ───────────────────────────────────────────────────────
    profile.cpu_cores = os.cpu_count() or 1

    # ── RAM (via psutil) ─────────────────────────────────────────
    try:
        import psutil
        mem = psutil.virtual_memory()
        profile.ram_total_mb = mem.total // (1024 * 1024)
        profile.ram_available_mb = mem.available // (1024 * 1024)
    except ImportError:
        # psutil not installed — estimate from os (Windows only).
        profile.ram_total_mb = 0
        profile.ram_available_mb = 0

    # ── GPU (NVIDIA via nvidia-smi) ──────────────────────────────
    _detect_nvidia_gpu(profile)

    return profile


def _detect_nvidia_gpu(profile: HardwareProfile) -> None:
    """Attempt to detect an NVIDIA GPU via ``nvidia-smi``.

    Updates *profile* in place.  Silently returns on any failure
    (no GPU, no driver, nvidia-smi not on PATH, etc.).
    """
    try:
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total,memory.free,driver_version",
                "--format=csv,noheader,nounits",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            creationflags=(
                subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
                if platform.system() == "Windows" else 0
            ),
        )

        if result.returncode != 0:
            return

        line = result.stdout.decode("utf-8", errors="replace").strip()
        if not line:
            return

        # Parse CSV: "NVIDIA GeForce RTX 4070, 16376, 13360, 591.86"
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 4:
            return

        profile.cuda_available = True
        profile.gpu_name       = parts[0]
        profile.vram_total_mb  = int(float(parts[1]))
        profile.vram_free_mb   = int(float(parts[2]))
        profile.driver_version = parts[3]

    except FileNotFoundError:
        pass  # nvidia-smi not installed
    except subprocess.TimeoutExpired:
        pass  # nvidia-smi hung
    except (ValueError, IndexError, OSError):
        pass  # Unexpected output format


# ── llama-cpp-python configuration ───────────────────────────────────

def get_llama_kwargs(profile: HardwareProfile) -> Dict[str, Any]:
    """Translate a hardware profile into optimal ``Llama()`` parameters.

    Parameters
    ----------
    profile : HardwareProfile
        Result of :func:`detect_hardware`.

    Returns
    -------
    dict[str, Any]
        Keyword arguments suitable for ``Llama(**kwargs)``.
    """
    kwargs: Dict[str, Any] = {
        "n_ctx":     8192,
        "verbose":   False,
    }

    # ── CPU thread count ─────────────────────────────────────────
    # Use physical-ish cores (half of logical for hyper-threaded CPUs),
    # but leave at least 2 cores free for the OS and GUI thread.
    if profile.cpu_cores >= 8:
        kwargs["n_threads"] = max(profile.cpu_cores // 2, 4)
    elif profile.cpu_cores >= 4:
        kwargs["n_threads"] = profile.cpu_cores - 1
    else:
        kwargs["n_threads"] = max(profile.cpu_cores, 1)

    # ── GPU offloading ───────────────────────────────────────────
    if profile.cuda_available and profile.vram_free_mb > 0:
        # Gemma 2 2B Q4_K_M needs ~1.6GB VRAM for full offload.
        # Each layer is roughly 60-80MB for a 2B model (~26 layers).
        if profile.vram_free_mb >= 2048:
            # Plenty of VRAM — offload all layers
            kwargs["n_gpu_layers"] = -1  # -1 = all layers
        elif profile.vram_free_mb >= 1024:
            # Partial offload — roughly half the layers
            kwargs["n_gpu_layers"] = 15
        elif profile.vram_free_mb >= 512:
            # Minimal offload — just a few layers
            kwargs["n_gpu_layers"] = 5
        else:
            # Not enough VRAM — stay on CPU
            kwargs["n_gpu_layers"] = 0

        # Larger batch size benefits GPU inference
        if kwargs.get("n_gpu_layers", 0) != 0:
            kwargs["n_batch"] = 512
    else:
        kwargs["n_gpu_layers"] = 0
        kwargs["n_batch"] = 256

    return kwargs


# ── Quick self-test ──────────────────────────────────────────────────
if __name__ == "__main__":
    profile = detect_hardware()
    print("=== Hardware Profile ===")
    print(f"  OS           : {profile.os_name}")
    print(f"  CPU cores    : {profile.cpu_cores}")
    print(f"  RAM total    : {profile.ram_total_mb:,} MB")
    print(f"  RAM available: {profile.ram_available_mb:,} MB")
    print(f"  CUDA         : {profile.cuda_available}")
    print(f"  GPU          : {profile.gpu_name}")
    print(f"  VRAM total   : {profile.vram_total_mb:,} MB")
    print(f"  VRAM free    : {profile.vram_free_mb:,} MB")
    print(f"  Driver       : {profile.driver_version}")
    print()
    print(f"  Summary: {profile.summary}")
    print()

    kwargs = get_llama_kwargs(profile)
    print("=== Llama() kwargs ===")
    for k, v in kwargs.items():
        print(f"  {k:15}: {v}")
