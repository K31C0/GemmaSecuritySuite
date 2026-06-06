"""
ai_inference.py – Local Gemma inference via llama-cpp-python.

Provides the LocalAI class which wraps a GGUF model and runs
chat-completion inference on a background thread so callers
(e.g. the GUI) never block.
"""

import gc
import os
import threading
import time
from typing import Callable, Optional

from llama_cpp import Llama

import health_monitor
from config import MODEL_FILE

# Portable model path resolved from config.py (relative to toolkit root).
_DEFAULT_MODEL_FILE = MODEL_FILE


class LocalAI:
    """Wrapper around a local Gemma GGUF model.

    Parameters
    ----------
    model_path : str, optional
        Path to the ``.gguf`` model file.  Defaults to the portable
        ``data/models/`` directory resolved by ``config.py``.
    """

    def __init__(self, model_path: str = _DEFAULT_MODEL_FILE) -> None:
        self.model_path = model_path
        self._thread: Optional[threading.Thread] = None
        self._busy = False
        self.llm: Optional[Llama] = None

    # ------------------------------------------------------------------
    #  Public API
    # ------------------------------------------------------------------

    @property
    def is_busy(self) -> bool:
        """``True`` while an inference job is running."""
        return self._busy

    def analyze(
        self,
        text: str,
        system_prompt: str = "",
        on_complete: Optional[Callable[[str], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        on_stream: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Run analysis on *text* in a background thread.

        Parameters
        ----------
        text : str
            The text (log, script, email, etc.) to analyse.
        system_prompt : str, optional
            Instructions for the AI (sent as the ``system`` role message).
        on_complete : callable(str) -> None, optional
            Fired on the **background thread** with the result string
            when inference finishes successfully.
        on_error : callable(str) -> None, optional
            Fired on the **background thread** with an error message
            if something goes wrong.
        """
        if self._busy:
            if on_error:
                on_error("Analysis already in progress.")
            return

        self._busy = True
        self._thread = threading.Thread(
            target=self._worker,
            args=(text, system_prompt, on_complete, on_error, on_stream),
            daemon=True,
            name="InferenceWorker",
        )
        self._thread.start()

    def wait(self, timeout: Optional[float] = None) -> None:
        """Block until the inference thread finishes."""
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    # ------------------------------------------------------------------
    #  Model loading
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        """Initialise the Llama instance from the GGUF file on disk.

        Uses :mod:`hardware_profiler` to auto-detect the host's compute
        capabilities and configure ``llama-cpp-python`` for optimal
        performance (GPU offload, thread count, batch size).

        Raises
        ------
        FileNotFoundError
            If the model file does not exist.
        RuntimeError
            If ``llama-cpp-python`` fails to load the model.
        """
        if not os.path.isfile(self.model_path):
            raise FileNotFoundError(
                f"Model not found: {self.model_path}\n"
                "Please download it first from the Setup screen."
            )

        # Force garbage collection in case we are reloading and the old
        # model hasn't been fully freed yet.
        gc.collect()

        # Auto-detect hardware and derive optimal Llama() parameters.
        from hardware_profiler import detect_hardware, get_llama_kwargs
        self.hw_profile = detect_hardware()
        llama_kwargs = get_llama_kwargs(self.hw_profile)

        try:
            self.llm = Llama(
                model_path=self.model_path,
                **llama_kwargs,
            )
        except Exception as exc:
            raise RuntimeError(
                f"Failed to load model: {exc}"
            ) from exc

    def reload_model(self) -> bool:
        """Force a full unload and reload of the model from disk.
        Useful for recovering from a corrupted state in memory.
        """
        try:
            if self.llm is not None:
                del self.llm
                self.llm = None
            self._load_model()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    #  Internal worker
    # ------------------------------------------------------------------

    def _worker(
        self,
        text: str,
        system_prompt: str,
        on_complete: Optional[Callable[[str], None]],
        on_error: Optional[Callable[[str], None]],
        on_stream: Optional[Callable[[str], None]],
    ) -> None:
        try:
            # ── Lazy-load the model on first call ────────────────────
            if self.llm is None:
                self._load_model()

            user_content = f"{system_prompt}{text}" if system_prompt else text
            messages: list[dict] = [
                {"role": "user", "content": user_content},
            ]

            # ── Run inference with retry logic ───────────────────────
            result = ""
            retries = 1
            
            for attempt in range(retries + 1):
                try:
                    # Run actual inference
                    stream = self.llm.create_chat_completion(
                        messages=messages,
                        max_tokens=1024,
                        temperature=0.7,
                        top_p=0.9,
                        stream=True,
                    )
                    
                    result_chunks = []
                    for chunk in stream:
                        delta = chunk.get("choices", [{}])[0].get("delta", {})
                        if "content" in delta:
                            content = delta["content"]
                            result_chunks.append(content)
                            if on_stream:
                                on_stream(content)
                                
                    result = "".join(result_chunks)
                    break  # Success
                except Exception as exc:
                    if attempt < retries:
                        print(f"Inference error: {exc}. Attempting model reload...")
                        self.reload_model()
                    else:
                        raise RuntimeError(f"Inference failed after {retries} retries: {exc}")

            if not result:
                raise RuntimeError("No response returned from model.")

            # ── Callback on completion ───────────────────────────────
            if on_complete:
                on_complete(result)

        except Exception as exc:
            if on_error:
                on_error(str(exc))
        finally:
            self._busy = False

    # ------------------------------------------------------------------
    #  Health Monitoring
    # ------------------------------------------------------------------

    def health_check(self) -> health_monitor.ModuleHealth:
        """Verify the AI model is present and operational."""
        # 1. Check if model file exists
        if not os.path.isfile(self.model_path):
            return health_monitor.ModuleHealth(
                name="ai_inference",
                status="degraded",
                message="Model file missing (download required)",
                can_recover=False
            )
            
        # 2. Check if thread is stuck
        if self._busy and self._thread and self._thread.is_alive():
            # We can't easily timeout llama_cpp blocking calls in python,
            # but we can detect if it's been running for an abnormal amount of time.
            return health_monitor.ModuleHealth(
                name="ai_inference",
                status="healthy",
                message="Inference in progress..."
            )
            
        # 3. If model is loaded, do a fast tokenizer check to ensure memory isn't fully corrupted
        if self.llm is not None:
            try:
                self.llm.tokenize(b"health check test string")
            except Exception as exc:
                return health_monitor.ModuleHealth(
                    name="ai_inference",
                    status="failed",
                    message=f"Model in memory corrupted: {exc}",
                    can_recover=True,
                    recovery_action="Reloading model"
                )
                
        return health_monitor.ModuleHealth(
            name="ai_inference",
            status="healthy",
            message="Ready"
        )


# ------------------------------------------------------------------
#  Quick self-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    def _done(result: str) -> None:
        print(result)

    def _fail(msg: str) -> None:
        print(f"ERROR: {msg}", file=sys.stderr)

    ai = LocalAI()
    print(f"Model path: {ai.model_path}")
    print(f"Exists:     {os.path.isfile(ai.model_path)}\n")
    print("Starting inference…")
    ai.analyze(
        "What is DNS and why is it important?",
        system_prompt="You are an expert IT support assistant. Keep your answer concise.",
        on_complete=_done,
        on_error=_fail,
    )
    ai.wait()
