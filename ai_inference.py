"""
ai_inference.py – Local Gemma inference via llama-cpp-python.

Provides the LocalAI class which wraps a GGUF model and runs
chat-completion inference on a background thread so callers
(e.g. the GUI) never block.
"""

import os
import threading
from typing import Callable, Optional

from llama_cpp import Llama

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
            args=(text, system_prompt, on_complete, on_error),
            daemon=True,
            name="LocalAI-Inference",
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

    # ------------------------------------------------------------------
    #  Internal worker
    # ------------------------------------------------------------------

    def _worker(
        self,
        text: str,
        system_prompt: str,
        on_complete: Optional[Callable[[str], None]],
        on_error: Optional[Callable[[str], None]],
    ) -> None:
        try:
            # ── Lazy-load the model on first call ────────────────────
            if self.llm is None:
                self._load_model()

            # ── Build the chat messages ──────────────────────────────
            # Gemma does not support the "system" role, so we prepend
            # the system instructions into the user message.
            user_content = f"{system_prompt}{text}" if system_prompt else text
            messages: list[dict] = [
                {"role": "user", "content": user_content},
            ]

            # ── Run inference ────────────────────────────────────────
            response = self.llm.create_chat_completion(
                messages=messages,
                max_tokens=1024,
                temperature=0.7,
                top_p=0.9,
            )

            # ── Extract the reply text ───────────────────────────────
            result = (
                response.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            ).strip()

            if not result:
                result = "(Model returned an empty response.)"

            if on_complete:
                on_complete(result)

        except Exception as exc:
            if on_error:
                on_error(str(exc))
        finally:
            self._busy = False


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
