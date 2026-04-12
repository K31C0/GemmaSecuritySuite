"""
hash_checker.py – Memory-safe file hashing utility.

Exports a single function:
    compute_hashes(file_path) -> dict[str, str]

Reads files in fixed-size chunks so even multi-GB ISOs won't blow up
memory.  Returns MD5 and SHA-256 digests as hex strings.
"""

import hashlib
import os
from typing import Dict

# 64 KB – large enough for fast throughput, small enough to keep
# memory usage trivial regardless of file size.
_CHUNK_SIZE = 65_536


class HashError(Exception):
    """Raised when hashing fails due to an I/O or path issue."""


def compute_hashes(
    file_path: str,
    *,
    chunk_size: int = _CHUNK_SIZE,
) -> Dict[str, str]:
    """Calculate MD5 and SHA-256 hashes for *file_path*.

    Parameters
    ----------
    file_path : str
        Absolute or relative path to the target file.
    chunk_size : int, optional
        Number of bytes read per iteration (default 64 KB).

    Returns
    -------
    dict[str, str]
        ``{"md5": "<hex>", "sha256": "<hex>", "file": "<path>",
           "size_bytes": <int>}``

    Raises
    ------
    FileNotFoundError
        If *file_path* does not point to an existing file.
    HashError
        If the file cannot be read (permissions, locked handle, etc.).
    """
    # ── Validate path ────────────────────────────────────────────────
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    md5    = hashlib.md5()
    sha256 = hashlib.sha256()

    try:
        file_size = os.path.getsize(file_path)

        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                md5.update(chunk)
                sha256.update(chunk)

    except PermissionError as exc:
        raise HashError(f"Permission denied: {exc}") from exc
    except OSError as exc:
        raise HashError(f"Could not read file: {exc}") from exc

    return {
        "md5":        md5.hexdigest(),
        "sha256":     sha256.hexdigest(),
        "file":       os.path.abspath(file_path),
        "size_bytes": file_size,
    }


# ── Quick self-test ──────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    import sys
    import tempfile

    # Create a tiny temp file to hash.
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
        tmp.write(b"Hello, Security Operations Platform!\n")
        tmp_path = tmp.name

    try:
        result = compute_hashes(tmp_path)
        print(json.dumps(result, indent=2))
    finally:
        os.remove(tmp_path)
