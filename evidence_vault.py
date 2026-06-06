"""
evidence_vault.py – AES-256-GCM encrypted evidence storage.

Provides secure, tamper-evident storage for malicious payloads,
suspicious files, and other forensic evidence collected during an
incident response engagement.

Encryption details:
    * **Cipher**: AES-256-GCM (authenticated encryption)
    * **Key derivation**: PBKDF2-HMAC-SHA256, 600 000 iterations,
      random 16-byte salt per file
    * **Nonce**: random 12-byte nonce per encryption operation
    * **Integrity**: GCM authentication tag verified on decryption

Files are stored in ``data/evidence/`` with a ``.vault`` extension.
A companion ``vault_manifest.jsonl`` (append-only) tracks every item
stored, including original filename, SHA-256 of the plaintext,
timestamps, and analyst notes.

All operations are logged to the custody chain.
"""

import datetime
import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import config


# ── Constants ────────────────────────────────────────────────────────

_PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 16
_NONCE_BYTES = 12
_KEY_BYTES = 32  # AES-256


@dataclass
class VaultItem:
    """Metadata for one encrypted evidence item.

    Attributes
    ----------
    item_id : str
        Unique identifier (UUID4) for this item.
    original_name : str
        Original filename before encryption.
    stored_at : str
        ISO-8601 UTC timestamp of when the item was stored.
    sha256_plaintext : str
        SHA-256 hash of the original plaintext file.
    size_bytes : int
        Size of the original plaintext file in bytes.
    analyst_notes : str
        Free-text notes from the analyst.
    vault_filename : str
        Name of the encrypted ``.vault`` file on disk.
    """
    item_id:          str = ""
    original_name:    str = ""
    stored_at:        str = ""
    sha256_plaintext: str = ""
    size_bytes:       int = 0
    analyst_notes:    str = ""
    vault_filename:   str = ""


class Vault:
    """Encrypted evidence vault backed by AES-256-GCM.

    Parameters
    ----------
    evidence_dir : str, optional
        Override directory for encrypted files.
        Defaults to ``config.EVIDENCE_DIR``.
    custody_logger : CustodyLogger, optional
        If provided, all operations are recorded to the audit trail.

    Usage::

        vault = Vault()
        vault.store("C:/evidence/malware.exe", "hunter2", "Suspicious DLL")
        for item in vault.list_items():
            print(item.original_name, item.sha256_plaintext)
        vault.extract(item_id, "hunter2", "C:/output/recovered.exe")
    """

    def __init__(
        self,
        evidence_dir: Optional[str] = None,
        custody_logger=None,
    ) -> None:
        self._dir = evidence_dir or config.EVIDENCE_DIR
        self._custody = custody_logger
        self._manifest_path = os.path.join(self._dir, "vault_manifest.jsonl")
        os.makedirs(self._dir, exist_ok=True)

    # ── Public API ───────────────────────────────────────────────────

    def store(
        self,
        file_path: str,
        password: str,
        analyst_notes: str = "",
    ) -> VaultItem:
        """Encrypt and store a file in the vault.

        Parameters
        ----------
        file_path : str
            Path to the plaintext file to encrypt.
        password : str
            Password used to derive the encryption key.
        analyst_notes : str, optional
            Free-text notes about the evidence.

        Returns
        -------
        VaultItem
            Metadata for the newly stored item.

        Raises
        ------
        FileNotFoundError
            If ``file_path`` does not exist.
        ValueError
            If ``password`` is empty.
        """
        if not password:
            raise ValueError("Password must not be empty.")
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Read plaintext.
        with open(file_path, "rb") as f:
            plaintext = f.read()

        # Compute SHA-256 of the original file.
        sha256 = hashlib.sha256(plaintext).hexdigest()

        # Generate unique ID and vault filename.
        item_id = uuid.uuid4().hex[:16]
        vault_name = f"{item_id}.vault"
        vault_path = os.path.join(self._dir, vault_name)

        # Derive key and encrypt.
        salt = os.urandom(_SALT_BYTES)
        nonce = os.urandom(_NONCE_BYTES)
        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Write vault file: [salt (16)] [nonce (12)] [ciphertext+tag (N+16)]
        with open(vault_path, "wb") as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)

        # Build metadata.
        now = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(timespec="seconds")
        item = VaultItem(
            item_id=item_id,
            original_name=os.path.basename(file_path),
            stored_at=now,
            sha256_plaintext=sha256,
            size_bytes=len(plaintext),
            analyst_notes=analyst_notes,
            vault_filename=vault_name,
        )

        # Append to manifest.
        self._append_manifest(item)

        # Custody log.
        if self._custody:
            self._custody.record(
                "evidence_stored", "evidence_vault",
                target=file_path,
                sha256=sha256,
                detail=(f"Stored as {vault_name}, "
                        f"{len(plaintext)} bytes, "
                        f"notes: {analyst_notes or 'none'}"),
            )

        return item

    def list_items(self) -> List[VaultItem]:
        """Return all items in the vault manifest.

        No decryption is performed — this reads only the metadata.
        """
        if not os.path.isfile(self._manifest_path):
            return []

        items: List[VaultItem] = []
        with open(self._manifest_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    items.append(VaultItem(**data))
                except (json.JSONDecodeError, TypeError):
                    continue
        return items

    def extract(
        self,
        item_id: str,
        password: str,
        dest_path: str,
    ) -> str:
        """Decrypt and extract an item from the vault.

        Parameters
        ----------
        item_id : str
            ID of the item to extract.
        password : str
            Password used during storage.
        dest_path : str
            Where to write the decrypted file.

        Returns
        -------
        str
            SHA-256 of the decrypted file (for verification).

        Raises
        ------
        KeyError
            If ``item_id`` is not in the manifest.
        ValueError
            If decryption fails (wrong password or tampered data).
        """
        item = self._find_item(item_id)
        vault_path = os.path.join(self._dir, item.vault_filename)

        if not os.path.isfile(vault_path):
            raise FileNotFoundError(
                f"Vault file missing: {item.vault_filename}")

        # Read vault file.
        with open(vault_path, "rb") as f:
            salt = f.read(_SALT_BYTES)
            nonce = f.read(_NONCE_BYTES)
            ciphertext = f.read()

        # Derive key and decrypt.
        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise ValueError(
                "Decryption failed — wrong password or tampered data."
            ) from exc

        # Verify integrity.
        sha256 = hashlib.sha256(plaintext).hexdigest()
        if sha256 != item.sha256_plaintext:
            raise ValueError(
                f"Integrity check failed! "
                f"Expected {item.sha256_plaintext}, got {sha256}."
            )

        # Write decrypted file.
        os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
        with open(dest_path, "wb") as f:
            f.write(plaintext)

        # Custody log.
        if self._custody:
            self._custody.record(
                "evidence_extracted", "evidence_vault",
                target=dest_path,
                sha256=sha256,
                detail=f"Extracted {item.original_name} ({item.item_id})",
            )

        return sha256

    def verify(self, item_id: str) -> bool:
        """Check that a vault file exists and is not corrupted.

        Does **not** decrypt — only verifies the file exists and
        its size is plausible (salt + nonce + at least 16 bytes of
        GCM tag).

        Parameters
        ----------
        item_id : str
            ID of the item to verify.

        Returns
        -------
        bool
            ``True`` if the vault file exists and passes basic checks.
        """
        try:
            item = self._find_item(item_id)
        except KeyError:
            return False

        vault_path = os.path.join(self._dir, item.vault_filename)
        if not os.path.isfile(vault_path):
            return False

        # Minimum size: salt + nonce + GCM tag (no plaintext = 0 bytes)
        min_size = _SALT_BYTES + _NONCE_BYTES + 16
        actual_size = os.path.getsize(vault_path)
        return actual_size >= min_size

    # ── Internal ─────────────────────────────────────────────────────

    def _find_item(self, item_id: str) -> VaultItem:
        """Look up an item in the manifest by ID."""
        for item in self.list_items():
            if item.item_id == item_id:
                return item
        raise KeyError(f"Item not found in vault: {item_id}")

    def _append_manifest(self, item: VaultItem) -> None:
        """Append a VaultItem to the manifest JSONL file."""
        with open(self._manifest_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(item), ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())


# ── Key derivation ───────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# ── Quick self-test ──────────────────────────────────────────────────
if __name__ == "__main__":
    import shutil
    import tempfile

    test_dir = os.path.join(config.EVIDENCE_DIR, "_selftest")
    vault = Vault(evidence_dir=test_dir)

    # Create a test file.
    test_file = os.path.join(test_dir, "test_evidence.txt")
    os.makedirs(test_dir, exist_ok=True)
    with open(test_file, "w") as f:
        f.write("This is a test evidence file with sensitive data.\n")
        f.write("Mimikatz output: sekurlsa::logonpasswords\n")

    # Store it.
    print("Storing evidence...")
    item = vault.store(test_file, "hunter2", "Test malware sample")
    print(f"  Item ID:  {item.item_id}")
    print(f"  Original: {item.original_name}")
    print(f"  SHA-256:  {item.sha256_plaintext}")
    print(f"  Size:     {item.size_bytes} bytes")
    print(f"  Vault:    {item.vault_filename}")
    print()

    # List items.
    print("Listing vault contents...")
    items = vault.list_items()
    for it in items:
        print(f"  [{it.item_id}] {it.original_name} "
              f"({it.size_bytes}B, {it.stored_at})")
    print()

    # Verify.
    print("Verifying integrity...")
    ok = vault.verify(item.item_id)
    print(f"  Integrity: {'PASS' if ok else 'FAIL'}")
    print()

    # Extract.
    print("Extracting evidence...")
    extract_path = os.path.join(test_dir, "recovered.txt")
    sha = vault.extract(item.item_id, "hunter2", extract_path)
    print(f"  SHA-256:  {sha}")
    with open(extract_path, "r") as f:
        print(f"  Content:  {f.readline().strip()}")
    print()

    # Test wrong password.
    print("Testing wrong password...")
    try:
        vault.extract(item.item_id, "wrong_password",
                      os.path.join(test_dir, "should_fail.txt"))
        print("  ERROR: Should have raised ValueError!")
    except ValueError as e:
        print(f"  Correctly rejected: {e}")
    print()

    # Cleanup.
    shutil.rmtree(test_dir)
    print(f"Cleaned up: {test_dir}")
