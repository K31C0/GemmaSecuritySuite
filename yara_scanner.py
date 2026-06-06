"""
yara_scanner.py – YARA rule engine for malware/IOC signature scanning.

Compiles all ``.yar`` / ``.yara`` files from two directories:
    * ``data/yara_rules/community/``  — bundled community rules
    * ``data/yara_rules/custom/``     — analyst's own rules

Provides both file-based and in-memory scanning so the Script Auditor
can pre-scan pasted scripts before sending them to the LLM.

If ``yara-python`` is not installed, the engine degrades gracefully:
all scans return empty results and a warning is logged.
"""

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import config

# ── Graceful degradation if yara-python is not installed ─────────────
try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False


@dataclass
class YaraMatch:
    """One YARA rule match against a target.

    Attributes
    ----------
    rule_name : str
        Name of the matched rule (e.g. ``"Mimikatz_Memory"``).
    tags : list[str]
        Tags attached to the rule (e.g. ``["malware", "credential"]``).
    meta : dict[str, Any]
        Rule metadata (author, description, severity, etc.).
    strings_matched : list[str]
        The matched string identifiers (e.g. ``["$s1", "$s2"]``).
    namespace : str
        Which rule file the match came from (``"community"`` or
        ``"custom"``).
    """
    rule_name:       str            = ""
    tags:            List[str]      = field(default_factory=list)
    meta:            Dict[str, Any] = field(default_factory=dict)
    strings_matched: List[str]      = field(default_factory=list)
    namespace:       str            = ""


class YaraEngine:
    """Compiles and runs YARA rules from the toolkit's rule directories.

    Parameters
    ----------
    community_dir : str, optional
        Path to community rules directory.
    custom_dir : str, optional
        Path to analyst's custom rules directory.

    Usage::

        engine = YaraEngine()
        matches = engine.scan_buffer(script_bytes)
        for m in matches:
            print(f"Matched: {m.rule_name} [{', '.join(m.tags)}]")
    """

    def __init__(
        self,
        community_dir: Optional[str] = None,
        custom_dir: Optional[str] = None,
    ) -> None:
        self._community_dir = community_dir or config.YARA_COMMUNITY
        self._custom_dir = custom_dir or config.YARA_CUSTOM
        self._rules: Optional[Any] = None  # yara.Rules object
        self._errors: List[str] = []
        self._rule_count = 0
        self._available = _YARA_AVAILABLE

        if self._available:
            self._compile_rules()

    @property
    def available(self) -> bool:
        """``True`` if yara-python is installed and rules compiled."""
        return self._available and self._rules is not None

    @property
    def rule_count(self) -> int:
        """Number of compiled rules."""
        return self._rule_count

    @property
    def errors(self) -> List[str]:
        """Any errors encountered during rule compilation."""
        return list(self._errors)

    # ── Scanning ─────────────────────────────────────────────────────

    def scan_file(self, file_path: str) -> List[YaraMatch]:
        """Scan a file on disk against all compiled rules.

        Parameters
        ----------
        file_path : str
            Path to the file to scan.

        Returns
        -------
        list[YaraMatch]
            All matching rules.  Empty if no match or engine unavailable.
        """
        if not self.available:
            return []
        try:
            raw = self._rules.match(filepath=file_path)
            return self._convert_matches(raw)
        except Exception:
            return []

    def scan_buffer(self, data: bytes) -> List[YaraMatch]:
        """Scan in-memory bytes against all compiled rules.

        Parameters
        ----------
        data : bytes
            Raw content to scan (e.g. a pasted script encoded to bytes).

        Returns
        -------
        list[YaraMatch]
            All matching rules.  Empty if no match or engine unavailable.
        """
        if not self.available:
            return []
        try:
            raw = self._rules.match(data=data)
            return self._convert_matches(raw)
        except Exception:
            return []

    # ── Formatting ───────────────────────────────────────────────────

    @staticmethod
    def format_matches(matches: List[YaraMatch]) -> str:
        """Format a list of YARA matches into a human-readable string.

        Suitable for display in the GUI or prepending to an LLM prompt.
        """
        if not matches:
            return "YARA Pre-Scan: No matches found."

        lines = [f"YARA Pre-Scan: {len(matches)} rule(s) matched!"]
        lines.append("-" * 50)
        for m in matches:
            tags_str = ", ".join(m.tags) if m.tags else "none"
            lines.append(f"  Rule: {m.rule_name}")
            lines.append(f"  Tags: {tags_str}")
            if m.meta.get("description"):
                lines.append(f"  Desc: {m.meta['description']}")
            if m.meta.get("severity"):
                lines.append(f"  Severity: {m.meta['severity']}")
            if m.meta.get("author"):
                lines.append(f"  Author: {m.meta['author']}")
            if m.strings_matched:
                lines.append(f"  Strings: {', '.join(m.strings_matched[:10])}")
            lines.append(f"  Source: {m.namespace}")
            lines.append("")
        return "\n".join(lines)

    # ── Internal ─────────────────────────────────────────────────────

    def _compile_rules(self) -> None:
        """Discover and compile all .yar/.yara files from both dirs."""
        filepaths: Dict[str, str] = {}  # namespace -> filepath

        for label, dirpath in [
            ("community", self._community_dir),
            ("custom", self._custom_dir),
        ]:
            if not os.path.isdir(dirpath):
                continue
            for root, _dirs, files in os.walk(dirpath):
                for fname in files:
                    if fname.endswith((".yar", ".yara")):
                        full = os.path.join(root, fname)
                        ns = f"{label}/{fname}"
                        filepaths[ns] = full

        if not filepaths:
            self._errors.append(
                "No YARA rule files found. "
                "Place .yar files in data/yara_rules/community/ "
                "or data/yara_rules/custom/"
            )
            return

        try:
            self._rules = yara.compile(filepaths=filepaths)
            # Count rules by doing a dummy scan on empty bytes
            dummy = self._rules.match(data=b"")
            # We can't easily count rules without scanning, but we can
            # count filepaths as a proxy
            self._rule_count = len(filepaths)
        except yara.SyntaxError as exc:
            self._errors.append(f"YARA syntax error: {exc}")
            # Try compiling rules one at a time to find the bad one
            self._compile_rules_individually(filepaths)
        except Exception as exc:
            self._errors.append(f"YARA compile error: {exc}")

    def _compile_rules_individually(
        self, filepaths: Dict[str, str]
    ) -> None:
        """Fallback: compile each rule file individually, skip broken ones."""
        good: Dict[str, str] = {}
        for ns, fp in filepaths.items():
            try:
                yara.compile(filepaths={ns: fp})
                good[ns] = fp
            except Exception as exc:
                self._errors.append(f"Skipped {ns}: {exc}")

        if good:
            try:
                self._rules = yara.compile(filepaths=good)
                self._rule_count = len(good)
            except Exception as exc:
                self._errors.append(f"Final compile failed: {exc}")

    @staticmethod
    def _convert_matches(raw_matches) -> List[YaraMatch]:
        """Convert yara-python match objects to our dataclass."""
        results = []
        for m in raw_matches:
            strings = []
            if hasattr(m, "strings"):
                for s in m.strings:
                    if hasattr(s, "identifier"):
                        strings.append(s.identifier)
                    else:
                        strings.append(str(s))

            results.append(YaraMatch(
                rule_name=m.rule,
                tags=list(m.tags) if m.tags else [],
                meta=dict(m.meta) if m.meta else {},
                strings_matched=strings,
                namespace=m.namespace or "",
            ))
        return results


# ── Quick self-test ──────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"yara-python available: {_YARA_AVAILABLE}")
    if _YARA_AVAILABLE:
        print(f"YARA version: {yara.YARA_VERSION}")

    print(f"\nCommunity dir: {config.YARA_COMMUNITY}")
    print(f"  Exists: {os.path.isdir(config.YARA_COMMUNITY)}")
    print(f"Custom dir: {config.YARA_CUSTOM}")
    print(f"  Exists: {os.path.isdir(config.YARA_CUSTOM)}")

    engine = YaraEngine()
    print(f"\nEngine available: {engine.available}")
    print(f"Rule files: {engine.rule_count}")
    if engine.errors:
        print("Errors:")
        for e in engine.errors:
            print(f"  - {e}")

    # Test with EICAR signature if engine is available
    if engine.available:
        # EICAR test pattern (safe, used for AV testing)
        eicar = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
                 b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        matches = engine.scan_buffer(eicar)
        print(f"\nEICAR scan: {len(matches)} match(es)")
        if matches:
            print(engine.format_matches(matches))
    else:
        print("\nSkipping scan test (no rules loaded).")

    # Test with a harmless script
    test_script = b"Get-Process | Select-Object Name, CPU"
    matches = engine.scan_buffer(test_script)
    print(f"\nHarmless script scan: {len(matches)} match(es)")
