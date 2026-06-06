"""
ip_lookup.py – Offline IP Geolocation and ASN Lookup utility.

Provides a single function:
    lookup_ip(ip_address) -> dict

Uses locally-bundled IP2Location LITE databases for 100% offline
IP geolocation and ASN lookups.  No network calls are made.

Required database files (place in data/databases/):
    • IP2LOCATION-LITE-DB11.BIN  – Country, Region, City, Lat, Lon, Timezone
    • IP2LOCATION-LITE-ASN.BIN   – ISP and ASN data

Download these free databases from https://lite.ip2location.com
(requires a free IP2Location LITE account).

Attribution: This product includes IP2Location LITE data available
from https://lite.ip2location.com
"""

import os
from typing import Dict, Optional

from config import DB_DIR

# Database file paths (resolved from the portable config).
_DB_CITY_PATH: str = os.path.join(DB_DIR, "IP2LOCATION-LITE-DB11.BIN")
_DB_ASN_PATH: str = os.path.join(DB_DIR, "IP2LOCATION-LITE-ASN.BIN")

# Lazy-loaded database handles (opened on first lookup).
_city_db: Optional[object] = None
_asn_db: Optional[object] = None

# Attribution notice (required by IP2Location LITE license).
ATTRIBUTION = "IP2Location LITE — https://lite.ip2location.com"


def _load_databases() -> None:
    """Lazy-load the IP2Location BIN databases on first use.

    Populates module-level ``_city_db`` and ``_asn_db`` handles.
    Databases are kept open for the lifetime of the process to
    avoid repeated file I/O on every lookup.
    """
    global _city_db, _asn_db

    try:
        import IP2Location
    except ImportError:
        return  # Package not installed – handled in lookup_ip()

    if _city_db is None and os.path.isfile(_DB_CITY_PATH):
        try:
            _city_db = IP2Location.IP2Location(_DB_CITY_PATH)
        except Exception:
            _city_db = None

    if _asn_db is None and os.path.isfile(_DB_ASN_PATH):
        try:
            _asn_db = IP2Location.IP2Location(_DB_ASN_PATH)
        except Exception:
            _asn_db = None


def lookup_ip(ip_address: str, timeout: float = 5.0) -> Dict[str, str]:
    """Retrieve geolocation and ASN data for an IP address.

    Performs a fully offline lookup against locally-bundled
    IP2Location LITE databases.  The *timeout* parameter is
    retained for API compatibility but is unused (no network).

    Parameters
    ----------
    ip_address : str
        The IPv4 or IPv6 address to lookup.
    timeout : float
        Unused – kept for backward compatibility with callers.

    Returns
    -------
    dict[str, str]
        A clean dictionary with keys: 'Country', 'City', 'ISP', 'AS'.
        If the lookup fails (missing database, invalid IP, etc.), an
        'Error' key is included with the failure reason.
    """
    # ── Pre-flight checks ────────────────────────────────────────────
    try:
        import IP2Location  # noqa: F811
    except ImportError:
        return {"Error": "IP2Location package not installed. Run: pip install IP2Location"}

    if not os.path.isfile(_DB_CITY_PATH) and not os.path.isfile(_DB_ASN_PATH):
        return {
            "Error": (
                "No IP2Location databases found.\n"
                f"Place BIN files in: {DB_DIR}\n\n"
                "Download free databases from:\n"
                "https://lite.ip2location.com\n\n"
                "Required files:\n"
                "  - IP2LOCATION-LITE-DB11.BIN (geolocation)\n"
                "  - IP2LOCATION-LITE-ASN.BIN  (ISP/ASN)"
            )
        }

    # ── Load databases (lazy, one-time) ──────────────────────────────
    _load_databases()

    country = "N/A"
    city = "N/A"
    isp = "N/A"
    asn = "N/A"

    # ── City / Geolocation lookup ────────────────────────────────────
    if _city_db is not None:
        try:
            rec = _city_db.get_all(ip_address)
            if rec is not None:
                country = _safe_str(rec.country_long)
                city = _safe_str(rec.city)
        except Exception as exc:
            return {"Error": f"Geolocation lookup failed: {exc}"}
    else:
        country = "Database not loaded"
        city = "Database not loaded"

    # ── ASN / ISP lookup ─────────────────────────────────────────────
    if _asn_db is not None:
        try:
            rec = _asn_db.get_all(ip_address)
            if rec is not None:
                asn_raw = _safe_str(rec.asn)
                as_name = _safe_str(rec.as_name)
                isp = as_name if as_name != "N/A" else asn_raw
                asn = asn_raw if asn_raw != "N/A" else "Unknown"
        except Exception as exc:
            isp = f"ASN lookup failed: {exc}"
            asn = "Error"

    return {
        "Country": country,
        "City": city,
        "ISP": isp,
        "AS": asn,
    }


def _safe_str(value: object) -> str:
    """Convert a database field value to a clean string.

    IP2Location returns various sentinel values for missing data
    (e.g. '-', 'This parameter is unavailable...').  This helper
    normalises them all to 'N/A'.
    """
    if value is None:
        return "N/A"
    s = str(value).strip()
    if not s or s == "-" or s.startswith("This parameter"):
        return "N/A"
    return s


# ------------------------------------------------------------------
#  Quick self-test
# ------------------------------------------------------------------
if __name__ == "__main__":

    def print_result(ip: str) -> None:
        print(f"--- Lookup: {ip} ---")
        result = lookup_ip(ip)
        for k, v in result.items():
            print(f"{k:>10}: {v}")
        print()

    print(f"City DB : {_DB_CITY_PATH}")
    print(f"  Exists: {os.path.isfile(_DB_CITY_PATH)}")
    print(f"ASN DB  : {_DB_ASN_PATH}")
    print(f"  Exists: {os.path.isfile(_DB_ASN_PATH)}")
    print(f"Attribution: {ATTRIBUTION}")
    print()

    # Valid IP lookup
    print_result("8.8.8.8")

    # Invalid IP lookup
    print_result("999.999.999.999")

    # Internal IP lookup
    print_result("192.168.1.1")
