"""
ip_lookup.py – IP Geolocation and ASN Lookup utility.

Provides a single function:
    lookup_ip(ip_address) -> dict

Uses the free ip-api.com service to resolve an IP address to its
geographical location and ISP details without requiring an API key.
"""

import json
import socket
import urllib.request
import urllib.error
from typing import Dict


def lookup_ip(ip_address: str, timeout: float = 5.0) -> Dict[str, str]:
    """Retrieve geolocation and ASN data for an IP address.

    Parameters
    ----------
    ip_address : str
        The IPv4 or IPv6 address to lookup.
    timeout : float
        Network timeout in seconds.

    Returns
    -------
    dict[str, str]
        A clean dictionary with keys: 'Country', 'City', 'ISP', 'AS'.
        If the lookup fails (invalid IP, timeout, etc.), an 'Error'
        key is included with the failure reason.
    """
    url = f"http://ip-api.com/json/{ip_address}"
    
    # ip-api.com blocks default Python urllib User-Agents, so we provide one.
    headers = {"User-Agent": "GemmaSecuritySuite/1.0"}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw_data = response.read().decode("utf-8")
            data = json.loads(raw_data)

        # ip-api responds with 200 OK but sets status="fail" for bad queries
        if data.get("status") == "fail":
            return {"Error": f"API returned: {data.get('message', 'invalid query')}"}

        return {
            "Country": data.get("country", "Unknown"),
            "City": data.get("city", "Unknown"),
            "ISP": data.get("isp", "Unknown"),
            "AS": data.get("as", "Unknown"),
        }

    except urllib.error.HTTPError as exc:
        return {"Error": f"HTTP {exc.code} - {exc.reason}"}
    except urllib.error.URLError as exc:
        return {"Error": f"Connection failed: {exc.reason}"}
    except socket.timeout:
        return {"Error": "Connection timed out."}
    except json.JSONDecodeError:
        return {"Error": "Failed to parse API response."}
    except Exception as exc:
        return {"Error": f"Unexpected error: {exc}"}


# ------------------------------------------------------------------
#  Quick self-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    import textwrap

    def print_result(ip: str):
        print(f"--- Lookup: {ip} ---")
        result = lookup_ip(ip)
        for k, v in result.items():
            print(f"{k:>10}: {v}")
        print()

    # Valid IP lookup
    print_result("8.8.8.8")
    
    # Invalid IP lookup
    print_result("999.999.999.999")
    
    # Internal IP lookup
    print_result("192.168.1.1")
