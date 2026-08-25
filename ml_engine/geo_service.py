import json
import urllib.request
import urllib.error
from email_parser import is_valid_public_ip

PRIMARY_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,mobile,proxy,hosting,query"
SECONDARY_API_URL = "https://ipapi.co/{ip}/json/"
TIMEOUT_SECONDS = 2.0

def get_mock_fallback_geolocation(ip_candidate: str) -> dict:
    """
    Hardcoded Mock Fallback for Offline / Rate-Limited (HTTP 429) testing.
    Guarantees the demo never crashes or returns empty values.
    """
    return {
        "ip": ip_candidate,
        "country": "United States",
        "country_code": "US",
        "region": "Virginia",
        "city": "Ashburn",
        "isp": "Amazon Data Services",
        "asn": "AS16509 Amazon.com, Inc.",
        "latitude": 39.0438,
        "longitude": -77.4874,
        "is_vpn_tor_proxy": False,
        "is_fallback": True
    }


def resolve_ip_geolocation(ip_str: str, is_cloud_webmail: bool = False, cloud_provider: str = "") -> dict:
    """
    Dual-layer Geolocation Resolver with HTTP 429, Timeout Fallback, and Cloud Webmail Annotations.
    """
    ip_str = ip_str.strip() if ip_str else ""

    if not ip_str or not is_valid_public_ip(ip_str):
        return {
            "originating_ip": ip_str or "Unknown",
            "is_public": False,
            "geolocation": {
                "ip": ip_str or "127.0.0.1",
                "country": "Private / Internal Network",
                "country_code": "LOCAL",
                "region": "Internal",
                "city": "Localhost / LAN",
                "latitude": 0.0,
                "longitude": 0.0,
                "isp": "Private Network Node",
                "asn": "N/A",
                "is_vpn_tor_proxy": False,
                "is_fallback": False
            }
        }

    # Attempt 1: Primary ip-api.com
    geo_data = _query_primary_api(ip_str)
    if not geo_data:
        # Attempt 2: Secondary ipapi.co
        geo_data = _query_secondary_api(ip_str)
    
    if not geo_data:
        # Fallback: Hardcoded Mock Fallback
        geo_data = get_mock_fallback_geolocation(ip_str)

    # Cloud Webmail Annotations
    isp_str = geo_data.get("isp", "").lower()
    if is_cloud_webmail or "google" in isp_str or "microsoft" in isp_str:
        provider_name = cloud_provider or ("Google Workspace / Gmail" if "google" in isp_str else "Microsoft 365 / Outlook Web")
        geo_data["is_cloud_webmail"] = True
        geo_data["cloud_provider"] = provider_name
        geo_data["privacy_stripped"] = True
        geo_data["note"] = f"Sender personal IP masked by {provider_name} for user privacy. Coordinates reflect cloud server datacenter."

    return {
        "originating_ip": ip_str,
        "is_public": True,
        "geolocation": geo_data
    }


def _query_primary_api(ip: str) -> dict:
    url = PRIMARY_API_URL.format(ip=ip)
    req = urllib.request.Request(url, headers={"User-Agent": "MailForensix-GeoResolver/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    is_proxy = data.get("proxy", False) or data.get("hosting", False) or data.get("mobile", False)
                    return {
                        "ip": ip,
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", ""),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", ""),
                        "latitude": float(data.get("lat", 0.0)),
                        "longitude": float(data.get("lon", 0.0)),
                        "isp": data.get("isp") or data.get("org") or "Unknown",
                        "asn": data.get("as", "Unknown"),
                        "is_vpn_tor_proxy": bool(is_proxy),
                        "is_fallback": False
                    }
    except urllib.error.HTTPError as e:
        if e.code == 429:
            pass
    except Exception:
        pass
    return None


def _query_secondary_api(ip: str) -> dict:
    url = SECONDARY_API_URL.format(ip=ip)
    req = urllib.request.Request(url, headers={"User-Agent": "MailForensix-GeoResolver/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "ip": ip,
                    "country": data.get("country_name", "Unknown"),
                    "country_code": data.get("country_code", ""),
                    "region": data.get("region", ""),
                    "city": data.get("city", ""),
                    "latitude": float(data.get("latitude", 0.0)),
                    "longitude": float(data.get("longitude", 0.0)),
                    "isp": data.get("org", "Unknown"),
                    "asn": data.get("asn", "Unknown"),
                    "is_vpn_tor_proxy": False,
                    "is_fallback": False
                }
    except Exception:
        pass
    return None
