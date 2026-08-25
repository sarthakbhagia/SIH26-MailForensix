import email
from email import policy
from email.parser import BytesParser, Parser
import re
import ipaddress
from urllib.parse import urlparse
from bs4 import BeautifulSoup

TIMEZONE_MAP = {
    "+0530": "UTC +05:30 (IST - India / South Asia)",
    "+0500": "UTC +05:00 (PKT / West Asia)",
    "+0545": "UTC +05:45 (NPT - Nepal)",
    "+0600": "UTC +06:00 (BST - Bangladesh)",
    "+0800": "UTC +08:00 (CST / SGT - China / Singapore)",
    "+0900": "UTC +09:00 (JST / KST - Japan / Korea)",
    "+0000": "UTC +00:00 (GMT / London)",
    "+0100": "UTC +01:00 (CET - W. Europe)",
    "+0200": "UTC +02:00 (EET / CEST - E. Europe)",
    "-0400": "UTC -04:00 (EDT - US/Canada East)",
    "-0500": "UTC -05:00 (EST / CDMX)",
    "-0600": "UTC -06:00 (CST - US Central)",
    "-0700": "UTC -07:00 (MST / PDT - US West)",
    "-0800": "UTC -08:00 (PST - US Pacific)",
}

def extract_timezone_info(date_header: str) -> dict:
    """
    Extracts local clock timezone offset from email Date: header.
    Example: 'Tue, 25 Aug 2026 21:40:00 +0530' -> '+0530' -> 'UTC +05:30 (IST - India / South Asia)'
    """
    if not date_header:
        return {"raw_date": "", "offset": "", "inferred_timezone": "Unknown"}

    match = re.search(r'([+-]\d{4})\b', date_header)
    if match:
        offset = match.group(1)
        inferred = TIMEZONE_MAP.get(offset, f"UTC {offset[:3]}:{offset[3:]}")
        return {
            "raw_date": date_header,
            "offset": offset,
            "inferred_timezone": inferred
        }

    if "GMT" in date_header or "UTC" in date_header or "Z" in date_header:
        return {
            "raw_date": date_header,
            "offset": "+0000",
            "inferred_timezone": "UTC +00:00 (GMT)"
        }

    return {"raw_date": date_header, "offset": "", "inferred_timezone": "Unknown"}


def is_valid_public_ip(ip_str: str) -> bool:
    """
    Strict IP validator using Python's built-in ipaddress module.
    Explicitly filters out private, loopback, link-local, and reserved IPs.
    """
    if not ip_str:
        return False

    clean_ip = ip_str.strip().strip("[]()")
    if clean_ip in ("0.0.0.0", "255.255.255.255"):
        return False

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
            return False
        return True
    except Exception:
        return False


def detect_cloud_webmail(from_header: str, received_chain: list, auth_results: str, message_id: str) -> tuple:
    """
    Detects if an email was sent via a major Cloud Webmail provider (Gmail, Outlook, Yahoo)
    where originating client home IPs are stripped for user privacy.
    Returns (is_cloud_webmail: bool, cloud_provider: str).
    """
    combined = f"{from_header} {' '.join(received_chain)} {auth_results} {message_id}".lower()

    if "gmail.com" in combined or "mail-sor-" in combined or "google.com" in combined:
        return True, "Google Workspace / Gmail"
    elif "outlook.com" in combined or "protection.outlook.com" in combined or "microsoft.com" in combined or "live.com" in combined:
        return True, "Microsoft 365 / Outlook Web"
    elif "yahoo.com" in combined or "mail.yahoo.com" in combined:
        return True, "Yahoo Webmail"

    return False, ""


def extract_originating_ip(received_chain: list, auth_results: str = "", received_spf: str = "") -> tuple:
    """
    Trusted Edge Mail Server Verification Strategy:
    1. Check topmost Authentication-Results or Received-SPF headers for client-ip= or SPF designator IP.
    2. If missing/invalid, parse Received: headers from TOP to BOTTOM (gateway downward).
    """
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ipv6_pattern = re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}')

    auth_combined = f"{auth_results} {received_spf}"
    if auth_combined.strip():
        client_ip_match = re.search(r'client-ip=([0-9a-fA-F\.:]+)', auth_combined, re.IGNORECASE)
        if client_ip_match:
            candidate = client_ip_match.group(1).strip()
            if is_valid_public_ip(candidate):
                return candidate, True

        designates_match = re.search(r'designates\s+([0-9a-fA-F\.:]+)', auth_combined, re.IGNORECASE)
        if designates_match:
            candidate = designates_match.group(1).strip()
            if is_valid_public_ip(candidate):
                return candidate, True

        all_auth_candidates = ipv4_pattern.findall(auth_combined) + ipv6_pattern.findall(auth_combined)
        for candidate in all_auth_candidates:
            if is_valid_public_ip(candidate):
                return candidate, True

    all_found_ips = []
    if received_chain:
        for hop in received_chain:
            hop_str = str(hop)
            candidates = ipv4_pattern.findall(hop_str) + ipv6_pattern.findall(hop_str)

            for ip_str in candidates:
                all_found_ips.append(ip_str)
                if is_valid_public_ip(ip_str):
                    return ip_str, True

    if all_found_ips:
        return all_found_ips[0], False

    return "Unknown", False


def parse_eml(eml_content):
    """
    Parses raw .eml content (bytes or string) and extracts key email metadata,
    headers, bodies, embedded URLs, timezone offset, and cloud webmail indicators.
    """
    if isinstance(eml_content, bytes):
        msg = BytesParser(policy=policy.default).parsebytes(eml_content)
    elif isinstance(eml_content, str):
        msg = Parser(policy=policy.default).parsestr(eml_content)
    else:
        raise ValueError("Invalid EML content format. Expected bytes or str.")

    # Core headers
    from_header = str(msg.get("From", ""))
    to_header = str(msg.get("To", ""))
    return_path = str(msg.get("Return-Path", ""))
    subject = str(msg.get("Subject", ""))
    message_id = str(msg.get("Message-ID", ""))
    date_header = str(msg.get("Date", ""))

    # Authentication headers
    auth_results = str(msg.get("Authentication-Results", ""))
    dkim_sig = str(msg.get("DKIM-Signature", ""))
    received_spf = str(msg.get("Received-SPF", ""))

    # Received header chain (hops)
    received_headers = msg.get_all("Received") or []
    received_chain = [str(hop).strip() for hop in received_headers]

    # Timezone offset analysis
    tz_info = extract_timezone_info(date_header)

    # Cloud Webmail provider detection
    is_cloud, cloud_provider = detect_cloud_webmail(from_header, received_chain, auth_results, message_id)

    # Originating Public IP extraction
    originating_ip, is_public = extract_originating_ip(received_chain, auth_results=auth_results, received_spf=received_spf)

    # Extract body text and html
    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition:
                continue

            try:
                payload = part.get_content()
                if isinstance(payload, str):
                    if content_type == "text/plain" and not body_text:
                        body_text = payload
                    elif content_type == "text/html" and not body_html:
                        body_html = payload
            except Exception:
                pass
    else:
        payload = msg.get_content()
        if isinstance(payload, str):
            if msg.get_content_type() == "text/html":
                body_html = payload
            else:
                body_text = payload

    if not body_text and body_html:
        soup = BeautifulSoup(body_html, "html.parser")
        body_text = soup.get_text(separator=" ", strip=True)

    # Extract URLs from HTML body and Text body
    raw_urls = set()
    if body_html:
        soup = BeautifulSoup(body_html, "html.parser")
        for tag in soup.find_all("a", href=True):
            raw_urls.add(tag["href"])

    url_pattern = re.compile(r'https?://[^\s<>"\'`()]+', re.IGNORECASE)
    for match in url_pattern.findall(body_text + " " + body_html):
        raw_urls.add(match)

    urls = sorted(list(raw_urls))

    extracted_domains = []
    for u in urls:
        try:
            parsed = urlparse(u)
            domain = parsed.netloc.split(":")[0].lower()
            if domain and domain not in extracted_domains:
                extracted_domains.append(domain)
        except Exception:
            pass

    return {
        "from": from_header,
        "to": to_header,
        "return_path": return_path,
        "subject": subject,
        "message_id": message_id,
        "date_header": date_header,
        "auth_results": auth_results,
        "dkim_signature": dkim_sig,
        "received_spf": received_spf,
        "received_chain": received_chain,
        "hop_count": len(received_chain),
        "originating_ip_candidate": originating_ip,
        "is_public": is_public,
        "is_cloud_webmail": is_cloud,
        "cloud_provider": cloud_provider,
        "privacy_stripped": is_cloud,
        "timezone_info": tz_info,
        "body_text": body_text,
        "body_html": body_html,
        "urls": urls,
        "domains": extracted_domains
    }
