import re
from urllib.parse import urlparse

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def extract_domain(email_or_header: str) -> str:
    """Extracts domain from an email address or header string like 'Name <user@domain.com>'."""
    match = re.search(r'[\w\.-]+@([\w\.-]+)', email_or_header)
    if match:
        return match.group(1).lower()
    return ""


def check_header_anomalies(parsed_headers: dict) -> dict:
    """
    Evaluates SPF/DKIM/DMARC status, From vs Return-Path mismatch, and routing hops.
    Returns Header Risk Score (0-100) and alert details.
    """
    alerts = []
    penalty = 0

    # 1. SPF / DKIM status check
    auth_res = parsed_headers.get("auth_results", "").lower()
    rec_spf = parsed_headers.get("received_spf", "").lower()
    dkim_sig = parsed_headers.get("dkim_signature", "")

    spf_pass = "spf=pass" in auth_res or "pass" in rec_spf
    dkim_pass = "dkim=pass" in auth_res or len(dkim_sig) > 0

    if not spf_pass:
        penalty += 30
        alerts.append("SPF authentication missing or failed")
    if not dkim_pass:
        penalty += 25
        alerts.append("DKIM signature missing or failed")

    # 2. From domain vs Return-Path domain check (Spoofing)
    from_header = parsed_headers.get("from", "")
    return_path = parsed_headers.get("return_path", "")
    
    from_domain = extract_domain(from_header)
    return_domain = extract_domain(return_path)

    if from_domain and return_domain and from_domain != return_domain:
        penalty += 35
        alerts.append(f"Domain mismatch / spoofing detected: From ({from_domain}) != Return-Path ({return_domain})")
    elif not return_domain and from_domain:
        penalty += 15
        alerts.append("Return-Path domain missing while From header is present")

    # 3. Hop count anomaly check (> 6 hops)
    hop_count = parsed_headers.get("hop_count", 0)
    if hop_count > 6:
        penalty += 15
        alerts.append(f"Excessive email routing hops detected: {hop_count} hops (>6 threshold)")

    # Score bounded 0 - 100
    header_score = min(100.0, float(penalty))

    return {
        "header_score": header_score,
        "alerts": alerts,
        "from_domain": from_domain,
        "return_domain": return_domain,
        "hop_count": hop_count
    }


def check_url_anomalies(urls: list) -> dict:
    """
    Checks for IP address URLs and typosquatting/lookalike domains against target corporate brands.
    Returns URL Risk Score (0-100) and flagged suspicious links.
    """
    alerts = []
    suspicious_urls = []
    penalty = 0
    target_brands = ["paypal", "microsoft", "google", "apple", "bankofamerica", "wellsfargo", "amazon"]

    ip_pattern = re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?', re.IGNORECASE)

    for url in urls:
        parsed = urlparse(url)
        netloc = parsed.netloc.split(":")[0].lower()

        # 1. IP address in URL check
        if ip_pattern.match(url) or re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', netloc):
            penalty += 40
            alert_msg = f"Suspicious IP-based URL detected: {url}"
            alerts.append(alert_msg)
            suspicious_urls.append({"url": url, "reason": "Raw IP Address"})
            continue

        # 2. Typosquatting / Levenshtein distance check against target corporate brands
        domain_parts = netloc.split(".")
        main_domain = domain_parts[-2] if len(domain_parts) >= 2 else netloc

        for brand in target_brands:
            # Check if it's lookalike (e.g. distance 1 or 2, but not identical)
            dist = levenshtein_distance(main_domain, brand)
            if 0 < dist <= 2 and main_domain != brand:
                penalty += 35
                alert_msg = f"Typosquatting/lookalike domain detected: '{netloc}' mimics brand '{brand}' (distance: {dist})"
                alerts.append(alert_msg)
                suspicious_urls.append({"url": url, "reason": f"Lookalike domain mimicking {brand}"})
                break

    url_score = min(100.0, float(penalty))

    return {
        "url_score": url_score,
        "alerts": alerts,
        "suspicious_urls": suspicious_urls
    }
