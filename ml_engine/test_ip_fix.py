import json
from email_parser import parse_eml, extract_originating_ip, is_valid_public_ip
from geo_service import resolve_ip_geolocation

def run_ip_fix_tests():
    print("==========================================================")
    print("   RUNNING TRUSTED EDGE IP EXTRACTION & GEO FIX TESTS     ")
    print("==========================================================\n")

    # --------------------------------------------------
    # CASE A: Authentication-Results with client-ip
    # --------------------------------------------------
    print("--- CASE A: Trusted Edge Verification via Authentication-Results ---")
    raw_eml_a = """From: "Test User" <user@test.com>
To: recipient@example.com
Subject: Test Email Case A
Authentication-Results: mx.google.com; dkim=pass header.i=@test.com; spf=pass (google.com: domain of user@test.com designates 185.220.101.5 as permitted sender) client-ip=185.220.101.5;
Received-SPF: pass (google.com: domain of user@test.com designates 185.220.101.5 as permitted sender)
Received: from mail.test.com (mail.test.com [10.0.0.1]) by mx.google.com with ESMTPS id xyz789

This is a test body.
"""
    parsed_a = parse_eml(raw_eml_a)
    ip_a = parsed_a["originating_ip_candidate"]
    is_pub_a = parsed_a["is_public"]
    geo_a = resolve_ip_geolocation(ip_a)

    print(f"Case A Extracted IP : {ip_a}")
    print(f"Case A Is Public    : {is_pub_a}")
    print("Case A Resolved Geolocation:")
    print(json.dumps(geo_a, indent=2))

    assert ip_a == "185.220.101.5", f"Case A failed: Expected '185.220.101.5', got '{ip_a}'"
    assert is_pub_a is True, "Case A failed: Expected is_public == True"
    print("-> CASE A PASSED: Successfully extracted 185.220.101.5 from Authentication-Results!\n")

    # --------------------------------------------------
    # CASE B: Top-to-Bottom Received chain with private hops before public IP
    # --------------------------------------------------
    print("--- CASE B: Top-to-Bottom Received Chain (Private Hops -> Public IP) ---")
    raw_eml_b = """From: "Sender" <sender@domain.com>
To: recipient@example.com
Subject: Test Email Case B
Received: from internal-gateway.local (internal-gateway.local [10.0.0.1]) by recipient.server with ESMTP
Received: from edge-proxy.local (edge-proxy.local [192.168.1.1]) by internal-gateway.local with ESMTP
Received: from public-relay.net (public-relay.net [8.8.8.8]) by edge-proxy.local with ESMTP
Received: from client.local (localhost [127.0.0.1]) by public-relay.net with ESMTP

This is test body B.
"""
    parsed_b = parse_eml(raw_eml_b)
    ip_b = parsed_b["originating_ip_candidate"]
    is_pub_b = parsed_b["is_public"]
    geo_b = resolve_ip_geolocation(ip_b)

    print(f"Case B Extracted IP : {ip_b}")
    print(f"Case B Is Public    : {is_pub_b}")
    print("Case B Resolved Geolocation:")
    print(json.dumps(geo_b, indent=2))

    assert ip_b == "8.8.8.8", f"Case B failed: Expected '8.8.8.8', got '{ip_b}'"
    assert is_pub_b is True, "Case B failed: Expected is_public == True"
    print("-> CASE B PASSED: Bypassed private hops (10.0.0.1, 192.168.1.1) and isolated 8.8.8.8!\n")

    # --------------------------------------------------
    # CASE C: Offline / Rate Limited Mock Fallback Test
    # --------------------------------------------------
    print("--- CASE C: Hardcoded Mock Fallback Verification ---")
    from geo_service import get_mock_fallback_geolocation
    fallback_data = get_mock_fallback_geolocation("1.1.1.1")
    print(json.dumps(fallback_data, indent=2))

    assert fallback_data["ip"] == "1.1.1.1"
    assert fallback_data["city"] == "Ashburn"
    assert fallback_data["is_fallback"] is True
    print("-> CASE C PASSED: Mock Fallback format validated!\n")

    print("==========================================================")
    print("         ALL TRUSTED EDGE IP TESTS PASSED!                ")
    print("==========================================================")

if __name__ == "__main__":
    run_ip_fix_tests()
