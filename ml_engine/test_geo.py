import json
from email_parser import extract_originating_ip
from geo_service import resolve_ip_geolocation, is_public_ip

def test_ip_extraction_and_geolocation():
    print("==================================================")
    print("    RUNNING MAILFORENSIX IP & GEO UNIT TESTS     ")
    print("==================================================\n")

    # Sample Received header chain simulating an incoming email through multiple hops
    # Ordered from top (recipient's edge mail server) to bottom (original sender hop)
    received_chain = [
        "Received: from mx.destination.com (mx.destination.com [10.0.0.1]) by recipient.internal with ESMTP",
        "Received: from relay2.internal.net (relay2.internal.net [172.16.0.2]) by mx.destination.com with ESMTP",
        "Received: from boundary.isp.com (boundary.isp.com [192.168.1.5]) by relay2.internal.net with ESMTP",
        "Received: from tor-exit.provider.org (tor-exit.provider.org [185.220.101.5]) by boundary.isp.com with ESMTP",
        "Received: from client.local (localhost [127.0.0.1]) by tor-exit.provider.org with ESMTP"
    ]

    print("Step 1: Testing Received Chain Traversal (Bottom to Top)...")
    print(f"Chain length: {len(received_chain)} hops")

    # Bottom hop has 127.0.0.1 (loopback)
    # Next bottom hop has 185.220.101.5 (public)
    # Next hops have 192.168.1.5, 172.16.0.2, 10.0.0.1 (private)
    originating_ip, is_public = extract_originating_ip(received_chain)

    print(f"-> Extracted Originating Candidate IP: '{originating_ip}'")
    print(f"-> Is Public IP: {is_public}")

    # Assertions
    assert originating_ip == "185.220.101.5", f"Expected '185.220.101.5', got '{originating_ip}'"
    assert is_public is True, "Expected is_public == True"
    print("SUCCESS: Private, loopback, and local IPs (127.0.0.1, 192.168.1.5, 172.16.0.2, 10.0.0.1) were correctly bypassed!\n")

    print("Step 2: Testing Dual-Layer Geolocation Resolver...")
    resolved = resolve_ip_geolocation(originating_ip)

    print("-> Resolved Geolocation Payload:")
    print(json.dumps(resolved, indent=2))

    assert resolved["originating_ip"] == "185.220.101.5"
    assert resolved["is_public"] is True
    assert "country" in resolved["geolocation"]
    assert "isp" in resolved["geolocation"]

    print("\nStep 3: Testing Google Public DNS IP (8.8.8.8)...")
    dns_geo = resolve_ip_geolocation("8.8.8.8")
    print("-> Resolved 8.8.8.8 Geolocation Payload:")
    print(json.dumps(dns_geo, indent=2))
    assert dns_geo["geolocation"]["country_code"] == "US" or dns_geo["geolocation"]["country"] == "United States"

    print("\n==================================================")
    print("         ALL UNIT TESTS PASSED SUCCESSFULLY!       ")
    print("==================================================")

if __name__ == "__main__":
    test_ip_extraction_and_geolocation()
