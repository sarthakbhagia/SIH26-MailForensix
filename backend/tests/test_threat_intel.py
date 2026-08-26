import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from app.core.correlation.threat_intel import (
    ThreatIntelAggregator,
    AbuseIPDBResult,
    VirusTotalResult,
    PhishTankResult,
    RateLimiter,
)
from app.core.correlation.cache import RedisCache


@pytest.mark.asyncio
async def test_rate_limiter():
    limiter = RateLimiter(calls_per_minute=60)
    # Should acquire without error
    await limiter.acquire()
    assert limiter.tokens < 60.0


@pytest.mark.asyncio
async def test_threat_intel_without_api_keys():
    """Verify aggregator gracefully returns clean data when API keys are not provided."""
    aggregator = ThreatIntelAggregator(cache=None)
    aggregator.abuseipdb_key = ""
    aggregator.virustotal_key = ""

    report = await aggregator.enrich(
        ips=["8.8.8.8"],
        domains=["example.com"],
        urls=["http://example.com/test"],
        hashes=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )

    assert "8.8.8.8" in report.ip_results
    assert report.ip_results["8.8.8.8"].abuse_confidence_score == 0
    assert "example.com" in report.domain_results
    assert report.domain_results["example.com"].malicious_count == 0
    assert "http://example.com/test" in report.url_results
    assert report.url_results["http://example.com/test"].malicious_count == 0
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in report.hash_results
    assert report.phishtank_results["http://example.com/test"].is_phishing is False


@pytest.mark.asyncio
async def test_abuseipdb_mock_query():
    """Test AbuseIPDB query parsing with mocked HTTP response."""
    aggregator = ThreatIntelAggregator(cache=None)
    aggregator.abuseipdb_key = "test_abuseipdb_key"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "ipAddress": "198.51.100.1",
            "abuseConfidenceScore": 85,
            "totalReports": 42,
            "lastReportedAt": "2026-08-20T10:00:00Z",
            "reports": [{"categories": [18]}],
            "isp": "Malicious Host Inc",
            "domain": "badhost.net",
            "countryCode": "RU",
            "isWhitelisted": False,
        }
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await aggregator._query_abuseipdb("198.51.100.1")

        assert result.ip == "198.51.100.1"
        assert result.abuse_confidence_score == 85
        assert result.total_reports == 42
        assert "Brute-Force" in result.category_names
        assert result.isp == "Malicious Host Inc"


@pytest.mark.asyncio
async def test_virustotal_mock_queries():
    """Test VirusTotal domain/URL/hash query parsing with mocked HTTP response."""
    aggregator = ThreatIntelAggregator(cache=None)
    aggregator.virustotal_key = "test_vt_key"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 15,
                    "suspicious": 3,
                    "harmless": 60,
                    "undetected": 10,
                },
                "reputation": -50,
                "categories": {"VendorA": "phishing"},
                "last_analysis_date": 1770000000,
            }
        }
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        # Test Domain
        dom_res = await aggregator._query_virustotal_domain("evil-domain.com")
        assert dom_res.indicator == "evil-domain.com"
        assert dom_res.malicious_count == 15
        assert dom_res.detection_ratio > 0.15

        # Test URL
        url_res = await aggregator._query_virustotal_url("http://evil-domain.com/login")
        assert url_res.indicator == "http://evil-domain.com/login"
        assert url_res.malicious_count == 15

        # Test Hash
        hash_res = await aggregator._query_virustotal_hash("a" * 64)
        assert hash_res.indicator == "a" * 64
        assert hash_res.malicious_count == 15


@pytest.mark.asyncio
async def test_caching_behavior():
    """Test that results are retrieved from and saved to cache."""
    mock_cache = AsyncMock(spec=RedisCache)
    mock_cache.get.return_value = None  # Cache miss first

    aggregator = ThreatIntelAggregator(cache=mock_cache)
    aggregator.abuseipdb_key = ""

    result = await aggregator._query_abuseipdb("198.51.100.2")
    assert result.ip == "198.51.100.2"

    # Now test cache hit
    cached_data = {
        "ip": "198.51.100.2",
        "abuse_confidence_score": 90,
        "total_reports": 100,
        "last_reported": "2026-08-25T00:00:00Z",
        "categories": [15],
        "category_names": ["Hacking"],
        "isp": "Cached ISP",
        "domain": "cached.com",
        "country_code": "US",
        "is_whitelisted": False,
    }
    mock_cache.get.return_value = cached_data

    cached_result = await aggregator._query_abuseipdb("198.51.100.2")
    assert cached_result.abuse_confidence_score == 90
    assert cached_result.isp == "Cached ISP"
