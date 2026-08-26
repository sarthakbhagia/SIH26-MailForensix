import asyncio
import base64
import logging
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import httpx
from app.config import settings
from app.core.correlation.cache import RedisCache

logger = logging.getLogger(__name__)


@dataclass
class AbuseIPDBResult:
    ip: str
    abuse_confidence_score: int   # 0-100 from AbuseIPDB
    total_reports: int
    last_reported: Optional[str]     # ISO timestamp
    categories: List[int]         # AbuseIPDB category codes
    category_names: List[str]     # Human-readable category names
    isp: str
    domain: str
    country_code: str
    is_whitelisted: bool


@dataclass
class VirusTotalResult:
    indicator: str                # IP, domain, URL, or hash
    indicator_type: str           # "ip" | "domain" | "url" | "hash"
    malicious_count: int          # Vendors flagging as malicious
    suspicious_count: int
    harmless_count: int
    total_vendors: int
    detection_ratio: float        # malicious / total
    community_score: int          # VirusTotal community reputation votes
    categories: Dict[str, str]    # {vendor: category}
    last_analysis_date: Optional[str]


@dataclass
class PhishTankResult:
    url: str
    is_phishing: bool
    phish_id: Optional[int]
    verified: bool
    verified_at: Optional[str]


@dataclass
class ThreatIntelReport:
    ip_results: Dict[str, AbuseIPDBResult]
    domain_results: Dict[str, VirusTotalResult]
    url_results: Dict[str, VirusTotalResult]
    hash_results: Dict[str, VirusTotalResult]
    phishtank_results: Dict[str, PhishTankResult]
    enrichment_timestamp: str
    apis_queried: List[str]


class RateLimiter:
    """Token bucket rate limiter for API calls."""

    def __init__(self, calls_per_minute: int):
        self.rate = max(1, calls_per_minute)
        self.tokens = float(self.rate)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(float(self.rate), self.tokens + elapsed * (self.rate / 60.0))
            self.last_refill = now

            if self.tokens < 1.0:
                wait_time = (1.0 - self.tokens) / (self.rate / 60.0)
                await asyncio.sleep(wait_time)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0


class ThreatIntelAggregator:
    """Enriches extracted indicators with external threat intelligence (AbuseIPDB, VirusTotal, PhishTank)."""

    ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
    VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"
    PHISHTANK_DB_URL = "http://data.phishtank.com/data/online-valid.json"

    ABUSEIPDB_CATEGORIES = {
        1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
        4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
        7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
        10: "Web Spam", 11: "Email Spam", 14: "Port Scan",
        15: "Hacking", 16: "SQL Injection", 17: "Email Spoofing",
        18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
        21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
    }

    def __init__(self, cache: Optional[RedisCache] = None):
        self.cache = cache
        self.abuseipdb_key = getattr(settings, "ABUSEIPDB_KEY", "") or getattr(settings, "ABUSEIPDB_API_KEY", "")
        self.virustotal_key = getattr(settings, "VIRUSTOTAL_KEY", "") or getattr(settings, "VIRUSTOTAL_API_KEY", "")
        
        self._vt_rate_limiter = RateLimiter(calls_per_minute=4)
        self._abuseipdb_rate_limiter = RateLimiter(calls_per_minute=60)
        self._phishtank_local_cache: List[dict] = []

    def _is_valid_key(self, key: Optional[str]) -> bool:
        if not key or not str(key).strip():
            return False
        clean = str(key).strip().lower()
        return clean not in ("your_key_here", "your_token_here", "your_api_key", "change_me", "none", "null", "")

    async def query(self, *args, **kwargs) -> Any:
        """Backward-compatible query stub."""
        return await self.enrich(*args, **kwargs)

    async def enrich(
        self,
        ips: Optional[List[str]] = None,
        domains: Optional[List[str]] = None,
        urls: Optional[List[str]] = None,
        hashes: Optional[List[str]] = None,
    ) -> ThreatIntelReport:
        """Run comprehensive threat intelligence enrichment across all IOC lists."""
        ips = ips or []
        domains = domains or []
        urls = urls or []
        hashes = hashes or []

        ip_results: Dict[str, AbuseIPDBResult] = {}
        domain_results: Dict[str, VirusTotalResult] = {}
        url_results: Dict[str, VirusTotalResult] = {}
        hash_results: Dict[str, VirusTotalResult] = {}
        phishtank_results: Dict[str, PhishTankResult] = {}
        apis_queried: List[str] = []

        # 1. Enrich IPs
        for ip in ips:
            if not ip or ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")):
                continue
            ip_results[ip] = await self._query_abuseipdb(ip)
            if "AbuseIPDB" not in apis_queried:
                apis_queried.append("AbuseIPDB")

        # 2. Enrich Domains with VirusTotal
        for domain in domains:
            if not domain or domain in ("localhost", "local"):
                continue
            domain_results[domain] = await self._query_virustotal_domain(domain)
            if "VirusTotal" not in apis_queried:
                apis_queried.append("VirusTotal")

        # 3. Enrich URLs with VirusTotal & PhishTank
        for url in urls:
            if not url:
                continue
            url_results[url] = await self._query_virustotal_url(url)
            phishtank_results[url] = await self._check_phishtank(url)
            if "VirusTotal" not in apis_queried:
                apis_queried.append("VirusTotal")
            if "PhishTank" not in apis_queried:
                apis_queried.append("PhishTank")

        # 4. Enrich Hashes with VirusTotal
        for h in hashes:
            if not h:
                continue
            hash_results[h] = await self._query_virustotal_hash(h)
            if "VirusTotal" not in apis_queried:
                apis_queried.append("VirusTotal")

        return ThreatIntelReport(
            ip_results=ip_results,
            domain_results=domain_results,
            url_results=url_results,
            hash_results=hash_results,
            phishtank_results=phishtank_results,
            enrichment_timestamp=datetime.now(timezone.utc).isoformat(),
            apis_queried=apis_queried,
        )

    async def _query_abuseipdb(self, ip: str) -> AbuseIPDBResult:
        """Query AbuseIPDB for IP reputation with cache support."""
        cache_key = f"abuseipdb:{ip}"
        if self.cache:
            cached = await self.cache.get(cache_key)
            if cached and isinstance(cached, dict):
                return AbuseIPDBResult(**cached)

        if not self._is_valid_key(self.abuseipdb_key):
            logger.debug("AbuseIPDB key not configured, returning default clean result.")
            return AbuseIPDBResult(
                ip=ip,
                abuse_confidence_score=0,
                total_reports=0,
                last_reported=None,
                categories=[],
                category_names=[],
                isp="Unknown",
                domain="Unknown",
                country_code="",
                is_whitelisted=False,
            )

        await self._abuseipdb_rate_limiter.acquire()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{self.ABUSEIPDB_BASE}/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                    headers={
                        "Key": self.abuseipdb_key,
                        "Accept": "application/json",
                    },
                )
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    cats = data.get("reports", [])
                    cat_ids = list({r.get("categories", [0])[0] for r in cats if "categories" in r and r["categories"]})
                    
                    result = AbuseIPDBResult(
                        ip=ip,
                        abuse_confidence_score=data.get("abuseConfidenceScore", 0),
                        total_reports=data.get("totalReports", 0),
                        last_reported=data.get("lastReportedAt"),
                        categories=cat_ids,
                        category_names=[self.ABUSEIPDB_CATEGORIES.get(c, f"Cat {c}") for c in cat_ids],
                        isp=data.get("isp", "Unknown"),
                        domain=data.get("domain", "Unknown"),
                        country_code=data.get("countryCode", ""),
                        is_whitelisted=data.get("isWhitelisted", False),
                    )
                    if self.cache:
                        await self.cache.set(cache_key, asdict(result), ttl=86400)
                    return result
                else:
                    logger.warning(f"AbuseIPDB returned status {response.status_code} for IP {ip}")
        except Exception as e:
            logger.warning(f"Error querying AbuseIPDB for IP {ip}: {e}")

        return AbuseIPDBResult(
            ip=ip,
            abuse_confidence_score=0,
            total_reports=0,
            last_reported=None,
            categories=[],
            category_names=[],
            isp="Unknown",
            domain="Unknown",
            country_code="",
            is_whitelisted=False,
        )

    def _empty_vt_result(self, indicator: str, indicator_type: str) -> VirusTotalResult:
        return VirusTotalResult(
            indicator=indicator,
            indicator_type=indicator_type,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            total_vendors=0,
            detection_ratio=0.0,
            community_score=0,
            categories={},
            last_analysis_date=None,
        )

    async def _query_virustotal_ip(self, ip: str) -> VirusTotalResult:
        """Query VirusTotal v3 for IP reputation."""
        cache_key = f"vt:ip:{ip}"
        if self.cache:
            cached = await self.cache.get(cache_key)
            if cached and isinstance(cached, dict):
                return VirusTotalResult(**cached)

        if not self._is_valid_key(self.virustotal_key):
            return self._empty_vt_result(ip, "ip")

        await self._vt_rate_limiter.acquire()
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    f"{self.VIRUSTOTAL_BASE}/ip_addresses/{ip}",
                    headers={"x-apikey": self.virustotal_key},
                )
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    total = sum(stats.values()) or 1
                    
                    result = VirusTotalResult(
                        indicator=ip,
                        indicator_type="ip",
                        malicious_count=malicious,
                        suspicious_count=suspicious,
                        harmless_count=harmless,
                        total_vendors=total,
                        detection_ratio=round(malicious / total, 3),
                        community_score=data.get("reputation", 0),
                        categories={},
                        last_analysis_date=str(data.get("last_analysis_date", "")),
                    )
                    if self.cache:
                        await self.cache.set(cache_key, asdict(result), ttl=86400)
                    return result
                elif response.status_code == 404:
                    return self._empty_vt_result(ip, "ip")
                else:
                    logger.warning(f"VirusTotal IP query error {response.status_code} for {ip}")
        except Exception as e:
            logger.warning(f"Error querying VirusTotal for IP {ip}: {e}")

        return self._empty_vt_result(ip, "ip")

    async def _query_virustotal_domain(self, domain: str) -> VirusTotalResult:
        """Query VirusTotal v3 for domain reputation."""
        cache_key = f"vt:domain:{domain}"
        if self.cache:
            cached = await self.cache.get(cache_key)
            if cached and isinstance(cached, dict):
                return VirusTotalResult(**cached)

        if not self._is_valid_key(self.virustotal_key):
            return self._empty_vt_result(domain, "domain")

        await self._vt_rate_limiter.acquire()
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    f"{self.VIRUSTOTAL_BASE}/domains/{domain}",
                    headers={"x-apikey": self.virustotal_key},
                )
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    total = sum(stats.values()) or 1

                    result = VirusTotalResult(
                        indicator=domain,
                        indicator_type="domain",
                        malicious_count=malicious,
                        suspicious_count=suspicious,
                        harmless_count=harmless,
                        total_vendors=total,
                        detection_ratio=round(malicious / total, 3),
                        community_score=data.get("reputation", 0),
                        categories=data.get("categories", {}),
                        last_analysis_date=str(data.get("last_analysis_date", "")),
                    )
                    if self.cache:
                        await self.cache.set(cache_key, asdict(result), ttl=86400)
                    return result
                elif response.status_code == 404:
                    return self._empty_vt_result(domain, "domain")
        except Exception as e:
            logger.warning(f"Error querying VirusTotal for domain {domain}: {e}")

        return self._empty_vt_result(domain, "domain")

    async def _query_virustotal_url(self, url: str) -> VirusTotalResult:
        """Query VirusTotal v3 for URL reputation using base64 encoded URL identifier."""
        cache_key = f"vt:url:{url}"
        if self.cache:
            cached = await self.cache.get(cache_key)
            if cached and isinstance(cached, dict):
                return VirusTotalResult(**cached)

        if not self._is_valid_key(self.virustotal_key):
            return self._empty_vt_result(url, "url")

        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        await self._vt_rate_limiter.acquire()
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    f"{self.VIRUSTOTAL_BASE}/urls/{url_id}",
                    headers={"x-apikey": self.virustotal_key},
                )
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    total = sum(stats.values()) or 1

                    result = VirusTotalResult(
                        indicator=url,
                        indicator_type="url",
                        malicious_count=malicious,
                        suspicious_count=suspicious,
                        harmless_count=harmless,
                        total_vendors=total,
                        detection_ratio=round(malicious / total, 3),
                        community_score=data.get("reputation", 0),
                        categories=data.get("categories", {}),
                        last_analysis_date=str(data.get("last_analysis_date", "")),
                    )
                    if self.cache:
                        await self.cache.set(cache_key, asdict(result), ttl=21600)  # 6h TTL
                    return result
                elif response.status_code == 404:
                    return self._empty_vt_result(url, "url")
        except Exception as e:
            logger.warning(f"Error querying VirusTotal for URL {url}: {e}")

        return self._empty_vt_result(url, "url")

    async def _query_virustotal_hash(self, file_hash: str) -> VirusTotalResult:
        """Query VirusTotal v3 for file hash reputation."""
        cache_key = f"vt:hash:{file_hash}"
        if self.cache:
            cached = await self.cache.get(cache_key)
            if cached and isinstance(cached, dict):
                return VirusTotalResult(**cached)

        if not self._is_valid_key(self.virustotal_key):
            return self._empty_vt_result(file_hash, "hash")

        await self._vt_rate_limiter.acquire()
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    f"{self.VIRUSTOTAL_BASE}/files/{file_hash}",
                    headers={"x-apikey": self.virustotal_key},
                )
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    total = sum(stats.values()) or 1

                    result = VirusTotalResult(
                        indicator=file_hash,
                        indicator_type="hash",
                        malicious_count=malicious,
                        suspicious_count=suspicious,
                        harmless_count=harmless,
                        total_vendors=total,
                        detection_ratio=round(malicious / total, 3),
                        community_score=data.get("reputation", 0),
                        categories={},
                        last_analysis_date=str(data.get("last_analysis_date", "")),
                    )
                    if self.cache:
                        await self.cache.set(cache_key, asdict(result), ttl=172800)  # 48h TTL
                    return result
                elif response.status_code == 404:
                    return self._empty_vt_result(file_hash, "hash")
        except Exception as e:
            logger.warning(f"Error querying VirusTotal for hash {file_hash}: {e}")

        return self._empty_vt_result(file_hash, "hash")

    async def _check_phishtank(self, url: str) -> PhishTankResult:
        """Check URL against PhishTank indicators."""
        cache_key = f"phishtank:{url}"
        if self.cache:
            cached = await self.cache.get(cache_key)
            if cached and isinstance(cached, dict):
                return PhishTankResult(**cached)

        # Check in local cache if populated
        for entry in self._phishtank_local_cache:
            target_url = entry.get("url", "")
            if target_url and (target_url == url or url.startswith(target_url)):
                result = PhishTankResult(
                    url=url,
                    is_phishing=True,
                    phish_id=entry.get("phish_id"),
                    verified=entry.get("verified", False),
                    verified_at=entry.get("verification_time"),
                )
                if self.cache:
                    await self.cache.set(cache_key, asdict(result), ttl=3600)
                return result

        result = PhishTankResult(
            url=url,
            is_phishing=False,
            phish_id=None,
            verified=False,
            verified_at=None,
        )
        if self.cache:
            await self.cache.set(cache_key, asdict(result), ttl=21600)
        return result
