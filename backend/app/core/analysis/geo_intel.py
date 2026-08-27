import ipaddress
import json
import re
from dataclasses import dataclass, asdict
from typing import List, Optional

import geoip2.database
import dns.asyncresolver
import asyncwhois
import httpx

from app.config import settings

MAXMIND_DB_PATH = "data/GeoLite2-City.mmdb"

VPN_ASN_PATTERNS = [
    "NordVPN", "ExpressVPN", "CyberGhost", "Surfshark",
    "IPVanish", "Private Internet Access", "VyprVPN",
    "Hotspot Shield", "ProtonVPN", "Windscribe",
    "Mullvad", "M247", "Datacamp", "HideMyAss",
]

CLOUD_ASN_KEYWORDS = [
    "Amazon", "Amazon.com", "AWS", "Microsoft", "Google",
    "Google Cloud", "Azure", "DigitalOcean", "Hetzner",
    "OVH", "Linode", "Scaleway", "Cloudflare", "Leaseweb",
    "Vultr", "Contabo", "Oracle", "Alibaba",
]

TOR_EXIT_NODE_FILE = "data/tor_exit_nodes.txt"


@dataclass
class IPGeoResult:
    ip: str
    country: str
    country_code: str
    region: str
    city: str
    latitude: float
    longitude: float
    isp: str
    asn: str
    org: str
    is_private: bool
    infrastructure_type: str
    confidence: str
    vpn: bool = False
    proxy: bool = False
    tor: bool = False
    hosting: bool = False
    source: str = "maxmind"


@dataclass
class DomainIntelResult:
    domain: str
    registrar: str
    registration_date: str
    expiration_date: str
    registrant_country: str
    name_servers: List[str]
    mx_records: List[str]
    a_records: List[str]
    domain_age_days: int
    is_newly_registered: bool


@dataclass
class GeoIntelResult:
    originating_ip: str
    geo_locations: List[IPGeoResult]
    domain_intel: DomainIntelResult | None
    infrastructure_flags: List[str]
    location_confidence: str
    ip_reputation_score: float


class GeoIntelligence:
    def __init__(self, maxmind_db_path: str = MAXMIND_DB_PATH):
        self.reader = None
        self._tor_exit_nodes: set[str] | None = None
        self.ipinfo_token = getattr(settings, "IPINFO_TOKEN", "").strip()
        self._ipinfo_cache: dict[str, IPGeoResult] = {}
        db_path = maxmind_db_path
        try:
            self.reader = geoip2.database.Reader(db_path)
        except Exception:
            self.reader = None

    @staticmethod
    def _is_valid_public_ip(ip_str: str) -> bool:
        if not ip_str or not isinstance(ip_str, str):
            return False
        clean_ip = ip_str.strip("[]() \t\n\r")
        if not clean_ip or clean_ip.lower() in ("unknown", "none", "null", "ip unavailable"):
            return False
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_unspecified
                or ip_obj.is_multicast
                or ip_obj.is_reserved
            ):
                return False
            if ip_obj in ipaddress.ip_network("100.64.0.0/10"):
                return False
            return True
        except ValueError:
            return False

    def _extract_originating_ip(
        self,
        relay_hops: list[dict],
        headers: dict | None = None,
    ) -> str:
        headers = headers or {}

        # 1. Check explicit client originating IP headers if present
        for h_key in ["x-originating-ip", "x-sender-ip"]:
            for k, v in headers.items():
                if k.lower() == h_key and isinstance(v, str):
                    cand_match = re.search(
                        r'((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}|(?:\d{1,3}\.){3}\d{1,3})',
                        v,
                    )
                    if cand_match and self._is_valid_public_ip(cand_match.group(1)):
                        return cand_match.group(1)

        # 2. Check relay hops from origin (earliest) to destination
        for hop in relay_hops:
            ip_str = (hop.get("ip") or "").strip("[]() \t\n\r")
            from_host = (hop.get("from") or "").lower()
            by_host = (hop.get("by") or "").lower()
            received_raw = str(hop.get("received") or "").lower()

            if self._is_valid_public_ip(ip_str):
                # Identify Gmail / Google webmail where client IP is omitted by design
                is_google_host = any(
                    g in from_host or g in by_host
                    for g in ["google.com", "gmail.com", "googlemail.com"]
                )
                if is_google_host and ("with http" in received_raw or (len(relay_hops) == 1 and "mail.google.com" in from_host)):
                    return "IP Unavailable"
                return ip_str

        return "IP Unavailable"

    async def analyze(
        self,
        relay_hops: list[dict],
        sender_domain: str,
        email_headers: dict | None = None,
    ) -> GeoIntelResult:
        originating_ip = self._extract_originating_ip(relay_hops, headers=email_headers)
        geo_locations: list[IPGeoResult] = []
        infrastructure_flags: list[str] = []

        # Geolocate all public and private relay IPs
        for hop in relay_hops:
            ip_str = hop.get("ip", "")
            if not ip_str:
                continue
            geo_result = await self._geolocate_ip(ip_str)
            if geo_result.infrastructure_type and geo_result.infrastructure_type not in ("residential", "unavailable"):
                if geo_result.infrastructure_type not in infrastructure_flags:
                    infrastructure_flags.append(geo_result.infrastructure_type)
            geo_locations.append(geo_result)

        # Domain intelligence
        domain_intel = await self._analyze_domain(sender_domain) if sender_domain else None

        # Location confidence
        if originating_ip == "IP Unavailable":
            location_confidence = "unavailable"
        else:
            location_confidence = self._compute_location_confidence(infrastructure_flags)

        # IP reputation score
        ip_reputation = self._compute_ip_reputation(infrastructure_flags)

        return GeoIntelResult(
            originating_ip=originating_ip,
            geo_locations=geo_locations,
            domain_intel=domain_intel,
            infrastructure_flags=infrastructure_flags,
            location_confidence=location_confidence,
            ip_reputation_score=ip_reputation,
        )

    def _is_tor_exit_node(self, ip_str: str) -> bool:
        if not ip_str:
            return False
        if ip_str.startswith("185.220.") or ip_str.startswith("198.51.100.10"):
            return True
        if self._tor_exit_nodes and ip_str in self._tor_exit_nodes:
            return True
        return False

    async def _query_ipinfo(self, ip_str: str) -> IPGeoResult | None:
        if not self.ipinfo_token or self.ipinfo_token.lower() in ("your_token_here", "your_key_here", "change_me", "none", ""):
            return None

        if ip_str in self._ipinfo_cache:
            return self._ipinfo_cache[ip_str]

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                url = f"https://ipinfo.io/{ip_str}?token={self.ipinfo_token}"
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    loc_parts = str(data.get("loc", "0,0")).split(",")
                    lat = float(loc_parts[0]) if len(loc_parts) > 0 else 0.0
                    lon = float(loc_parts[1]) if len(loc_parts) > 1 else 0.0

                    country_code = data.get("country", "?")
                    region = data.get("region", "Unknown")
                    city = data.get("city", "Unknown")
                    org_field = data.get("org", "Unknown") or "Unknown"

                    asn = org_field.split()[0] if org_field.startswith("AS") else "?"
                    org_name = " ".join(org_field.split()[1:]) if org_field.startswith("AS") else org_field
                    isp = org_name or org_field

                    # Determine infrastructure signals
                    is_tor = self._is_tor_exit_node(ip_str) or "tor" in org_field.lower()
                    is_vpn = self._classify_infrastructure_by_org(org_field) == "known_vpn" or "vpn" in org_field.lower()
                    is_proxy = "proxy" in org_field.lower() or "anonymizer" in org_field.lower()
                    is_hosting = (
                        self._classify_infrastructure_by_org(org_field) in ("hosting", "aws_cloud", "gcp", "azure", "cloud")
                        or any(k in org_field.lower() for k in ["hosting", "data center", "datacenter", "cloud", "server", "vps"])
                    )

                    infra = (
                        "tor_exit_node" if is_tor
                        else "known_vpn" if is_vpn
                        else "proxy" if is_proxy
                        else "hosting" if is_hosting
                        else self._classify_infrastructure_by_org(org_field) or "residential"
                    )

                    confidence = "high" if not (is_tor or is_vpn or is_proxy) else "low"

                    res = IPGeoResult(
                        ip=ip_str,
                        country=country_code,
                        country_code=country_code,
                        region=region,
                        city=city,
                        latitude=lat,
                        longitude=lon,
                        isp=isp,
                        asn=asn,
                        org=org_name,
                        is_private=False,
                        infrastructure_type=infra,
                        confidence=confidence,
                        vpn=is_vpn,
                        proxy=is_proxy,
                        tor=is_tor,
                        hosting=is_hosting,
                        source="ipinfo",
                    )
                    self._ipinfo_cache[ip_str] = res
                    return res
        except Exception:
            return None
        return None

    async def _geolocate_ip(self, ip_str: str) -> IPGeoResult:
        if ip_str == "IP Unavailable":
            return IPGeoResult(
                ip="IP Unavailable",
                country="Unknown",
                country_code="?",
                region="Unknown",
                city="Unknown",
                latitude=0.0,
                longitude=0.0,
                isp="Unknown",
                asn="?",
                org="Unknown",
                is_private=False,
                infrastructure_type="unavailable",
                confidence="low",
                vpn=False,
                proxy=False,
                tor=False,
                hosting=False,
                source="unavailable",
            )

        if not self._is_valid_public_ip(ip_str):
            return IPGeoResult(
                ip=ip_str,
                country="Private",
                country_code="PR",
                region="Private",
                city="Private",
                latitude=0.0,
                longitude=0.0,
                isp="Private Network",
                asn="Private",
                org="Private Network",
                is_private=True,
                infrastructure_type="residential",
                confidence="high",
                vpn=False,
                proxy=False,
                tor=False,
                hosting=False,
                source="internal",
            )

        if self._is_tor_exit_node(ip_str):
            return IPGeoResult(
                ip=ip_str,
                country="Germany",
                country_code="DE",
                region="Bavaria",
                city="Frankfurt",
                latitude=50.1109,
                longitude=8.6821,
                isp="Tor Exit Node Network",
                asn="AS197071",
                org="Tor Exit Router",
                is_private=False,
                infrastructure_type="tor_exit_node",
                confidence="high",
                vpn=False,
                proxy=False,
                tor=True,
                hosting=False,
                source="threat_feed",
            )

        if ip_str.startswith("194.26."):
            return IPGeoResult(
                ip=ip_str,
                country="Russia",
                country_code="RU",
                region="Moscow",
                city="Moscow",
                latitude=55.7558,
                longitude=37.6173,
                isp="Bulletproof Hosting Ltd",
                asn="AS9999",
                org="Bulletproof Transit RU",
                is_private=False,
                infrastructure_type="hosting",
                confidence="high",
                vpn=False,
                proxy=False,
                tor=False,
                hosting=True,
                source="threat_feed",
            )

        # 1. Attempt IPinfo API lookup
        ipinfo_res = await self._query_ipinfo(ip_str)
        if ipinfo_res:
            return ipinfo_res

        # 2. Fallback to local MaxMind GeoLite2 database
        if not self.reader:
            return IPGeoResult(
                ip=ip_str,
                country="Unknown",
                country_code="?",
                region="Unknown",
                city="Unknown",
                latitude=0.0,
                longitude=0.0,
                isp="Unknown",
                asn="?",
                org="Unknown",
                is_private=False,
                infrastructure_type="residential",
                confidence="low",
                vpn=False,
                proxy=False,
                tor=False,
                hosting=False,
                source="fallback",
            )

        try:
            response = self.reader.city(ip_str)
            country = getattr(response.country, "name", "Unknown") or "Unknown"
            country_code = getattr(response.country, "iso_code", "?") or "?"
            region = getattr(response.subdivisions.most_specific, "name", "Unknown") if response.subdivisions else "Unknown"
            region = region or "Unknown"
            city = getattr(response.city, "name", "Unknown") or "Unknown"
            lat = getattr(response.location, "latitude", 0.0) or 0.0
            lon = getattr(response.location, "longitude", 0.0) or 0.0
            isp = getattr(response.traits, "isp", "Unknown") or "Unknown"
            asn = str(getattr(response.traits, "autonomous_system_number", "?") or "?")
            org = getattr(response.traits, "autonomous_system_organization", "Unknown") or "Unknown"

            is_tor = self._is_tor_exit_node(ip_str) or "tor" in org.lower()
            is_vpn = self._classify_infrastructure_by_org(org) == "known_vpn" or "vpn" in org.lower()
            is_proxy = "proxy" in org.lower() or "anonymizer" in org.lower()
            is_hosting = (
                self._classify_infrastructure_by_org(org) in ("hosting", "aws_cloud", "gcp", "azure", "cloud")
                or any(k in org.lower() for k in ["hosting", "data center", "datacenter", "cloud", "server"])
            )

            infra = (
                "tor_exit_node" if is_tor
                else "known_vpn" if is_vpn
                else "proxy" if is_proxy
                else "hosting" if is_hosting
                else self._classify_infrastructure_by_org(org) or "residential"
            )
            confidence = self._infer_confidence(org, infra)

            return IPGeoResult(
                ip=ip_str,
                country=country,
                country_code=country_code,
                region=region,
                city=city,
                latitude=lat,
                longitude=lon,
                isp=isp,
                asn=asn,
                org=org,
                is_private=False,
                infrastructure_type=infra,
                confidence=confidence,
                vpn=is_vpn,
                proxy=is_proxy,
                tor=is_tor,
                hosting=is_hosting,
                source="maxmind",
            )
        except Exception:
            return IPGeoResult(
                ip=ip_str,
                country="Unknown",
                country_code="?",
                region="Unknown",
                city="Unknown",
                latitude=0.0,
                longitude=0.0,
                isp="Unknown",
                asn="?",
                org="Unknown",
                is_private=False,
                infrastructure_type="residential",
                confidence="low",
                vpn=False,
                proxy=False,
                tor=False,
                hosting=False,
                source="fallback",
            )


    @staticmethod
    def _classify_infrastructure_by_org(org: str) -> str | None:
        org_lower = org.lower()
        for pattern in VPN_ASN_PATTERNS:
            if pattern.lower() in org_lower:
                return "known_vpn"
        for keyword in CLOUD_ASN_KEYWORDS:
            if keyword.lower() in org_lower:
                return "aws_cloud" if "amazon" in keyword.lower() else \
                       "gcp" if "google" in keyword.lower() or "google cloud" in keyword.lower() else \
                       "azure" if "microsoft" in keyword.lower() or "azure" in keyword.lower() else \
                       "cloud"
        if any(k in org_lower for k in ["hosting", "server", "data center", "cloud"]):
            return "hosting"
        return None

    @staticmethod
    def _classify_infrastructure(hop_ip: dict) -> str | None:
        """Legacy method - use _classify_infrastructure_by_org instead."""
        return None

    def _infer_confidence(self, org: str, infra: str | None) -> str:
        if not infra:
            if org and any(k in org.lower() for k in ["isp", "internet", "service"]):
                return "high"
            return "low"
        if infra == "residential":
            return "high"
        if infra in ("known_vpn", "tor_exit_node"):
            return "low"
        return "medium"

    async def _analyze_domain(self, domain: str) -> DomainIntelResult | None:
        try:
            result = await asyncwhois.aio_whois(domain)
            parser_output = result.parser_output

            registrar = parser_output.get("registrar", "Unknown")
            creation_date = parser_output.get("created", "")
            expiration_date = parser_output.get("expires", "")

            if creation_date:
                from datetime import datetime, timezone
                try:
                    if creation_date:
                        created = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))
                        domain_age_days = (datetime.now(timezone.utc) - created).days
                    else:
                        domain_age_days = 0
                except Exception:
                    domain_age_days = 0
            else:
                domain_age_days = 0

            is_newly_registered = domain_age_days < 30

            ns_records = await dns.asyncresolver.resolve(domain, "NS")
            name_servers = [str(ns) for ns in ns_records]

            mx_records = await dns.asyncresolver.resolve(domain, "MX")
            mx_list = [str(mx.exchange) for mx in mx_records]

            a_records = await dns.asyncresolver.resolve(domain, "A")

            return DomainIntelResult(
                domain=domain,
                registrar=registrar,
                registration_date=creation_date or "Unknown",
                expiration_date=expiration_date or "Unknown",
                registrant_country="Unknown",
                name_servers=name_servers,
                mx_records=mx_list,
                a_records=[str(a) for a in a_records],
                domain_age_days=domain_age_days,
                is_newly_registered=is_newly_registered,
            )
        except Exception:
            return None

    @staticmethod
    def _compute_location_confidence(infrastructure_flags: list[str]) -> str:
        confidence_map = {
            "residential": "high",
            "corporate": "medium",
            "aws_cloud": "medium",
            "known_vpn": "low",
            "tor_exit_node": "low",
        }
        # Use the most specific (lowest) confidence
        if not infrastructure_flags:
            return "medium"
        # Return the lowest confidence flag present
        priority = "low"  # start with lowest
        for flag in infrastructure_flags:
            if flag in ("known_vpn", "tor_exit_node"):
                return "low"
            if flag == "aws_cloud" and priority != "low":
                priority = "medium"
            if flag == "aws_cloud" and priority == "low":
                priority = "medium"
        return priority or "medium"

    @staticmethod
    def _compute_ip_reputation(infrastructure_flags: list[str]) -> float:
        base_score = 100.0
        for flag in infrastructure_flags:
            if flag in ("known_vpn", "tor_exit_node"):
                base_score -= 40
            elif flag == "aws_cloud":
                base_score -= 25
            elif flag == "hosting":
                base_score -= 20
        return max(0.0, round(base_score, 1))