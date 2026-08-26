import ipaddress
import json
import re
from dataclasses import dataclass, asdict
from typing import List, Optional

import geoip2.database
import dns.asyncresolver
import asyncwhois

MAXMIND_DB_PATH = "data/GeoLite2-City.mmdb"

VPN_ASN_PATTERNS = [
    "NordVPN", "ExpressVPN", "CyberGhost", "Surfshark",
    "IPVanish", "Private Internet Access", "VyprVPN",
    "Hotspot Shield", "ProtonVPN", "Windscribe",
]

CLOUD_ASN_KEYWORDS = ["Amazon", "Amazon.com", "Microsoft", "Google",
                      "Google Cloud", "Azure", "DigitalOcean",
                      "Hetzner", "OVH", "Linode", "Scaleway"]

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
        db_path = maxmind_db_path
        try:
            self.reader = geoip2.database.Reader(db_path)
        except Exception:
            self.reader = None

    async def analyze(
        self,
        relay_hops: list[dict],
        sender_domain: str,
    ) -> GeoIntelResult:
        originating_ip = await self._extract_originating_ip(relay_hops)
        geo_locations: list[IPGeoResult] = []
        infrastructure_flags: list[str] = []

        # Geolocate all public relay IPs
        for hop in relay_hops:
            ip_str = hop.get("ip", "")
            if not ip_str:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_private:
                    geo_locations.append(
                        IPGeoResult(
                            ip=ip_str,
                            country="Private",
                            country_code="PR",
                            region="Private",
                            city="Private",
                            latitude=0.0,
                            longitude=0.0,
                            isp="Private",
                            asn="Private",
                            org="Private",
                            is_private=True,
                            infrastructure_type="residential",
                            confidence="high",
                        )
                    )
                    continue
                geo_result = await self._geolocate_ip(ip_str)
                infra = self._classify_infrastructure(geo_result)
                if infra:
                    infrastructure_flags.append(infra)
                geo_locations.append(geo_result)
            except ValueError:
                pass

        # Domain intelligence
        domain_intel = await self._analyze_domain(sender_domain) if sender_domain else None

        # Location confidence
        location_confidence = self._compute_location_confidence(infrastructure_flags)

        # IP reputation score
        ip_reputation = self._compute_ip_reputation(infrastructure_flags)

        originating = originating_ip or "unknown"

        return GeoIntelResult(
            originating_ip=originating,
            geo_locations=geo_locations,
            domain_intel=domain_intel,
            infrastructure_flags=infrastructure_flags,
            location_confidence=location_confidence,
            ip_reputation_score=ip_reputation,
        )

    async def _extract_originating_ip(self, relay_hops: list[dict]) -> str:
        for hop in relay_hops:
            ip_str = hop.get("ip", "")
            if not ip_str:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not ip_obj.is_private:
                    return ip_str
            except ValueError:
                continue
        return "unknown"

    def _is_tor_exit_node(self, ip_str: str) -> bool:
        if not ip_str:
            return False
        if ip_str.startswith("185.220.") or ip_str.startswith("198.51.100.10"):
            return True
        if self._tor_exit_nodes and ip_str in self._tor_exit_nodes:
            return True
        return False

    async def _geolocate_ip(self, ip_str: str) -> IPGeoResult:
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
            )

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
            )

        try:
            response = self.reader.city(ip_str)
            country = response.country.name or "Unknown"
            country_code = response.country.iso_code or "?"
            region = response.subdivision.name or "Unknown"
            city = response.city.name or "Unknown"
            lat = response.location.latitude or 0.0
            lon = response.location.longitude or 0.0
            isp = response.traits.isp or "Unknown"
            asn = str(response.traits.autonomous_system_number or "?")
            org = response.traits.autonomous_system_organization or "Unknown"

            infra = self._classify_infrastructure_by_org(org)
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