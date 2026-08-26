import re
import tldextract
from dataclasses import dataclass, asdict
from typing import List, Set
from difflib import SequenceMatcher

import httpx

SHORTENERS: Set[str] = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "short.link", "rb.gy", "cutt.ly",
}

TOP_BRANDS: Set[str] = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "netflix.com", "facebook.com", "instagram.com",
    "linkedin.com", "dropbox.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "dhl.com", "fedex.com", "usps.com",
    "irs.gov", "who.int", "adobe.com", "zoom.us",
}


@dataclass
class URLAnalysisResult:
    original_url: str
    resolved_url: str
    domain: str
    subdomain: str
    tld: str
    is_shortened: bool
    redirect_chain: List[str]
    risk_score: float
    risk_reasons: List[str]
    is_phishing: bool
    lookalike_target: str | None


@dataclass
class LinkAnalysisResult:
    urls_analyzed: int
    url_results: List[URLAnalysisResult]
    overall_link_risk: float
    phishing_urls_found: int
    suspicious_urls_found: int


class LinkAnalyzer:
    async def analyze(self, urls: list[str]) -> LinkAnalysisResult:
        if not urls:
            return LinkAnalysisResult(
                urls_analyzed=0,
                url_results=[],
                overall_link_risk=0.0,
                phishing_urls_found=0,
                suspicious_urls_found=0,
            )

        url_results: list[URLAnalysisResult] = []
        phishing_count = 0
        suspicious_count = 0

        async with httpx.AsyncClient(follow_redirects=True, max_redirects=10, timeout=10) as client:
            for url in urls:
                result = await self._analyze_url(client, url)
                url_results.append(result)
                if result.is_phishing:
                    phishing_count += 1
                if result.risk_score > 50:
                    suspicious_count += 1

        overall_risk = max((r.risk_score for r in url_results), default=0.0)
        return LinkAnalysisResult(
            urls_analyzed=len(urls),
            url_results=url_results,
            overall_link_risk=round(overall_risk, 1),
            phishing_urls_found=phishing_count,
            suspicious_urls_found=suspicious_count,
        )

    async def _analyze_url(self, client: httpx.AsyncClient, url: str) -> URLAnalysisResult:
        is_shortened = self._is_shortened(url)
        ext = tldextract.extract(url)
        domain = ext.domain
        subdomain = ext.subdomain
        tld = ext.suffix

        resolved_url = url
        redirect_chain: list[str] = []
        if is_shortened:
            try:
                response = await client.head(url, follow_redirects=False)
                redirect_chain = [str(response.url)]
                for resp in response.history:
                    redirect_chain.insert(0, str(resp.url))
                resolved_url = str(response.url)
            except Exception:
                resolved_url = url

        domain_extracted = tldextract.extract(resolved_url)
        domain = domain_extracted.domain
        suffix = domain_extracted.suffix
        subdomain = domain_extracted.subdomain

        risk_score = 0.0
        risk_reasons: list[str] = []
        lookalike_target: str | None = None
        is_phishing = False

        # Lookalike detection
        for brand in TOP_BRANDS:
            brand_domain = brand.split(".")[0]
            if domain and self._is_lookalike(domain, brand_domain):
                risk_score += 40
                risk_reasons.append("lookalike_domain")
                lookalike_target = brand
                if risk_score >= 100:
                    risk_score = 100
                    is_phishing = True
                break

        # Homoglyph detection
        try:
            from confusables import is_confusable
            if is_confusable(domain, preferred_aliases=["latin"]):
                risk_score += 50
                risk_reasons.append("homoglyph_attack")
                if risk_score >= 100:
                    risk_score = 100
                    is_phishing = True
        except Exception:
            pass

        # Additional homoglyph checks
        subst_map = {"0": "o", "1": "l", "rn": "m", "vv": "w"}
        for sub, rep in subst_map.items():
            if sub in domain.lower():
                alt = domain.lower().replace(sub, rep)
                for brand in TOP_BRANDS:
                    brand_dom = brand.split(".")[0]
                    if brand_dom in alt or SequenceMatcher(None, alt, brand_dom).ratio() > 0.8:
                        risk_score += 40
                        risk_reasons.append("homoglyph_attack")
                        lookalike_target = brand
                        break

        # Shortened URL penalty
        if is_shortened:
            risk_score += 10
            risk_reasons.append("shortened_url")

        # Suspicious TLD check
        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".buzz", ".icu"}
        tld_lower = (suffix or "").lower()
        if tld_lower and (f".{tld_lower}" in suspicious_tlds or tld_lower in suspicious_tlds):
            risk_score += 25
            risk_reasons.append("suspicious_tld")

        # IP as hostname
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain or ""):
            risk_score += 30
            risk_reasons.append("ip_as_hostname")

        # Data URI or javascript:
        if url.startswith("data:") or url.startswith("javascript:"):
            risk_score += 80
            risk_reasons.append("data_uri_or_javascript")

        # Punycode
        if domain and "xn--" in domain:
            risk_score += 25
            risk_reasons.append("punycode")

        if risk_score >= 50:
            is_phishing = True

        return URLAnalysisResult(
            original_url=url,
            resolved_url=resolved_url,
            domain=domain or "",
            subdomain=subdomain or "",
            tld=suffix or "",
            is_shortened=is_shortened,
            redirect_chain=redirect_chain,
            risk_score=min(100.0, round(risk_score, 1)),
            risk_reasons=risk_reasons,
            is_phishing=is_phishing,
            lookalike_target=lookalike_target,
        )

    @staticmethod
    def _is_shortened(url: str) -> bool:
        try:
            parsed = url.split("/")[2] if "/" in url else url
            domain = parsed.split("?")[0]
            return domain in SHORTENERS
        except Exception:
            return False

    @staticmethod
    def _is_lookalike(test_domain: str, brand_domain: str) -> bool:
        if not test_domain or not brand_domain:
            return False
        td = test_domain.lower()
        bd = brand_domain.lower()
        if td == bd:
            return False
        ratio = SequenceMatcher(None, td, bd).ratio()
        if ratio > 0.75:
            return True
        # Check sub-tokens (e.g. paypa1-security-login -> paypa1)
        tokens = re.split(r"[-_.]", td)
        for token in tokens:
            if token and token != bd:
                t_ratio = SequenceMatcher(None, token, bd).ratio()
                if t_ratio > 0.75:
                    return True
        return False