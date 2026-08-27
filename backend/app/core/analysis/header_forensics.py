from dataclasses import dataclass, asdict
from typing import List
import re
import email.utils
import dns.resolver
try:
    import dkim as dkimpy
except ImportError:
    import dkimpy



@dataclass
class SPFResult:
    status: str
    domain: str
    ip: str
    record: str
    details: str


@dataclass
class DKIMResult:
    status: str
    domain: str
    selector: str
    details: str


@dataclass
class DMARCResult:
    status: str
    policy: str
    domain: str
    alignment_spf: bool
    alignment_dkim: bool
    record: str
    details: str = ""


@dataclass
class RelayHop:
    hop_number: int
    from_host: str
    by_host: str
    ip: str
    timestamp: str
    protocol: str
    delay_seconds: float
    is_private: bool


@dataclass
class AnomalyFlag:
    type: str
    severity: str
    description: str
    evidence: str


@dataclass
class HeaderForensicsResult:
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult
    relay_path: List[RelayHop]
    anomalies: List[AnomalyFlag]
    auth_confidence_score: float


class HeaderForensics:
    async def analyze(
        self,
        raw_eml: bytes,
        parsed_headers: dict,
        sender: str,
        received_hops: list[dict],
    ) -> HeaderForensicsResult:

        _, sender_email = email.utils.parseaddr(sender)
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else (sender_email or sender)
        spf = await self._validate_spf(sender_domain, parsed_headers)
        dkim = await self._verify_dkim(raw_eml, parsed_headers, sender_domain)
        dmarc = await self._check_dmarc(sender_domain, spf, dkim, headers=parsed_headers)
        relay_path = self._reconstruct_relay_path(received_hops)
        anomalies = self._detect_anomalies(parsed_headers, relay_path, sender_domain)
        auth_score = self._compute_auth_confidence(spf, dkim, dmarc, anomalies)

        return HeaderForensicsResult(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            relay_path=relay_path,
            anomalies=anomalies,
            auth_confidence_score=auth_score,
        )

    async def _validate_spf(self, domain: str, headers: dict) -> SPFResult:
        if not domain or not domain.strip():
            return SPFResult(
                status="unavailable",
                domain="",
                ip="",
                record="",
                details="No sender domain available for SPF validation",
            )

        clean_domain = domain.strip().lower()
        
        # 1. Check Received-SPF header if present
        received_spf = ""
        for k, v in headers.items():
            if k.lower() == "received-spf" and isinstance(v, str):
                received_spf = v
                break

        if received_spf:
            status_match = re.match(r"^\s*([a-zA-Z]+)", received_spf)
            client_ip_match = re.search(r"client-ip=([^\s;]+)", received_spf, re.IGNORECASE)
            domain_match = re.search(r"domain of ([^\s;()]+)", received_spf, re.IGNORECASE)
            
            raw_status = status_match.group(1).lower() if status_match else "none"
            client_ip = client_ip_match.group(1).strip("[]()") if client_ip_match else ""
            spf_domain = domain_match.group(1) if domain_match else clean_domain

            status_map = {
                "pass": "pass",
                "softfail": "softfail",
                "fail": "fail",
                "neutral": "neutral",
                "none": "none",
                "permerror": "fail",
                "temperror": "unavailable",
            }
            status = status_map.get(raw_status, "none")
            return SPFResult(
                status=status,
                domain=spf_domain,
                ip=client_ip,
                record=received_spf[:200],
                details=f"SPF {status} verified from Received-SPF header",
            )

        # 2. Check Authentication-Results header
        auth_results = ""
        for k, v in headers.items():
            if k.lower() == "authentication-results" and isinstance(v, str):
                auth_results = v
                break

        if auth_results:
            spf_match = re.search(r"\bspf=([a-zA-Z]+)", auth_results, re.IGNORECASE)
            if spf_match:
                raw_status = spf_match.group(1).lower()
                status_map = {
                    "pass": "pass",
                    "softfail": "softfail",
                    "fail": "fail",
                    "neutral": "neutral",
                    "none": "none",
                    "permerror": "fail",
                    "temperror": "unavailable",
                }
                status = status_map.get(raw_status, "none")
                ip_match = re.search(r"sender IP is ([^\s;()]+)", auth_results, re.IGNORECASE)
                client_ip = ip_match.group(1) if ip_match else ""
                return SPFResult(
                    status=status,
                    domain=clean_domain,
                    ip=client_ip,
                    record=auth_results[:200],
                    details=f"SPF {status} verified from Authentication-Results header",
                )

        # 3. Live DNS lookup using checkdmarc / dnspython
        try:
            import checkdmarc
            res = await asyncio.wait_for(
                asyncio.to_thread(checkdmarc.check_spf, clean_domain, timeout=2.0),
                timeout=3.0,
            )
            record_str = res.get("record", "")
            parsed = res.get("parsed", {})
            all_action = parsed.get("all", "none")
            status = "pass" if res.get("valid") else (all_action if all_action in ("softfail", "fail", "neutral", "pass") else "none")

            return SPFResult(
                status=status,
                domain=clean_domain,
                ip="",
                record=str(record_str)[:200],
                details=f"SPF {status} published for {clean_domain}",
            )
        except Exception:
            pass

        # Fallback: query TXT record manually with dnspython
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            answers = await asyncio.wait_for(
                asyncio.to_thread(resolver.resolve, clean_domain, "TXT"),
                timeout=3.0,
            )
            txt_value = ""
            for rdata in answers:
                txt_value += "".join(p.decode("utf-8", errors="ignore") if isinstance(p, bytes) else str(p) for p in rdata.strings)

            spf_match = re.search(r"v=spf1\s+(.*)", txt_value)
            if not spf_match:
                return SPFResult(
                    status="none",
                    domain=clean_domain,
                    ip="",
                    record=txt_value[:200],
                    details="No valid SPF record found in DNS",
                )

            mechanisms = spf_match.group(1)
            qualifier_match = re.search(r"([+\~-])all\b", mechanisms)
            qualifier = qualifier_match.group(1) if qualifier_match else "?"
            status_map = {"+": "pass", "~": "softfail", "-": "fail", "?": "neutral"}
            status = status_map.get(qualifier, "neutral")

            return SPFResult(
                status=status,
                domain=clean_domain,
                ip="",
                record=txt_value[:200],
                details=f"SPF {status} (parsed from DNS TXT record)",
            )
        except Exception:
            return SPFResult(
                status="none",
                domain=clean_domain,
                ip="",
                record="",
                details="SPF record not found in DNS",
            )

    async def _verify_dkim(
        self, raw_eml: bytes, headers: dict, domain: str
    ) -> DKIMResult:
        try:
            dkim_sig = ""
            for k, v in headers.items():
                if k.lower() == "dkim-signature" and isinstance(v, str):
                    dkim_sig = v
                    break

            auth_results = ""
            for k, v in headers.items():
                if k.lower() == "authentication-results" and isinstance(v, str):
                    auth_results = v
                    break

            if not dkim_sig:
                if auth_results:
                    dkim_match = re.search(r"\bdkim=([a-zA-Z]+)", auth_results, re.IGNORECASE)
                    if dkim_match:
                        raw_status = dkim_match.group(1).lower()
                        status = "pass" if raw_status == "pass" else ("fail" if raw_status == "fail" else "none")
                        return DKIMResult(
                            status=status,
                            domain=domain,
                            selector="",
                            details=f"DKIM {status} from Authentication-Results header",
                        )

                return DKIMResult(
                    status="none",
                    domain="",
                    selector="",
                    details="No DKIM-Signature header found",
                )

            selector_match = re.search(r"s=([^\s;]+)", dkim_sig)
            domain_match = re.search(r"d=([^\s;]+)", dkim_sig)

            selector = selector_match.group(1) if selector_match else ""
            signed_domain = domain_match.group(1) if domain_match else domain

            # Attempt cryptographic verification with dkimpy
            verified = False
            try:
                verified = dkimpy.verify(raw_eml)
            except Exception:
                verified = False

            if verified:
                return DKIMResult(
                    status="pass",
                    domain=signed_domain,
                    selector=selector,
                    details="DKIM signature verified cryptographically",
                )

            # If cryptographic verification failed, check if receiving MTA recorded dkim=pass
            if auth_results:
                dkim_match = re.search(r"\bdkim=([a-zA-Z]+)", auth_results, re.IGNORECASE)
                if dkim_match and dkim_match.group(1).lower() == "pass":
                    return DKIMResult(
                        status="pass",
                        domain=signed_domain,
                        selector=selector,
                        details="DKIM verified by receiving MTA (Authentication-Results)",
                    )

            return DKIMResult(
                status="fail",
                domain=signed_domain,
                selector=selector,
                details="DKIM signature verification failed",
            )
        except Exception as e:
            return DKIMResult(
                status="fail",
                domain=domain,
                selector="",
                details=f"DKIM verification error: {str(e)[:100]}",
            )

    async def _check_dmarc(
        self, domain: str, spf: SPFResult, dkim: DKIMResult, headers: dict | None = None
    ) -> DMARCResult:
        if not domain or not domain.strip():
            return DMARCResult(
                status="unavailable",
                policy="none",
                domain="",
                alignment_spf=False,
                alignment_dkim=False,
                record="",
                details="No domain available for DMARC evaluation",
            )

        headers = headers or {}
        clean_domain = domain.strip().lower()
        org_domain = ".".join(clean_domain.split(".")[-2:]) if "." in clean_domain else clean_domain

        # 1. Check Authentication-Results header
        auth_results = ""
        for k, v in headers.items():
            if k.lower() == "authentication-results" and isinstance(v, str):
                auth_results = v
                break

        if auth_results:
            dmarc_match = re.search(r"\bdmarc=([a-zA-Z]+)", auth_results, re.IGNORECASE)
            if dmarc_match:
                raw_status = dmarc_match.group(1).lower()
                status = "pass" if raw_status == "pass" else ("fail" if raw_status == "fail" else "none")
                policy_match = re.search(r"(?:action|p)=([a-zA-Z]+)", auth_results, re.IGNORECASE)
                policy = policy_match.group(1).lower() if policy_match else "none"

                alignment_spf = (spf.status == "pass")
                alignment_dkim = (dkim.status == "pass")

                return DMARCResult(
                    status=status,
                    policy=policy,
                    domain=clean_domain,
                    alignment_spf=alignment_spf,
                    alignment_dkim=alignment_dkim,
                    record="",
                    details=f"DMARC {status} from Authentication-Results header",
                )

        # 2. Live DNS check with checkdmarc
        try:
            import checkdmarc
            res = await asyncio.wait_for(
                asyncio.to_thread(checkdmarc.check_dmarc, org_domain, timeout=2.0),
                timeout=3.0,
            )
            record_str = res.get("record", "")
            tags = res.get("tags", {})
            policy = tags.get("p", {}).get("value", "none")

            spf_aligned = (spf.status == "pass" and bool(spf.domain and (spf.domain.lower() == org_domain or org_domain in spf.domain.lower())))
            dkim_aligned = (dkim.status == "pass" and bool(dkim.domain and (dkim.domain.lower() == org_domain or org_domain in dkim.domain.lower())))

            status = "pass" if (spf_aligned or dkim_aligned) else ("fail" if (spf.status in ("fail", "softfail") or dkim.status == "fail") else "none")

            return DMARCResult(
                status=status,
                policy=policy,
                domain=org_domain,
                alignment_spf=spf_aligned,
                alignment_dkim=dkim_aligned,
                record=record_str,
                details=f"DMARC {status} (policy: {policy})",
            )
        except Exception:
            pass

        return DMARCResult(
            status="none",
            policy="none",
            domain=clean_domain,
            alignment_spf=False,
            alignment_dkim=False,
            record="",
            details="No DMARC record found in DNS",
        )

    def _reconstruct_relay_path(self, received_hops: list[dict]) -> list[RelayHop]:
        hops = []
        for i, hop in enumerate(received_hops):
            from_host = hop.get("from", "")
            by_host = hop.get("by", "")
            ip = hop.get("ip", "").strip("[]()")
            protocol = hop.get("protocol", "SMTP")

            timestamp = hop.get("timestamp", "")
            if not timestamp:
                received_val = hop.get("received", "")
                ts_match = re.search(r";\s*([^;]+)$", received_val)
                if ts_match:
                    timestamp = ts_match.group(1).strip()

            extracted_ip = ip
            is_private = False
            if extracted_ip:
                try:
                    import ipaddress
                    is_private = ipaddress.ip_address(extracted_ip).is_private
                except Exception:
                    is_private = False

            hops.append(
                RelayHop(
                    hop_number=i + 1,
                    from_host=from_host,
                    by_host=by_host,
                    ip=extracted_ip,
                    timestamp=timestamp,
                    protocol=protocol,
                    delay_seconds=0.0,
                    is_private=is_private,
                )
            )

        # Order from origin (bottom/last) to destination (top/first)
        hops.reverse()

        # Calculate delays
        for i in range(1, len(hops)):
            prev_ts = hops[i - 1].timestamp
            curr_ts = hops[i].timestamp
            if prev_ts and curr_ts:
                try:
                    prev_dt = email.utils.parsedate_to_datetime(prev_ts)
                    curr_dt = email.utils.parsedate_to_datetime(curr_ts)
                    delay = (curr_dt - prev_dt).total_seconds()
                    hops[i].delay_seconds = max(0, delay)
                except Exception:
                    hops[i].delay_seconds = 0.0

        return hops

    def _detect_anomalies(
        self,
        headers: dict,
        relay_path: list[RelayHop],
        sender_domain: str,
    ) -> list[AnomalyFlag]:
        anomalies = []
        from_reply_mismatch = False
        time_travel = False
        missing_msg_id = True
        malformed_msg_id = False
        display_name_spoof = False
        missing_date = True
        future_date = False
        suspicious_x_mailer = False

        from_header = headers.get("from", "")
        reply_to = headers.get("reply-to", "")

        if from_header:
            import tldextract
            from_domain = tldextract.extract(from_header).registered_domain
            reply_domain = (
                tldextract.extract(reply_to).registered_domain if reply_to else ""
            )
            if from_domain and reply_domain and from_domain != reply_domain:
                from_reply_mismatch = True

        # Time travel check
        for i in range(1, len(relay_path)):
            prev_ts = relay_path[i - 1].timestamp
            curr_ts = relay_path[i].timestamp
            if prev_ts and curr_ts:
                try:
                    prev_dt = email.utils.parsedate_to_datetime(prev_ts)
                    curr_dt = email.utils.parsedate_to_datetime(curr_ts)
                    if curr_dt < prev_dt:
                        time_travel = True
                except Exception:
                    pass

        # Message-ID check
        msg_id = headers.get("message-id", "")
        if not msg_id:
            missing_msg_id = True
        else:
            missing_msg_id = False
            malformed_msg_id = not re.match(r"<[^>]+@[^>]+>", msg_id)

        # X-Mailer check
        x_mailer = headers.get("x-mailer", "")
        suspicious_patterns = [
            "mailx", "sendmail", "qmail", "postfix", "esmtp",
        ]
        if x_mailer:
            ml = x_mailer.lower()
            if any(p in ml for p in suspicious_patterns):
                suspicious_x_mailer = True

        # Display name spoofing
        from_match = re.match(r"(.*)\<([^>]+)\>", from_header or "")
        display_name = from_match.group(1).strip() if from_match else from_header or ""
        actual_email = re.search(r"<([^>]+)>", from_header or "").group(1) if re.search(r"<([^>]+)>", from_header or "") else ""
        if display_name and actual_email and display_name != actual_email:
            display_name_spoof = True

        # Date header check
        date_header = headers.get("date", "")
        if not date_header:
            missing_date = True
        else:
            try:
                dt = email.utils.parsedate_to_datetime(date_header)
                now = datetime.datetime.now(dt.tzinfo) if dt.tzinfo else datetime.datetime.now()
                if dt > now + datetime.timedelta(hours=1):
                    future_date = True
                else:
                    missing_date = False
            except Exception:
                missing_date = True

        severity_map = {
            "from_reply_mismatch": "warning",
            "time_travel": "critical",
            "missing_message_id": "warning",
            "malformed_message_id": "info",
            "suspicious_x_mailer": "info",
            "x_originating_ip_suspicious": "warning",
            "excessive_relay_hops": "info",
            "from_header_display_name_spoofing": "warning",
            "missing_date_header": "info",
            "future_dated_email": "warning",
        }

        if from_reply_mismatch:
            anomalies.append(
                AnomalyFlag(
                    type="from_reply_mismatch",
                    severity="warning",
                    description="From/Reply-To domain mismatch",
                    evidence=f"From: {from_header}, Reply-To: {reply_to}",
                )
            )

        if time_travel:
            anomalies.append(
                AnomalyFlag(
                    type="time_travel",
                    severity="critical",
                    description="Time travel in relay detected",
                    evidence=f"Relay hops have timestamps out of order",
                )
            )

        if missing_msg_id:
            anomalies.append(
                AnomalyFlag(
                    type="missing_message_id",
                    severity="warning",
                    description="Missing Message-ID header",
                    evidence="Message-ID header absent or empty",
                )
            )

        if malformed_msg_id and not missing_msg_id:
            anomalies.append(
                AnomalyFlag(
                    type="malformed_message_id",
                    severity="info",
                    description="Malformed Message-ID format",
                    evidence=f"Message-ID: {msg_id}",
                )
            )

        if suspicious_x_mailer:
            anomalies.append(
                AnomalyFlag(
                    type="suspicious_x_mailer",
                    severity="info",
                    description="Suspicious X-Mailer detected",
                    evidence=f"X-Mailer: {x_mailer}",
                )
            )

        if display_name_spoof:
            anomalies.append(
                AnomalyFlag(
                    type="from_header_display_name_spoofing",
                    severity="warning",
                    description="From header display name spoofing",
                    evidence=f"Display name: {display_name}, actual email: {actual_email}",
                )
            )

        if missing_date:
            anomalies.append(
                AnomalyFlag(
                    type="missing_date_header",
                    severity="info",
                    description="Missing Date header",
                    evidence="Date header absent",
                )
            )

        if future_date:
            anomalies.append(
                AnomalyFlag(
                    type="future_dated_email",
                    severity="warning",
                    description="Future-dated email",
                    evidence=f"Date header is in the future: {date_header}",
                )
            )

        return anomalies

    def _compute_auth_confidence(
        self, spf: SPFResult, dkim: DKIMResult, dmarc: DMARCResult, anomalies: list[AnomalyFlag]
    ) -> float:
        w_spf = 0.30
        w_dkim = 0.30
        w_dmarc = 0.25
        w_anomaly = 0.15

        spf_score = 0 if spf.status == "pass" else (50 if spf.status == "softfail" else 100)
        dkim_score = 0 if dkim.status == "pass" else 100
        dmarc_score = 0 if dmarc.status == "pass" else 100
        anomaly_score = min(100, len(anomalies) * 20)

        score = (
            100
            - (w_spf * spf_score + w_dkim * dkim_score + w_dmarc * dmarc_score + w_anomaly * anomaly_score)
        )

        return round(max(0.0, min(100.0, score)), 2)