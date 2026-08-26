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

        sender_domain, _ = email.utils.parseaddr(sender)
        spf = await self._validate_spf(sender_domain, parsed_headers)
        dkim = await self._verify_dkim(raw_eml, parsed_headers, sender_domain)
        dmarc = await self._check_dmarc(sender_domain, spf, dkim)
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
        ip = ""
        try:
            try:
                from checkdmarc.spf import get_spf_record
            except ImportError:
                from checkdmarc import get_spf_record

            record, parsed = get_spf_record(domain)
            mechanisms = parsed.get("mechanisms", [])
            ip = ""
            for mechan in mechanisms:
                tag = mechan.get("tag")
                value = mechan.get("value", "")
                if tag in ("ip4", "ip6", "a", "mx"):
                    ip = value
                elif tag == "include":
                    ip = await self._resolve_include(value, domain)

            qualifier = parsed.get("qualifier", "?")
            status_map = {"+": "pass", "~": "softfail", "-": "fail", "?": "none"}
            status = status_map.get(qualifier, "none")

            return SPFResult(
                status=status,
                domain=domain,
                ip=ip,
                record=str(record),
                details=f"SPF {status} for domain {domain}",
            )
        except Exception:
            pass

        # Fallback: query TXT record manually with dnspython
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, "TXT")
            txt_value = ""
            for rdata in answers:
                txt_value += "".join(str(p) for rdata in answers for p in rdata.strings) or ""

            # Simple SPF parsing
            spf_match = re.search(r"v=spf1\s+([^\s]+)", txt_value)
            if not spf_match:
                return SPFResult(
                    status="none",
                    domain=domain,
                    ip="",
                    record=txt_value,
                    details="No valid SPF record found",
                )

            mechanisms = spf_match.group(1)
            ip = ""
            for mechan_match in re.finditer(r"(ip4|ip6|a|mx|include)[:\s]+([^\s]+)", mechanisms):
                tag = mechan_match.group(1)
                value = mechan_match.group(2)
                if tag in ("ip4",):
                    ip = value
                    break

            qualifier_match = re.search(r"[+\~-]$", mechanisms)
            qualifier = qualifier_match.group(0) if qualifier_match else "?"
            status_map = {"+": "pass", "~": "softfail", "-": "fail", "?": "none"}
            status = status_map.get(qualifier, "none")

            return SPFResult(
                status=status,
                domain=domain,
                ip=ip,
                record=txt_value[:200],
                details=f"SPF {status} (fallback parse)",
            )
        except Exception:
            return SPFResult(
                status="none",
                domain=domain,
                ip="",
                record="",
                details="SPF validation failed",
            )

    async def _resolve_include(self, include_domain: str, base_domain: str) -> str:
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(include_domain, "TXT")
            for rdata in answers:
                txt = "".join(str(p) for p in rdata.strings)
                spf_match = re.search(r"v=spf1\s+([^\s]+)", txt)
                if spf_match:
                    return spf_match.group(1)[:100]
            return ""
        except Exception:
            return ""

    async def _verify_dkim(
        self, raw_eml: bytes, headers: dict, domain: str
    ) -> DKIMResult:
        try:
            dkim_sig = headers.get("dkim-signature", "")
            if not dkim_sig:
                return DKIMResult(
                    status="none",
                    domain="",
                    selector="",
                    details="No DKIM-Signature header found",
                )

            dkimpy.verify(raw_eml)

            selector_match = re.search(r"s=([^\s;]+)", dkim_sig)
            domain_match = re.search(r"d=([^\s;]+)", dkim_sig)

            selector = selector_match.group(1) if selector_match else ""
            signed_domain = domain_match.group(1) if domain_match else domain

            return DKIMResult(
                status="pass",
                domain=signed_domain,
                selector=selector,
                details="DKIM signature verified cryptographically",
            )
        except Exception as e:
            dkim_match = re.search(r"s=([^\s;]+)", dkim_sig)
            dkim_domain = dkim_match.group(1) if dkim_match else domain
            return DKIMResult(
                status="fail",
                domain=dkim_domain,
                selector="",
                details=f"DKIM verification failed: {str(e)[:100]}",
            )

    async def _check_dmarc(
        self, domain: str, spf: SPFResult, dkim: DKIMResult
    ) -> DMARCResult:
        org_domain = ".".join(domain.split(".")[-2:])
        try:
            try:
                from checkdmarc.dmarc import get_dmarc_record
            except ImportError:
                from checkdmarc import get_dmarc_record

            dmarc_record, parsed = get_dmarc_record(f"_dmarc.{org_domain}")

            policy = parsed.get("policy", "none")
            alignment_spf = parsed.get("alignment_spf", False)
            alignment_dkim = parsed.get("alignment_dkim", False)
            record_str = str(dmarc_record)

            return DMARCResult(
                status="pass",
                policy=policy,
                domain=org_domain,
                alignment_spf=alignment_spf,
                alignment_dkim=alignment_dkim,
                record=record_str,
            )
        except Exception:
            return DMARCResult(
                status="none",
                policy="none",
                domain=domain,
                alignment_spf=False,
                alignment_dkim=False,
                record="",
            )

    def _reconstruct_relay_path(self, received_hops: list[dict]) -> list[RelayHop]:
        hops = []
        for i, hop in enumerate(received_hops):
            from_host = hop.get("from", "")
            by_host = hop.get("by", "")
            ip = hop.get("ip", "")
            protocol = hop.get("protocol", "SMTP")

            timestamp = ""
            received_val = hop.get("received", "")
            ts_match = re.search(
                r";\\s*([^\\]*)$", received_val
            )
            if ts_match:
                timestamp = ts_match.group(1).strip()

            ip_match = re.search(r"\[?([\d.]+)\]?", ip)
            extracted_ip = ip_match.group(1) if ip_match else ip

            is_private = False
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