import pytest
import asyncio
from app.core.analysis.header_forensics import HeaderForensics, SPFResult, DKIMResult, DMARCResult


@pytest.mark.asyncio
async def test_auth_passing_headers():
    forensics = HeaderForensics()
    headers = {
        'Received-SPF': 'Pass (protection.outlook.com: domain of trusted.com designates 92.45.87.58 as permitted sender) client-ip=92.45.87.58;',
        'Authentication-Results': 'spf=pass (sender IP is 92.45.87.58) smtp.mailfrom=trusted.com; dkim=pass (signature was verified) header.d=trusted.com; dmarc=pass action=none header.from=trusted.com',
        'DKIM-Signature': 'v=1; a=rsa-sha256; d=trusted.com; s=s1; b=fake...',
    }
    raw_eml = b'From: user@trusted.com\nSubject: Test\n\nBody'

    res = await forensics.analyze(raw_eml, headers, 'user@trusted.com', [])
    assert res.spf.status == 'pass'
    assert res.spf.ip == '92.45.87.58'
    assert res.dkim.status == 'pass'
    assert res.dmarc.status == 'pass'
    assert res.auth_confidence_score >= 80.0


@pytest.mark.asyncio
async def test_auth_failure_headers():
    forensics = HeaderForensics()
    headers = {
        'Received-SPF': 'Fail (protection.outlook.com: domain of spoofed.com does not designate 1.2.3.4 as permitted sender) client-ip=1.2.3.4;',
        'Authentication-Results': 'spf=fail smtp.mailfrom=spoofed.com; dkim=fail header.d=spoofed.com; dmarc=fail action=reject header.from=spoofed.com',
        'DKIM-Signature': 'v=1; a=rsa-sha256; d=spoofed.com; s=s1; b=invalid...',
    }
    raw_eml = b'From: attacker@spoofed.com\nSubject: Spoofed\n\nEvil'

    res = await forensics.analyze(raw_eml, headers, 'attacker@spoofed.com', [])
    assert res.spf.status == 'fail'
    assert res.dkim.status == 'fail'
    assert res.dmarc.status == 'fail'
    assert res.auth_confidence_score <= 40.0


@pytest.mark.asyncio
async def test_auth_unavailable_no_domain():
    forensics = HeaderForensics()
    headers = {}
    raw_eml = b'Subject: No Sender\n\nBody'

    res = await forensics.analyze(raw_eml, headers, '', [])
    assert res.spf.status == 'unavailable'
    assert res.dkim.status == 'none'
    assert res.dmarc.status == 'unavailable'
