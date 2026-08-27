import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from app.core.analysis.geo_intel import GeoIntelligence, IPGeoResult
from app.core.correlation.risk_scorer import RiskScorer
from app.core.analysis.nlp_classifier import NLPClassificationResult
from app.core.analysis.header_forensics import HeaderForensicsResult, SPFResult, DKIMResult, DMARCResult


@pytest.mark.asyncio
async def test_extract_originating_ip_public():
    geo = GeoIntelligence()
    hops = [
        {'hop_number': 1, 'ip': '92.45.87.58', 'from': 'px58.kitapyurdu.com', 'by': 'mx.outlook.com'},
        {'hop_number': 2, 'ip': '2603:10b6:5:14c:cafe::41', 'from': 'mx.outlook.com', 'by': 'internal.outlook.com'},
    ]
    orig_ip = geo._extract_originating_ip(hops)
    assert orig_ip == '92.45.87.58'


@pytest.mark.asyncio
async def test_extract_originating_ip_x_originating_ip():
    geo = GeoIntelligence()
    headers = {'X-Originating-IP': '[140.82.121.3]'}
    hops = [
        {'hop_number': 1, 'ip': '209.85.220.41', 'from': 'mail.google.com', 'by': 'mx.enterprise.com'}
    ]
    orig_ip = geo._extract_originating_ip(hops, headers=headers)
    assert orig_ip == '140.82.121.3'


@pytest.mark.asyncio
async def test_extract_originating_ip_gmail_webmail():
    geo = GeoIntelligence()
    hops = [
        {
            'hop_number': 1,
            'ip': '209.85.216.44',
            'from': 'mail-pj1-f44.google.com',
            'by': 'mx.google.com',
            'received': 'by mail-pj1-f44.google.com with HTTP; Thu, 27 Aug 2026 07:00:00 -0700',
        }
    ]
    orig_ip = geo._extract_originating_ip(hops, headers={})
    assert orig_ip == 'IP Unavailable'


@pytest.mark.asyncio
async def test_extract_originating_ip_private_only():
    geo = GeoIntelligence()
    hops = [
        {'hop_number': 1, 'ip': '10.0.0.1', 'from': 'int1.local', 'by': 'int2.local'},
        {'hop_number': 2, 'ip': '192.168.1.50', 'from': 'int2.local', 'by': 'int3.local'},
        {'hop_number': 3, 'ip': '::1', 'from': 'int3.local', 'by': 'mx.local'},
    ]
    orig_ip = geo._extract_originating_ip(hops)
    assert orig_ip == 'IP Unavailable'


@pytest.mark.asyncio
async def test_extract_originating_ip_invalid_malformed():
    geo = GeoIntelligence()
    hops = [
        {'hop_number': 1, 'ip': '999.999.999.999', 'from': 'bad', 'by': 'bad'},
        {'hop_number': 2, 'ip': 'invalid-ip-string', 'from': 'bad', 'by': 'bad'},
    ]
    orig_ip = geo._extract_originating_ip(hops)
    assert orig_ip == 'IP Unavailable'


@pytest.mark.asyncio
async def test_ipinfo_api_success_mock():
    geo = GeoIntelligence()
    geo.ipinfo_token = 'test_ipinfo_token'

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        'ip': '140.82.121.3',
        'city': 'Frankfurt',
        'region': 'Hesse',
        'country': 'DE',
        'loc': '50.1109,8.6821',
        'org': 'AS197071 NordVPN Network',
    }

    with patch('httpx.AsyncClient.get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await geo._geolocate_ip('140.82.121.3')

    assert res.ip == '140.82.121.3'
    assert res.city == 'Frankfurt'
    assert res.country_code == 'DE'
    assert res.vpn is True
    assert res.infrastructure_type == 'known_vpn'
    assert res.source == 'ipinfo'


@pytest.mark.asyncio
async def test_ipinfo_api_failure_fallback_to_maxmind():
    geo = GeoIntelligence()
    geo.ipinfo_token = 'test_ipinfo_token'

    mock_resp = MagicMock()
    mock_resp.status_code = 429

    mock_city_resp = MagicMock()
    mock_city_resp.country.name = 'United States'
    mock_city_resp.country.iso_code = 'US'
    mock_city_resp.city.name = 'Mountain View'
    mock_city_resp.subdivisions.most_specific.name = 'California'
    mock_city_resp.location.latitude = 37.4
    mock_city_resp.location.longitude = -122.0
    mock_city_resp.traits.autonomous_system_number = 15169
    mock_city_resp.traits.autonomous_system_organization = 'Google LLC'
    mock_city_resp.traits.isp = 'Google LLC'

    geo.reader = MagicMock()
    geo.reader.city.return_value = mock_city_resp

    with patch('httpx.AsyncClient.get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await geo._geolocate_ip('8.8.8.8')

    assert res.ip == '8.8.8.8'
    assert res.country in ('United States', 'US')
    assert res.source == 'maxmind'


@pytest.mark.asyncio
async def test_vpn_risk_scoring_signal():
    scorer = RiskScorer()
    nlp_res = NLPClassificationResult(
        label='Legitimate',
        confidence=95.0,
        probabilities={'Legitimate': 0.95, 'Phishing': 0.05},
        urgency_score=0.0,
        bec_indicators=[],
        impersonation_signals=[],
        contributing_factors=[],
    )
    header_res = HeaderForensicsResult(
        spf=SPFResult(status='pass', domain='example.com', ip='140.82.121.3', record='', details='SPF match'),
        dkim=DKIMResult(status='pass', domain='example.com', selector='s1', details=''),
        dmarc=DMARCResult(status='pass', policy='none', domain='example.com', alignment_spf=True, alignment_dkim=True, record=''),
        relay_path=[],
        anomalies=[],
        auth_confidence_score=100.0,
    )
    geo_res = MagicMock()
    geo_res.originating_ip = '140.82.121.3'
    geo_res.infrastructure_flags = ['known_vpn']
    geo_res.ip_reputation_score = 80.0

    comp = scorer.compute(nlp_res, header_res, geo_res)
    assert comp.overall_score < 40.0
    assert comp.severity in ('low', 'medium')


@pytest.mark.asyncio
async def test_ip_unavailable_handling():
    scorer = RiskScorer()
    geo_res = MagicMock()
    geo_res.originating_ip = 'IP Unavailable'
    geo_res.infrastructure_flags = []
    geo_res.ip_reputation_score = 100.0

    details = scorer._extract_geo_details(geo_res)
    assert 'Unavailable' in details
