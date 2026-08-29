import test from 'node:test';
import assert from 'node:assert/strict';
import { generateForensicDossierText, type ForensicDossierParams } from '../dossierGenerator.ts';

test('Forensic Dossier Report - Valid Date (2026-08-29T10:30:00)', () => {
  const params: ForensicDossierParams = {
    emailId: 'e9a4f210-b991-4c12-8823-1d0b0432fef1',
    ingestedAt: '2026-08-29T10:30:00.000Z',
    status: 'analyzed',
    riskScore: 85,
    attributionCategory: 'Compromised Account',
    attributionConfidence: 90,
    subject: 'Urgent Wire Transfer Request',
    sender: 'ceo@example.com',
    senderDomain: 'example.com',
    recipients: 'finance@example.com',
    rawHeaders: { 'message-id': '<msg-123@example.com>' },
    originIp: '198.51.100.25',
    originLocText: 'London, United Kingdom',
    originProvider: 'DigitalOcean LLC',
    spf: { status: 'pass', domain: 'example.com' },
    dkim: { status: 'pass', domain: 'example.com', selector: 's1' },
    dmarc: { status: 'pass', policy: 'reject', alignment_spf: true, alignment_dkim: true },
    relayPath: [{ hop_number: 1, protocol: 'ESMTPS', ip: '198.51.100.25', hostname: 'mail.example.com' }],
    iocs: [{ type: 'IP', value: '198.51.100.25', risk_score: 85, reason: 'Suspicious origin' }],
    findings: [{ severity: 'critical', title: 'BEC Wire Fraud Attempt', detail: 'Financial urgency keywords detected.' }],
  };

  const report = generateForensicDossierText(params);
  assert.ok(report.includes('INGESTED AT      : 2026-08-29T10:30:00.000Z'));
  assert.ok(report.includes('EVIDENCE ID      : e9a4f210-b991-4c12-8823-1d0b0432fef1'));
  assert.ok(report.includes('COMPOSITE RISK   : 85 / 100'));
});

test('Forensic Dossier Report - Null/Missing Date', () => {
  const params: ForensicDossierParams = {
    emailId: 'e9a4f210-b991-4c12-8823-1d0b0432fef1',
    ingestedAt: null,
    status: 'analyzed',
    riskScore: 20,
    attributionCategory: 'Legitimate',
    attributionConfidence: null,
    subject: 'Meeting Notes',
    sender: 'alice@example.com',
    senderDomain: 'example.com',
    recipients: 'bob@example.com',
    rawHeaders: {},
    originIp: '192.0.2.1',
    spf: { status: 'pass', domain: 'example.com' },
    dkim: { status: 'pass', selector: 's1' },
    dmarc: { status: 'pass', policy: 'none', alignment_spf: true, alignment_dkim: true },
    relayPath: [],
    iocs: [],
    findings: [],
  };

  assert.doesNotThrow(() => {
    const report = generateForensicDossierText(params);
    assert.ok(report.includes('INGESTED AT      : '));
    assert.ok(report.includes('EVIDENCE ID      : e9a4f210-b991-4c12-8823-1d0b0432fef1'));
  });
});

test('Forensic Dossier Report - Invalid Date ("invalid-date") NEVER throws RangeError', () => {
  const params: ForensicDossierParams = {
    emailId: 'e9a4f210-b991-4c12-8823-1d0b0432fef1',
    ingestedAt: 'invalid-date',
    status: 'analyzed',
    riskScore: 45,
    attributionCategory: 'Undetermined',
    attributionConfidence: null,
    subject: 'Test Subject',
    sender: 'test@example.com',
    senderDomain: 'example.com',
    recipients: 'user@example.com',
    rawHeaders: {},
    originIp: '192.0.2.1',
    spf: { status: 'unavailable', domain: 'example.com' },
    dkim: { status: 'unavailable', selector: 'default' },
    dmarc: { status: 'unavailable', policy: 'none', alignment_spf: false, alignment_dkim: false },
    relayPath: [],
    iocs: [],
    findings: [],
  };

  assert.doesNotThrow(() => {
    const report = generateForensicDossierText(params);
    assert.ok(report.includes('INGESTED AT      : '));
    assert.ok(report.includes('MAILFORENSIX — FORENSIC THREAT INTELLIGENCE DOSSIER'));
  });
});

test('Overview Tab Isolation - Dossier report calculation skipped without affecting state', () => {
  let activeDomain = 'overview';
  let reportComputed = false;

  const computeReportIfDossier = (domain: string, params: ForensicDossierParams) => {
    if (domain !== 'dossier') {
      return '';
    }
    reportComputed = true;
    return generateForensicDossierText(params);
  };

  const dummyParams: ForensicDossierParams = {
    emailId: 'test-id',
    ingestedAt: 'invalid-date',
    status: 'analyzed',
    riskScore: 50,
    attributionCategory: 'Test',
    sender: 'a@b.com',
    senderDomain: 'b.com',
    recipients: 'c@d.com',
    rawHeaders: {},
    originIp: '1.2.3.4',
    spf: { status: 'pass' },
    dkim: { status: 'pass', selector: 's' },
    dmarc: { status: 'pass' },
    relayPath: [],
    iocs: [],
    findings: [],
  };

  // During Overview rendering
  const overviewResult = computeReportIfDossier(activeDomain, dummyParams);
  assert.equal(overviewResult, '');
  assert.equal(reportComputed, false);

  // When switching to Dossier tab
  activeDomain = 'dossier';
  const dossierResult = computeReportIfDossier(activeDomain, dummyParams);
  assert.equal(reportComputed, true);
  assert.ok(dossierResult.includes('MAILFORENSIX'));
});
