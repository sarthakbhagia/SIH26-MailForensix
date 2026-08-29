import { getVerdictForScore } from './severity.ts';
import { safeToISOString } from './dateUtils.ts';

export interface ForensicDossierParams {
  emailId: string;
  ingestedAt?: unknown;
  status?: string;
  riskScore: number;
  attributionCategory: string;
  attributionConfidence?: number | null;
  subject?: string;
  sender: string;
  senderDomain: string;
  recipients: string;
  rawHeaders?: Record<string, string>;
  originIp?: string;
  originLocText?: string;
  originProvider?: string;
  spf?: { status?: string; domain?: string; selector?: string; details?: string };
  dkim?: { status?: string; domain?: string; selector?: string; details?: string };
  dmarc?: { status?: string; policy?: string; domain?: string; alignment_spf?: boolean; alignment_dkim?: boolean; details?: string };
  relayPath?: any[];
  iocs?: any[];
  findings?: Array<{ severity: string; title: string; detail: string }>;
}

export function generateForensicDossierText(params: ForensicDossierParams): string {
  const {
    emailId,
    ingestedAt,
    status,
    riskScore,
    attributionCategory,
    attributionConfidence,
    subject,
    sender,
    senderDomain,
    recipients,
    rawHeaders = {},
    originIp = '—',
    originLocText = 'Undetermined',
    originProvider = '—',
    spf = { status: 'unavailable', domain: '—' },
    dkim = { status: 'unavailable', selector: '—' },
    dmarc = { status: 'unavailable', policy: 'none', alignment_spf: false, alignment_dkim: false },
    relayPath = [],
    iocs = [],
    findings = [],
  } = params;

  const verdictLabel = getVerdictForScore(riskScore).toUpperCase();

  return `================================================================================
MAILFORENSIX — FORENSIC THREAT INTELLIGENCE DOSSIER
================================================================================
EVIDENCE ID      : ${emailId}
INGESTED AT      : ${safeToISOString(ingestedAt)}
STATUS           : ${String(status || 'analyzed').toUpperCase()}
COMPOSITE RISK   : ${riskScore} / 100 [${verdictLabel}]
ATTRIBUTION      : ${attributionCategory}${attributionConfidence ? ` (Confidence: ${attributionConfidence}%)` : ''}

--------------------------------------------------------------------------------
1. TRANSMISSION & ENVELOPE METADATA
--------------------------------------------------------------------------------
Subject          : ${subject || '—'}
Sender (From)    : ${sender}
Sender Domain    : ${senderDomain || '—'}
Recipients (To)  : ${recipients}
Message-ID       : ${rawHeaders['message-id'] || rawHeaders['Message-ID'] || '—'}
Origin Client IP : ${originIp}
Origin Location  : ${originLocText || 'Undetermined'}
ISP / Network    : ${originProvider || '—'}

--------------------------------------------------------------------------------
2. AUTHENTICATION LEDGER
--------------------------------------------------------------------------------
SPF Status       : ${String(spf.status || 'unavailable').toUpperCase()} (Domain: ${spf.domain || '—'})
DKIM Signature   : ${String(dkim.status || 'unavailable').toUpperCase()} (Selector: ${dkim.selector || '—'})
DMARC Policy     : ${String(dmarc.status || 'unavailable').toUpperCase()} (Enforcement: ${String(dmarc.policy || 'none').toUpperCase()})
SPF Alignment    : ${dmarc.alignment_spf ? 'PASS' : 'FAIL'}
DKIM Alignment   : ${dmarc.alignment_dkim ? 'PASS' : 'FAIL'}

--------------------------------------------------------------------------------
3. RELAY PATH SEQUENCE (${relayPath.length} Hops)
--------------------------------------------------------------------------------
${relayPath.length > 0 ? relayPath.map((hop: any, i: number) => `[Hop ${hop.hop_number ?? i + 1}] Protocol: ${hop.protocol || 'ESMTP'} | IP: ${hop.ip || '—'} | Host: ${hop.hostname || hop.from_host || '—'} | Timestamp: ${hop.timestamp || '—'}`).join('\n') : 'No transmission hops recorded.'}

--------------------------------------------------------------------------------
4. EXTRACTED INDICATORS OF COMPROMISE (${iocs.length})
--------------------------------------------------------------------------------
${iocs.length > 0 ? iocs.map((ioc: any) => `[${String(ioc.type || 'IOC').toUpperCase()}] ${ioc.value || ''} (Risk: ${ioc.risk_score ?? 0}) - ${ioc.reason || 'Detected via pipeline'}`).join('\n') : 'Zero malicious indicators extracted.'}

--------------------------------------------------------------------------------
5. THREAT FINDINGS & ANALYST REMARKS
--------------------------------------------------------------------------------
${findings.map((f, i) => `${i + 1}. [${String(f.severity || 'INFO').toUpperCase()}] ${f.title}\n   ${f.detail}`).join('\n\n')}

================================================================================
END OF FORENSIC INTELLIGENCE REPORT · CLASSIFICATION: LAW ENFORCEMENT / SOC ONLY
================================================================================`;
}
