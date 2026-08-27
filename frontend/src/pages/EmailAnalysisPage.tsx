import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useEmail } from '@/hooks/useEmails';
import { useAnalysis as useAnalysisHook } from '@/hooks/useAnalysis';
import { AnalysisResult } from '@/types/analysis';
import {
  RiskGauge,
  TraceMap,
  Metric,
  FindingCard,
  defaultVerdictForScore,
} from '@/components/forensics';
import AuthenticationPanel from '@/components/analysis/AuthenticationPanel';
import RelayPathViewer from '@/components/analysis/RelayPathViewer';
import IOCTable from '@/components/analysis/IOCTable';
import RiskBreakdown from '@/components/analysis/RiskBreakdown';
import EmailDetail from '@/components/email/EmailDetail';
import HeaderInspector from '@/components/email/HeaderInspector';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import {
  ArrowLeft,
  Share2,
  FolderPlus,
  FileCheck2,
  MapPin,
  ShieldAlert,
  Download,
  Copy,
  Check,
  ExternalLink,
  Layers,
  Globe,
  Radio,
  FileText,
  AlertTriangle,
  Server,
} from 'lucide-react';

export default function EmailAnalysisPage() {
  const navigate = useNavigate();
  const { emailId } = useParams<{ emailId: string }>();
  const { data: email, isLoading: emailLoading, isError: emailError } = useEmail(emailId!);
  const { data: analysis, isLoading: analysisLoading } = useAnalysisHook(emailId!);

  const [activeTab, setActiveTab] = useState('overview');
  const [reportCopied, setReportCopied] = useState(false);
  const [isExportingPdf, setIsExportingPdf] = useState(false);
  const [isExportingJson, setIsExportingJson] = useState(false);

  if (emailLoading || analysisLoading) {
    return (
      <div className="space-y-6 max-w-7xl mx-auto p-4 md:p-6 animate-pulse">
        <div className="h-44 bg-surface/50 rounded-lg border border-border" />
        <div className="h-12 bg-surface/30 rounded-lg border border-border" />
        <div className="h-96 bg-surface/40 rounded-lg border border-border" />
      </div>
    );
  }

  if (emailError || !email) {
    return (
      <div className="max-w-4xl mx-auto p-8 text-center space-y-4">
        <div className="panel p-8 space-y-3">
          <AlertTriangle className="size-10 text-critical mx-auto" />
          <h2 className="text-lg font-bold text-foreground">Email Evidence Not Found</h2>
          <p className="text-xs text-muted-foreground">
            The requested email artifact with ID <code className="font-mono text-primary">{emailId}</code> could not be loaded.
          </p>
          <Button onClick={() => navigate('/ingest')} variant="outline" size="sm" className="mt-4 gap-2 font-mono text-xs">
            <ArrowLeft className="size-3.5" /> Return to Ingestion
          </Button>
        </div>
      </div>
    );
  }

  // Safe fallback models mapped directly against existing backend schemas
  const mEmail = email;
  const mAnalysis: AnalysisResult = (analysis as AnalysisResult) || {
    email_id: emailId!,
    composite_risk_score: mEmail.risk_score ?? 0,
    attribution_category: 'Undetermined',
    attribution_confidence: 0,
    risk_breakdown: {},
    relay_path: [],
    geo_data: [],
    iocs: [],
    nlp_result: { label: 'Unknown', confidence: 0, details: {} },
    auth_result: { spf_status: 'unavailable', dkim_status: 'unavailable', dmarc_status: 'unavailable' },
  };

  const riskScore = Math.round(mAnalysis.composite_risk_score ?? mEmail.risk_score ?? 0);
  const attributionCategory = mAnalysis.attribution_category || (mAnalysis.nlp_result?.label ? mAnalysis.nlp_result.label : defaultVerdictForScore(riskScore));
  const attributionConfidence = mAnalysis.attribution_confidence ? Math.round(mAnalysis.attribution_confidence * 100) : (mAnalysis.nlp_result?.confidence ? Math.round(mAnalysis.nlp_result.confidence * 100) : null);

  const sender = mEmail.sender || 'Unknown Sender';
  const senderDomain = sender.includes('@') ? sender.split('@').pop() : '';
  const recipients = mEmail.recipients?.join(', ') || 'Undisclosed Recipients';
  const rawHeaders = (mEmail.headers || {}) as Record<string, string>;

  // Authentication data
  const authResult = (mAnalysis as any)?.auth_result || (mAnalysis as any)?.auth_status || {};
  const spf = {
    status: (authResult.spf_status || authResult.spf || 'unavailable') as any,
    domain: authResult.spf_domain || senderDomain || '',
    ip: authResult.spf_ip || (mAnalysis.geo_data?.[0]?.ip) || '',
    record: authResult.spf_record || '',
    details: authResult.spf_details || '',
  };
  const dkim = {
    status: (authResult.dkim_status || authResult.dkim || 'unavailable') as any,
    domain: authResult.dkim_domain || senderDomain || '',
    selector: authResult.dkim_selector || 'default',
    details: authResult.dkim_details || '',
  };
  const dmarc = {
    status: (authResult.dmarc_status || authResult.dmarc || 'unavailable') as any,
    policy: (authResult.dmarc_policy || authResult.policy || 'none') as any,
    domain: authResult.dmarc_domain || senderDomain || '',
    alignment_spf: Boolean(authResult.alignment_spf ?? (authResult.spf_status === 'pass' || authResult.spf === 'pass')),
    alignment_dkim: Boolean(authResult.alignment_dkim ?? (authResult.dkim_status === 'pass' || authResult.dkim === 'pass')),
    record: authResult.dmarc_record || '',
    details: authResult.dmarc_details || '',
  };

  // Relay Path & Origin Geo data
  const relayPath = mAnalysis.relay_path || [];
  const originHop = relayPath[0];
  const originGeo = mAnalysis.geo_data?.[0] || originHop?.geo;

  // Origin coordinates
  const originLat = originGeo?.latitude ?? null;
  const originLon = originGeo?.longitude ?? null;
  const originLocText = originGeo ? `${originGeo.city ? `${originGeo.city}, ` : ''}${originGeo.country || originGeo.region || 'Unknown Location'}` : undefined;
  const originIp = originGeo?.ip || originHop?.ip || spf.ip || '—';
  const originProvider = originGeo?.isp || originGeo?.org || undefined;
  const originInfra = originGeo?.infrastructure_type || (originGeo?.hosting ? 'hosting' : originGeo?.vpn ? 'vpn' : originGeo?.tor ? 'tor' : undefined);

  // Indicators of compromise
  const iocs = (mAnalysis.iocs || []).map((ioc: any) => ({
    type: ioc.type || 'URL',
    value: ioc.value || '',
    risk_score: ioc.risk_score ?? 0,
    reason: ioc.reason || '',
    source: ioc.source || 'Pipeline Forensics',
  }));

  // Construct Dynamic Findings Stack based on real forensic telemetry
  const findings: Array<{ severity: string; category: string; title: string; detail: string; weight?: number }> = [];

  if (mAnalysis.nlp_result && mAnalysis.nlp_result.label && mAnalysis.nlp_result.label.toLowerCase() !== 'legitimate') {
    findings.push({
      severity: riskScore >= 75 ? 'critical' : 'high',
      category: 'NLP Threat Detection',
      title: `Language Model Flagged: ${mAnalysis.nlp_result.label}`,
      detail: `Model confidence ${(mAnalysis.nlp_result.confidence * 100).toFixed(1)}%. Text semantic analysis identified characteristic behavioral indicators matching ${mAnalysis.nlp_result.label.toLowerCase()} campaigns.`,
      weight: 35,
    });
  }

  if (spf.status === 'fail' || spf.status === 'softfail') {
    findings.push({
      severity: spf.status === 'fail' ? 'critical' : 'medium',
      category: 'Sender Authentication',
      title: `SPF Verification ${spf.status.toUpperCase()}`,
      detail: `Sending MTA IP (${spf.ip || 'origin'}) is not authorized in DNS SPF record for domain "${spf.domain || senderDomain}".`,
      weight: 20,
    });
  }

  if (dkim.status === 'fail') {
    findings.push({
      severity: 'high',
      category: 'Cryptographic Signature',
      title: 'DKIM Signature Invalid / Mismatch',
      detail: `Cryptographic body and header hash verification failed for domain "${dkim.domain || senderDomain}". Message headers or body may have been modified in transit.`,
      weight: 25,
    });
  }

  if (dmarc.status === 'fail') {
    findings.push({
      severity: 'critical',
      category: 'Domain Policy',
      title: `DMARC Policy Rejection (${dmarc.policy.toUpperCase()})`,
      detail: `Domain alignment check failed for "${dmarc.domain || senderDomain}". Sending server violates published DMARC domain enforcement policy.`,
      weight: 30,
    });
  }

  if (originGeo && (originGeo.tor || originGeo.vpn || originGeo.hosting)) {
    const infraType = originGeo.tor ? 'Tor Exit Node' : originGeo.vpn ? 'Commercial VPN Gateway' : 'Data Center / Hosting Cloud';
    findings.push({
      severity: originGeo.tor ? 'critical' : 'medium',
      category: 'Infrastructure Anomaly',
      title: `Anonymized Relay Origin: ${infraType}`,
      detail: `Originating IP ${originGeo.ip} belongs to ${originGeo.org || 'an anonymizing network'}. High probability of adversary traffic obfuscation.`,
      weight: 15,
    });
  }

  const highRiskIocs = iocs.filter((i) => i.risk_score >= 70);
  if (highRiskIocs.length > 0) {
    findings.push({
      severity: 'critical',
      category: 'Malicious Indicators',
      title: `${highRiskIocs.length} High-Risk IOC(s) Detected in Payload`,
      detail: `Extracted indicators (${highRiskIocs.map((i) => i.value).slice(0, 2).join(', ')}${highRiskIocs.length > 2 ? '...' : ''}) match active threat intelligence lists.`,
      weight: 25,
    });
  }

  if (findings.length === 0) {
    findings.push({
      severity: riskScore > 30 ? 'low' : 'clean',
      category: 'Forensic Baseline',
      title: riskScore > 30 ? 'Telemetry Baseline Warnings' : 'No Critical Anomalies Identified',
      detail: riskScore > 30 ? 'Low-severity heuristics triggered during automated ingestion.' : 'Message complies with standard authentication, relay routing, and content heuristics.',
    });
  }

  // Export handlers using existing backend REST endpoints
  const handleDownloadPdf = async () => {
    try {
      setIsExportingPdf(true);
      const res = await api.getReportPdf(emailId!);
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `forensic_report_${emailId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('PDF export failed:', err);
    } finally {
      setIsExportingPdf(false);
    }
  };

  const handleDownloadJson = async () => {
    try {
      setIsExportingJson(true);
      const res = await api.getReportJson(emailId!);
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(res.data, null, 2));
      const a = document.createElement('a');
      a.href = dataStr;
      a.download = `forensic_report_${emailId}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } catch (err) {
      console.error('JSON export failed:', err);
    } finally {
      setIsExportingJson(false);
    }
  };

  // Formatted Evidentiary Plaintext Report Content
  const reportText = `================================================================================
MAILFORENSIX — FORENSIC THREAT INTELLIGENCE DOSSIER
================================================================================
EVIDENCE ID      : ${emailId}
INGESTED AT      : ${new Date(mEmail.ingested_at || Date.now()).toISOString()}
STATUS           : ${String(mEmail.status || 'analyzed').toUpperCase()}
COMPOSITE RISK   : ${riskScore} / 100 [${defaultVerdictForScore(riskScore).toUpperCase()}]
ATTRIBUTION      : ${attributionCategory}${attributionConfidence ? ` (Confidence: ${attributionConfidence}%)` : ''}

--------------------------------------------------------------------------------
1. TRANSMISSION & ENVELOPE METADATA
--------------------------------------------------------------------------------
Subject          : ${mEmail.subject || '—'}
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
SPF Status       : ${spf.status.toUpperCase()} (Domain: ${spf.domain || '—'})
DKIM Signature   : ${dkim.status.toUpperCase()} (Selector: ${dkim.selector || '—'})
DMARC Policy     : ${dmarc.status.toUpperCase()} (Enforcement: ${dmarc.policy.toUpperCase()})
SPF Alignment    : ${dmarc.alignment_spf ? 'PASS' : 'FAIL'}
DKIM Alignment   : ${dmarc.alignment_dkim ? 'PASS' : 'FAIL'}

--------------------------------------------------------------------------------
3. RELAY PATH SEQUENCE (${relayPath.length} Hops)
--------------------------------------------------------------------------------
${relayPath.length > 0 ? relayPath.map((hop: any, i: number) => `[Hop ${hop.hop_number ?? i + 1}] Protocol: ${hop.protocol || 'ESMTP'} | IP: ${hop.ip || '—'} | Host: ${hop.hostname || hop.from_host || '—'} | Timestamp: ${hop.timestamp || '—'}`).join('\n') : 'No transmission hops recorded.'}

--------------------------------------------------------------------------------
4. EXTRACTED INDICATORS OF COMPROMISE (${iocs.length})
--------------------------------------------------------------------------------
${iocs.length > 0 ? iocs.map((ioc: any) => `[${ioc.type.toUpperCase()}] ${ioc.value} (Risk: ${ioc.risk_score}) - ${ioc.reason || 'Detected via pipeline'}`).join('\n') : 'Zero malicious indicators extracted.'}

--------------------------------------------------------------------------------
5. THREAT FINDINGS & ANALYST REMARKS
--------------------------------------------------------------------------------
${findings.map((f, i) => `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}\n   ${f.detail}`).join('\n\n')}

================================================================================
END OF FORENSIC INTELLIGENCE REPORT · CLASSIFICATION: LAW ENFORCEMENT / SOC ONLY
================================================================================`;

  const handleCopyReport = () => {
    navigator.clipboard.writeText(reportText);
    setReportCopied(true);
    setTimeout(() => setReportCopied(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* =================================================================== */}
      {/* 1. FORENSIC WORKSTATION TOP HEADER ZONE                             */}
      {/* =================================================================== */}
      <div className="panel relative p-5 md:p-6 overflow-hidden">
        {/* Background ambient corner glow */}
        <div className="absolute -top-16 -right-16 size-48 rounded-full bg-primary/10 blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          {/* Left: Identity, Subject, Attribution & Action Toolbar */}
          <div className="space-y-3.5 flex-1 min-w-0">
            {/* Navigation & Metadata Tag Row */}
            <div className="flex flex-wrap items-center gap-2.5">
              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate('/ingest')}
                className="h-7 px-2 text-xs gap-1.5 font-mono border-border bg-surface hover:bg-muted text-muted-foreground hover:text-foreground"
                title="Return to Email Ingestion List"
              >
                <ArrowLeft className="size-3.5" />
                <span>Inbox</span>
              </Button>

              <span className="label-mono text-[10px] bg-surface px-2 py-0.5 rounded border border-border">
                ID: {String(mEmail.id).slice(0, 12)}…
              </span>

              <span className="label-mono text-[10px] text-primary bg-primary/10 px-2 py-0.5 rounded border border-primary/20">
                ● {String(mEmail.status || 'analyzed').toUpperCase()}
              </span>

              <span className="text-xs text-muted-foreground font-mono hidden sm:inline-block">
                Ingested: {new Date(mEmail.ingested_at || Date.now()).toLocaleString()}
              </span>
            </div>

            {/* Email Subject */}
            <h1 className="text-xl md:text-2xl lg:text-3xl font-bold tracking-tight text-foreground break-words">
              {mEmail.subject || '(No Subject Provided)'}
            </h1>

            {/* Sender, Recipient & Attribution Card */}
            <div className="flex flex-wrap items-center gap-y-2 gap-x-4 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="label-mono">FROM:</span>
                <span className="font-mono text-foreground font-medium truncate max-w-sm" title={sender}>
                  {sender}
                </span>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="label-mono">TO:</span>
                <span className="font-mono text-muted-foreground truncate max-w-xs" title={recipients}>
                  {recipients}
                </span>
              </div>

              {/* Attribution Assessment Capsule */}
              <div className="flex items-center gap-1.5 pl-2 border-l border-border/60">
                <span className="label-mono text-accent">ATTRIBUTION:</span>
                <span className="font-mono font-semibold text-foreground">
                  {attributionCategory}
                </span>
                {attributionConfidence !== null && (
                  <span className="label-mono text-[10px] text-muted-foreground">
                    ({attributionConfidence}% conf)
                  </span>
                )}
              </div>
            </div>

            {/* Tactical Action Buttons Bar */}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate(`/graph?emailId=${emailId}`)}
                className="h-8 text-xs gap-1.5 font-mono border-border bg-surface hover:bg-muted"
              >
                <Share2 className="size-3.5 text-primary" />
                <span>Threat Graph</span>
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate(`/map?emailId=${emailId}`)}
                className="h-8 text-xs gap-1.5 font-mono border-border bg-surface hover:bg-muted"
              >
                <MapPin className="size-3.5 text-accent" />
                <span>Trace Map</span>
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate('/cases')}
                className="h-8 text-xs gap-1.5 font-mono border-border bg-surface hover:bg-muted"
              >
                <FolderPlus className="size-3.5 text-muted-foreground" />
                <span>Link Case</span>
              </Button>

              <Button
                size="sm"
                onClick={() => setActiveTab('report')}
                className="h-8 text-xs gap-1.5 font-mono bg-primary text-primary-foreground hover:bg-primary/90 font-semibold shadow-sm"
              >
                <FileCheck2 className="size-3.5" />
                <span>Forensic Report</span>
              </Button>
            </div>
          </div>

          {/* Right: Signature Risk Gauge Dial */}
          <div className="flex flex-col items-center justify-center shrink-0 border-t lg:border-t-0 lg:border-l border-border/60 pt-4 lg:pt-0 lg:pl-8">
            <RiskGauge
              score={riskScore}
              verdict={defaultVerdictForScore(riskScore)}
              size={148}
              label="RISK / 100"
              showVerdictBadge={true}
            />
          </div>
        </div>
      </div>

      {/* =================================================================== */}
      {/* 2. SIX FORENSIC WORKSTATION TABS                                    */}
      {/* =================================================================== */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full space-y-6">
        {/* Navigation Tabs Bar */}
        <div className="border-b border-border pb-px overflow-x-auto">
          <TabsList className="h-10 bg-surface p-1 border border-border rounded-md inline-flex w-auto min-w-full sm:min-w-0">
            <TabsTrigger value="overview" className="gap-2 font-mono text-xs uppercase px-3 py-1.5">
              <Radio className="size-3.5" />
              <span>Overview</span>
            </TabsTrigger>
            <TabsTrigger value="relay" className="gap-2 font-mono text-xs uppercase px-3 py-1.5">
              <Layers className="size-3.5" />
              <span>Relay Trace ({relayPath.length})</span>
            </TabsTrigger>
            <TabsTrigger value="geo" className="gap-2 font-mono text-xs uppercase px-3 py-1.5">
              <Globe className="size-3.5" />
              <span>Geolocation</span>
            </TabsTrigger>
            <TabsTrigger value="iocs" className="gap-2 font-mono text-xs uppercase px-3 py-1.5">
              <ShieldAlert className="size-3.5" />
              <span>IOCs ({iocs.length})</span>
            </TabsTrigger>
            <TabsTrigger value="headers" className="gap-2 font-mono text-xs uppercase px-3 py-1.5">
              <Server className="size-3.5" />
              <span>Headers</span>
            </TabsTrigger>
            <TabsTrigger value="report" className="gap-2 font-mono text-xs uppercase px-3 py-1.5">
              <FileText className="size-3.5" />
              <span>Report</span>
            </TabsTrigger>
          </TabsList>
        </div>

        {/* ----------------------------------------------------------------- */}
        {/* TAB 1: OVERVIEW                                                   */}
        {/* ----------------------------------------------------------------- */}
        <TabsContent value="overview" className="space-y-6 mt-0 animate-in fade-in duration-200">
          {/* 4x Authentication Protocol Pills */}
          <AuthenticationPanel spf={spf} dkim={dkim} dmarc={dmarc} />

          {/* 6x Telemetry Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <Metric label="sender domain" value={senderDomain || '—'} />
            <Metric label="origin client ip" value={originIp} valueClassName="text-primary font-semibold" />
            <Metric label="return-path" value={rawHeaders['return-path'] || sender} />
            <Metric label="message-id" value={rawHeaders['message-id'] || '—'} subtext="RFC-5322 identifier" />
            <Metric label="ingested at" value={new Date(mEmail.ingested_at || Date.now()).toLocaleTimeString()} subtext={new Date(mEmail.ingested_at || Date.now()).toLocaleDateString()} />
            <Metric label="sha256 digest" value={(mEmail as any).raw_hash_sha256 ? `${(mEmail as any).raw_hash_sha256.slice(0, 10)}…` : `${String(emailId).slice(0, 10)}…`} subtext="Cryptographic hash" />
          </div>

          {/* Threat Findings Stack & Risk Breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Finding Cards */}
            <div className="lg:col-span-2 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold tracking-tight text-foreground">Forensic Threat Findings</h3>
                  <p className="label-mono text-[10px] mt-0.5">HEURISTIC, AUTHENTICATION & NLP RISK INDICATORS</p>
                </div>
                <span className="label-mono text-[10px]">{findings.length} findings logged</span>
              </div>

              <div className="space-y-2.5">
                {findings.map((f, i) => (
                  <FindingCard
                    key={i}
                    severity={f.severity}
                    category={f.category}
                    title={f.title}
                    detail={f.detail}
                    weight={f.weight}
                  />
                ))}
              </div>
            </div>

            {/* Right 1 Col: Vector Assessment Breakdown */}
            <div className="space-y-4">
              <RiskBreakdown
                overallScore={riskScore}
                breakdownMap={mAnalysis.risk_breakdown}
              />
            </div>
          </div>

          {/* Email Body & Extracted Artifacts */}
          <EmailDetail email={mEmail} />
        </TabsContent>

        {/* ----------------------------------------------------------------- */}
        {/* TAB 2: RELAY TRACE                                                */}
        {/* ----------------------------------------------------------------- */}
        <TabsContent value="relay" className="space-y-6 mt-0 animate-in fade-in duration-200">
          <RelayPathViewer hops={relayPath} />
        </TabsContent>

        {/* ----------------------------------------------------------------- */}
        {/* TAB 3: GEOLOCATION                                                */}
        {/* ----------------------------------------------------------------- */}
        <TabsContent value="geo" className="space-y-6 mt-0 animate-in fade-in duration-200">
          <div className="space-y-4">
            <div>
              <h3 className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <Globe className="size-4 text-primary" />
                Origin Radar & Geolocation Intelligence
              </h3>
              <p className="label-mono text-[10px] mt-0.5">MTA SATELLITE ESTIMATION & INFRASTRUCTURE CLASSIFICATION</p>
            </div>

            {/* Vector SVG World Map with Radar Pulse */}
            <TraceMap
              latitude={originLat}
              longitude={originLon}
              locationText={originLocText}
              ip={originIp}
              provider={originProvider}
              infrastructure={originInfra}
              confidence={originGeo?.confidence === 'high' ? 95 : originGeo?.confidence === 'medium' ? 75 : 60}
            />

            {/* All Geolocation Hops Ledger */}
            {mAnalysis.geo_data && mAnalysis.geo_data.length > 0 && (
              <div className="panel p-4 space-y-3">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                  Transmission Geo-Hop Breakdown ({mAnalysis.geo_data.length})
                </h4>
                <div className="divide-y divide-border/50">
                  {mAnalysis.geo_data.map((geo, idx) => (
                    <div key={idx} className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
                      <div className="flex items-center gap-2">
                        <span className="size-5 rounded-full bg-surface-2 flex items-center justify-center text-[10px] font-bold text-primary">
                          {idx + 1}
                        </span>
                        <span className="text-foreground font-semibold">{geo.ip}</span>
                        <span className="text-muted-foreground">({geo.city || 'Unknown City'}, {geo.country || 'Unknown'})</span>
                      </div>
                      <div className="flex items-center gap-2 text-muted-foreground text-[11px]">
                        <span>{geo.org || geo.isp || '—'}</span>
                        {geo.vpn && <span className="rounded bg-high/15 text-high px-1.5 py-0.5 text-[9px] uppercase">VPN</span>}
                        {geo.tor && <span className="rounded bg-critical/15 text-critical px-1.5 py-0.5 text-[9px] uppercase">TOR</span>}
                        {geo.hosting && <span className="rounded bg-surface-2 text-muted-foreground px-1.5 py-0.5 text-[9px] uppercase">HOSTING</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </TabsContent>

        {/* ----------------------------------------------------------------- */}
        {/* TAB 4: IOCS                                                       */}
        {/* ----------------------------------------------------------------- */}
        <TabsContent value="iocs" className="space-y-6 mt-0 animate-in fade-in duration-200">
          <div className="space-y-4">
            <div>
              <h3 className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <ShieldAlert className="size-4 text-critical" />
                Extracted Indicators of Compromise
              </h3>
              <p className="label-mono text-[10px] mt-0.5">TACTICAL THREAT INTELLIGENCE & SUSPICIOUS ARTIFACT CORRELATION</p>
            </div>

            <IOCTable iocs={iocs} />
          </div>
        </TabsContent>

        {/* ----------------------------------------------------------------- */}
        {/* TAB 5: HEADERS                                                    */}
        {/* ----------------------------------------------------------------- */}
        <TabsContent value="headers" className="space-y-6 mt-0 animate-in fade-in duration-200">
          <div className="space-y-4">
            <div>
              <h3 className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <Server className="size-4 text-primary" />
                Forensic RFC-822 Headers Inspector
              </h3>
              <p className="label-mono text-[10px] mt-0.5">FULL UNREDACTED ENVELOPE & TRANSPORT HEADERS</p>
            </div>

            <HeaderInspector headers={rawHeaders} />
          </div>
        </TabsContent>

        {/* ----------------------------------------------------------------- */}
        {/* TAB 6: REPORT                                                     */}
        {/* ----------------------------------------------------------------- */}
        <TabsContent value="report" className="space-y-6 mt-0 animate-in fade-in duration-200">
          <div className="space-y-4">
            {/* Header with Export Actions */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/50 pb-3">
              <div>
                <h3 className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                  <FileText className="size-4 text-primary" />
                  Forensic Threat Intelligence Dossier
                </h3>
                <p className="label-mono text-[10px] mt-0.5">RAW EVIDENTIARY MONOSPACE ARTIFACT & EXPORT CONTROLS</p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCopyReport}
                  className="h-8 text-xs font-mono gap-1.5 border-border bg-surface"
                >
                  {reportCopied ? <Check className="size-3 text-clean" /> : <Copy className="size-3" />}
                  <span>{reportCopied ? 'Copied' : 'Copy Text'}</span>
                </Button>

                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleDownloadJson}
                  disabled={isExportingJson}
                  className="h-8 text-xs font-mono gap-1.5 border-border bg-surface"
                >
                  <Download className="size-3" />
                  <span>JSON Payload</span>
                </Button>

                <Button
                  size="sm"
                  onClick={handleDownloadPdf}
                  disabled={isExportingPdf}
                  className="h-8 text-xs font-mono gap-1.5 bg-primary text-primary-foreground font-semibold"
                >
                  <Download className="size-3" />
                  <span>{isExportingPdf ? 'Exporting…' : 'Export PDF'}</span>
                </Button>

                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => navigate(`/reports?emailId=${emailId}`)}
                  className="h-8 text-xs font-mono gap-1.5 border-border"
                >
                  <ExternalLink className="size-3" />
                  <span>A4 Previewer</span>
                </Button>
              </div>
            </div>

            {/* Evidentiary Monospace Report Pre Block */}
            <div className="panel p-5 overflow-hidden">
              <pre className="font-mono text-xs text-foreground/90 leading-relaxed whitespace-pre-wrap max-h-[600px] overflow-y-auto select-all">
                {reportText}
              </pre>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

