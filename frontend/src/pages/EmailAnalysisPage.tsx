import { useState, useMemo } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useEmail } from '@/hooks/useEmails';
import { useAnalysis as useAnalysisHook, useReanalyzeEmail } from '@/hooks/useAnalysis';
import { AnalysisResult } from '@/types/analysis';
import { EmailDetail } from '@/types/email';
import { defaultVerdictForScore } from '@/components/forensics';
import { TraceMap, HopGeoItem } from '@/components/map/TraceMap';
import EmailEvidenceHeader from '@/components/analysis/EmailEvidenceHeader';
import OverviewSummary from '@/components/analysis/OverviewSummary';
import AuthenticationPanel from '@/components/analysis/AuthenticationPanel';
import RelayPathViewer from '@/components/analysis/RelayPathViewer';
import IOCTable from '@/components/analysis/IOCTable';
import HeaderInspector from '@/components/email/HeaderInspector';
import EmailBodyViewer from '@/components/analysis/EmailBodyViewer';
import AttachmentViewer from '@/components/analysis/AttachmentViewer';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import {
  ArrowLeft,
  FileCheck2,
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
  Paperclip,
  Loader2,
  RefreshCw,
  RotateCcw,
  CheckCircle2,
  Activity,
  Inbox,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { generateForensicDossierText, type ForensicDossierParams } from '@/lib/dossierGenerator';

// ============================================================================
// 1. Initial Loading Skeleton View
// ============================================================================
function EmailAnalysisLoadingSkeleton() {
  return (
    <div className="space-y-4 max-w-full pb-6 animate-pulse">
      <div className="h-36 bg-surface/50 rounded border border-border" />
      <div className="h-10 bg-surface/30 rounded border border-border" />
      <div className="h-96 bg-surface/40 rounded border border-border" />
    </div>
  );
}

// ============================================================================
// 2. Email Artifact Not Found (Hard 404)
// ============================================================================
function EmailAnalysisNotFound({ emailId, onBack }: { emailId?: string; onBack: () => void }) {
  return (
    <div className="panel p-8 text-center space-y-3 max-w-md mx-auto my-12 border-critical/40">
      <AlertTriangle className="size-8 text-critical mx-auto" />
      <h2 className="text-base font-bold text-foreground">Email Evidence Artifact Not Found</h2>
      <p className="text-xs text-muted-foreground">
        The requested email artifact with ID <code className="font-mono text-primary">{emailId}</code> could not be loaded from the ingestion datastore.
      </p>
      <Button onClick={onBack} variant="outline" size="sm" className="mt-4 gap-2 font-mono text-xs border-border">
        <ArrowLeft className="size-3.5" /> Return to Ingestion Ledger
      </Button>
    </div>
  );
}

// ============================================================================
// 3. Analysis In Progress State (Pending / Processing)
// ============================================================================
interface ProcessingViewProps {
  email: EmailDetail;
  status: string;
  isFetching: boolean;
  onRefresh: () => void;
  onBack: () => void;
}

function EmailAnalysisProcessingView({
  email,
  status,
  isFetching,
  onRefresh,
  onBack,
}: ProcessingViewProps) {
  return (
    <div className="space-y-4 max-w-full pb-8">
      {/* Envelope Metadata Card */}
      <div className="panel p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/50 pb-3">
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={onBack}
              className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border"
            >
              <ArrowLeft className="size-3.5" />
              <span>Ingest Ledger</span>
            </Button>
            <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/30 uppercase flex items-center gap-1.5">
              <span className="size-1.5 rounded-full bg-primary animate-pulse" />
              Pipeline Active: {status}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={onRefresh}
              className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border bg-surface hover:bg-surface-2"
              title="Force refresh analysis telemetry"
            >
              <RefreshCw className={cn('size-3', isFetching && 'animate-spin')} />
              <span>Refresh</span>
            </Button>
          </div>
        </div>

        <div className="space-y-1">
          <span className="label-mono text-[9px]">EVIDENCE SUBJECT</span>
          <h1 className="text-lg font-bold text-foreground truncate">
            {email.subject || '(No Subject Header)'}
          </h1>
          <p className="text-xs text-muted-foreground font-mono">
            From: <span className="text-foreground">{email.sender || 'Unknown Sender'}</span>
          </p>
        </div>
      </div>

      {/* Processing State Card */}
      <div className="panel p-8 sm:p-12 text-center space-y-6 max-w-2xl mx-auto border-primary/30 bg-surface/50 shadow-xl">
        <div className="size-16 rounded-full bg-primary/10 text-primary flex items-center justify-center mx-auto border border-primary/30 animate-pulse">
          <Loader2 className="size-8 animate-spin" />
        </div>

        <div className="space-y-2">
          <h2 className="text-base sm:text-lg font-bold text-foreground tracking-tight">
            Forensic Threat Analysis in Progress
          </h2>
          <p className="text-xs text-muted-foreground max-w-md mx-auto leading-relaxed">
            The automated forensic pipeline is executing deep header analysis, IP geolocation triangulation, NLP semantic threat classification, and IOC correlation.
          </p>
        </div>

        {/* Pipeline Stage Indicators */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-left text-xs font-mono max-w-lg mx-auto">
          <div className="p-2.5 rounded bg-surface-2 border border-border/80 flex items-center justify-between">
            <span className="text-foreground flex items-center gap-1.5">
              <CheckCircle2 className="size-3.5 text-clean" /> RFC-822 Envelope Parsing
            </span>
            <span className="text-[10px] text-clean font-bold">READY</span>
          </div>

          <div className="p-2.5 rounded bg-surface-2 border border-primary/40 flex items-center justify-between">
            <span className="text-foreground flex items-center gap-1.5">
              <Loader2 className="size-3.5 text-primary animate-spin" /> Authentication Ledger
            </span>
            <span className="text-[10px] text-primary font-bold animate-pulse">EVALUATING</span>
          </div>

          <div className="p-2.5 rounded bg-surface-2 border border-primary/40 flex items-center justify-between">
            <span className="text-foreground flex items-center gap-1.5">
              <Loader2 className="size-3.5 text-primary animate-spin" /> Relay Geo Triangulation
            </span>
            <span className="text-[10px] text-primary font-bold animate-pulse">ROUTING</span>
          </div>

          <div className="p-2.5 rounded bg-surface-2 border border-primary/40 flex items-center justify-between">
            <span className="text-foreground flex items-center gap-1.5">
              <Loader2 className="size-3.5 text-primary animate-spin" /> NLP Threat Classification
            </span>
            <span className="text-[10px] text-primary font-bold animate-pulse">SCORING</span>
          </div>
        </div>

        <div className="flex items-center justify-center gap-2 pt-2 text-[11px] font-mono text-muted-foreground">
          <Activity className="size-3 text-primary animate-pulse" />
          <span>Polling telemetry updates automatically every 2 seconds…</span>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// 4. Analysis Failure / Error State
// ============================================================================
interface ErrorViewProps {
  email: EmailDetail;
  emailId: string;
  errorMessage?: string | null;
  isReanalyzing: boolean;
  onRetry: () => void;
  onBack: () => void;
}

function EmailAnalysisErrorView({
  email,
  errorMessage,
  isReanalyzing,
  onRetry,
  onBack,
}: ErrorViewProps) {
  return (
    <div className="space-y-4 max-w-full pb-8">
      <div className="panel p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-border/50 pb-3">
          <Button
            variant="outline"
            size="sm"
            onClick={onBack}
            className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border"
          >
            <ArrowLeft className="size-3.5" />
            <span>Ingest Ledger</span>
          </Button>
          <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-critical/15 text-critical border border-critical/30 uppercase">
            Pipeline Error
          </span>
        </div>

        <div className="space-y-1">
          <span className="label-mono text-[9px]">EVIDENCE SUBJECT</span>
          <h1 className="text-lg font-bold text-foreground truncate">
            {email.subject || '(No Subject Header)'}
          </h1>
          <p className="text-xs text-muted-foreground font-mono">
            From: <span className="text-foreground">{email.sender || 'Unknown Sender'}</span>
          </p>
        </div>
      </div>

      <div className="panel p-8 text-center space-y-4 max-w-lg mx-auto border-critical/50 bg-surface/50 shadow-xl">
        <div className="size-14 rounded-full bg-critical/15 text-critical flex items-center justify-center mx-auto border border-critical/30">
          <AlertTriangle className="size-7" />
        </div>

        <div className="space-y-1.5">
          <h2 className="text-base font-bold text-foreground tracking-tight">
            Forensic Analysis Pipeline Encountered an Error
          </h2>
          <p className="text-xs text-muted-foreground">
            {errorMessage || 'The pipeline was unable to complete automated analysis for this email evidence artifact.'}
          </p>
        </div>

        <div className="flex flex-wrap items-center justify-center gap-2.5 pt-2 font-mono text-xs">
          <Button
            size="sm"
            disabled={isReanalyzing}
            onClick={onRetry}
            className="h-8 px-3 gap-1.5 bg-primary text-primary-foreground font-semibold"
          >
            {isReanalyzing ? <Loader2 className="size-3.5 animate-spin" /> : <RotateCcw className="size-3.5" />}
            <span>{isReanalyzing ? 'Queuing…' : 'Retry Analysis Pipeline'}</span>
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={onBack}
            className="h-8 px-3 gap-1.5 border-border"
          >
            <Inbox className="size-3.5" />
            <span>Return to Ingestion Ledger</span>
          </Button>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// 5. Complete / Ready State View (Autonomous Hook Lifecycle)
// ============================================================================
interface CompleteViewProps {
  email: EmailDetail;
  emailId: string;
  analysis?: AnalysisResult | null;
}

function EmailAnalysisCompleteView({ email, emailId, analysis }: CompleteViewProps) {
  const navigate = useNavigate();

  const [activeDomain, setActiveDomain] = useState<string>('overview');
  const [reportCopied, setReportCopied] = useState(false);
  const [isExportingPdf, setIsExportingPdf] = useState(false);
  const [isExportingJson, setIsExportingJson] = useState(false);

  const mAnalysis: AnalysisResult = analysis || {
    email_id: emailId,
    status: 'analyzed',
    composite_risk_score: email.risk_score ?? 0,
    attribution_category: 'Undetermined',
    attribution_confidence: null,
    risk_breakdown: {},
    relay_path: [],
    geo_data: [],
    iocs: [],
    nlp_result: null,
    auth_result: null,
  };

  const normalizeConfidence = (val?: number | null): number | null => {
    if (val === undefined || val === null || isNaN(Number(val))) return null;
    const num = Number(val);
    if (num <= 0) return null;
    if (num <= 1.0) return Math.round(num * 100);
    return Math.round(Math.min(num, 100));
  };

  const riskScore = Math.round(mAnalysis.composite_risk_score ?? email.risk_score ?? 0);
  const attributionCategory =
    mAnalysis.attribution_category ||
    (mAnalysis.nlp_result?.label ? mAnalysis.nlp_result.label : defaultVerdictForScore(riskScore));
  const attributionConfidence = normalizeConfidence(mAnalysis.attribution_confidence);

  const sender = email.sender || 'Unknown Sender';
  const senderDomain = typeof sender === 'string' && sender.includes('@') ? sender.split('@').pop() || '' : '';

  const recipients = useMemo(() => {
    if (!email.recipients) return 'Undisclosed Recipients';
    if (Array.isArray(email.recipients)) {
      return email.recipients.filter(Boolean).join(', ') || 'Undisclosed Recipients';
    }
    if (typeof email.recipients === 'string') {
      try {
        const parsed = JSON.parse(email.recipients);
        if (Array.isArray(parsed)) return parsed.filter(Boolean).join(', ') || 'Undisclosed Recipients';
      } catch {
        // Not JSON
      }
      return email.recipients;
    }
    return 'Undisclosed Recipients';
  }, [email.recipients]);

  const rawHeaders = (typeof email.headers === 'object' && email.headers !== null ? email.headers : {}) as Record<string, string>;
  const rawUrls = Array.isArray(email.urls) ? email.urls : [];
  const rawAttachments = Array.isArray(email.attachments) ? email.attachments : [];

  const authResult = (mAnalysis as any)?.auth_result || (mAnalysis as any)?.auth_status || {};
  const spf = {
    status: (authResult.spf_status || authResult.spf || 'unavailable') as any,
    domain: authResult.spf_domain || senderDomain || '',
    ip: authResult.spf_ip || mAnalysis.geo_data?.[0]?.ip || '',
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

  const relayPath = mAnalysis.relay_path || [];
  const originHop = relayPath[0];
  const originGeo = mAnalysis.geo_data?.[0] || originHop?.geo;

  const originLat = originGeo?.latitude ?? null;
  const originLon = originGeo?.longitude ?? null;
  const originLocText = originGeo
    ? `${originGeo.city ? `${originGeo.city}, ` : ''}${originGeo.country || originGeo.region || 'Unknown'}`
    : undefined;
  const originIp = originGeo?.ip || originHop?.ip || spf.ip || '—';
  const originProvider = originGeo?.isp || originGeo?.org || undefined;
  const originInfra =
    originGeo?.infrastructure_type ||
    (originGeo?.hosting ? 'hosting' : originGeo?.vpn ? 'vpn' : originGeo?.tor ? 'tor' : undefined);

  const geoHops: HopGeoItem[] = useMemo(() => {
    const list: HopGeoItem[] = [];
    (mAnalysis.geo_data || []).forEach((geo: any, idx: number) => {
      if (geo.latitude != null && geo.longitude != null && !isNaN(geo.latitude) && !isNaN(geo.longitude)) {
        list.push({
          index: idx,
          hop_number: idx + 1,
          latitude: geo.latitude,
          longitude: geo.longitude,
          ip: geo.ip || 'Unknown IP',
          country: geo.country,
          city: geo.city,
          org: geo.org || geo.isp,
          infrastructureType:
            geo.infrastructure_type ||
            (geo.tor ? 'tor_exit_node' : geo.vpn ? 'known_vpn' : geo.hosting ? 'hosting' : 'residential'),
          riskScore: geo.tor ? 95 : geo.vpn ? 70 : geo.hosting ? 45 : 15,
        });
      }
    });
    if (list.length === 0 && originLat != null && originLon != null && !isNaN(originLat) && !isNaN(originLon)) {
      list.push({
        index: 0,
        hop_number: 1,
        latitude: originLat,
        longitude: originLon,
        ip: originIp,
        country: originGeo?.country || 'Unknown',
        city: originGeo?.city || 'Unknown',
        org: originProvider,
        infrastructureType: originInfra || 'origin',
        riskScore: 25,
      });
    }
    return list;
  }, [mAnalysis.geo_data, originLat, originLon, originIp, originGeo, originProvider, originInfra]);

  const iocs = (mAnalysis.iocs || []).map((ioc: any) => ({
    type: ioc?.type || 'URL',
    value: ioc?.value || '',
    risk_score: ioc?.risk_score ?? 0,
    reason: ioc?.reason || '',
    source: ioc?.source || 'Pipeline Forensics',
  }));

  const findings: Array<{ severity: string; category: string; title: string; detail: string; weight?: number }> = [];

  if (mAnalysis.nlp_result && mAnalysis.nlp_result.label && mAnalysis.nlp_result.label.toLowerCase() !== 'legitimate') {
    const isCalibrated = Boolean(mAnalysis.nlp_result.confidence_calibrated);
    const rawConf = mAnalysis.nlp_result.confidence != null ? Number(mAnalysis.nlp_result.confidence) : null;
    const confPercent =
      rawConf != null && !isNaN(rawConf)
        ? rawConf <= 1.0 && rawConf > 0
          ? (rawConf * 100).toFixed(1)
          : rawConf.toFixed(1)
        : null;
    const confText =
      confPercent != null
        ? isCalibrated
          ? `Model confidence ${confPercent}% (calibrated)`
          : `Evidence score ${confPercent}% (uncalibrated)`
        : `Heuristic rule match`;

    findings.push({
      severity: riskScore >= 75 ? 'critical' : 'high',
      category: 'NLP Threat Detection',
      title: `Classification: ${mAnalysis.nlp_result.label}`,
      detail: `${confText}. Text semantic analysis identified characteristic behavioral indicators matching ${mAnalysis.nlp_result.label.toLowerCase()} campaigns.`,
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
      title: `DMARC Policy Rejection (${String(dmarc.policy || 'none').toUpperCase()})`,
      detail: `Domain alignment check failed for "${dmarc.domain || senderDomain}". Sending server violates published DMARC domain enforcement policy.`,
      weight: 30,
    });
  }

  if (originGeo && (originGeo.tor || originGeo.vpn || originGeo.hosting)) {
    const infraType = originGeo.tor
      ? 'Tor Exit Node'
      : originGeo.vpn
      ? 'Commercial VPN Gateway'
      : 'Data Center / Hosting Cloud';
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
      detail:
        riskScore > 30
          ? 'Low-severity heuristics triggered during automated ingestion.'
          : 'Message complies with standard authentication, relay routing, and content heuristics.',
    });
  }

  const handleDownloadPdf = async () => {
    try {
      setIsExportingPdf(true);
      const res = await api.getReportPdf(emailId);
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
      const res = await api.getReportJson(emailId);
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

  const dossierReportParams: ForensicDossierParams = useMemo(
    () => ({
      emailId,
      ingestedAt: email.ingested_at,
      status: email.status,
      riskScore,
      attributionCategory,
      attributionConfidence,
      subject: email.subject,
      sender,
      senderDomain,
      recipients,
      rawHeaders,
      originIp,
      originLocText,
      originProvider,
      spf,
      dkim,
      dmarc,
      relayPath,
      iocs,
      findings,
    }),
    [
      emailId,
      email.ingested_at,
      email.status,
      riskScore,
      attributionCategory,
      attributionConfidence,
      email.subject,
      sender,
      senderDomain,
      recipients,
      rawHeaders,
      originIp,
      originLocText,
      originProvider,
      spf,
      dkim,
      dmarc,
      relayPath,
      iocs,
      findings,
    ]
  );

  const reportText = useMemo(() => {
    if (activeDomain !== 'dossier') {
      return '';
    }
    return generateForensicDossierText(dossierReportParams);
  }, [activeDomain, dossierReportParams]);

  const handleCopyReport = () => {
    const textToCopy = reportText || generateForensicDossierText(dossierReportParams);
    navigator.clipboard.writeText(textToCopy);
    setReportCopied(true);
    setTimeout(() => setReportCopied(false), 2000);
  };

  const domainNavItems = [
    { id: 'overview', label: 'Overview', icon: Radio, count: undefined },
    { id: 'auth', label: 'Authentication', icon: ShieldAlert, count: undefined },
    { id: 'relay', label: 'Relay Trace', icon: Layers, count: relayPath.length },
    { id: 'geo', label: 'Geolocation', icon: Globe, count: undefined },
    { id: 'iocs', label: 'IOCs', icon: ShieldAlert, count: iocs.length },
    { id: 'body', label: 'Body & URLs', icon: FileText, count: rawUrls.length },
    { id: 'attachments', label: 'Attachments', icon: Paperclip, count: rawAttachments.length },
    { id: 'headers', label: 'Headers', icon: Server, count: Object.keys(rawHeaders).length },
    { id: 'dossier', label: 'Dossier Report', icon: FileCheck2, count: undefined },
  ];

  return (
    <div className="space-y-4 max-w-full pb-8">
      {/* Level 1: Dense Identity & Verdict Header */}
      <EmailEvidenceHeader
        emailId={emailId}
        subject={email.subject}
        sender={sender}
        recipients={recipients}
        ingestedAt={email.ingested_at}
        status={email.status}
        riskScore={riskScore}
        verdict={defaultVerdictForScore(riskScore)}
        attributionCategory={attributionCategory}
        attributionConfidence={attributionConfidence}
        originIp={originIp}
        originLocation={originLocText}
        onExportPdf={handleDownloadPdf}
        onExportJson={handleDownloadJson}
        isExportingPdf={isExportingPdf}
      />

      {/* Level 2: Investigation Domain Navigation Strip */}
      <div className="panel p-1.5 flex items-center justify-between gap-2 overflow-x-auto select-none border-border">
        <div className="flex items-center gap-1 min-w-full sm:min-w-0">
          {domainNavItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeDomain === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveDomain(item.id)}
                className={cn(
                  'flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono tracking-wide transition-all shrink-0 cursor-pointer',
                  isActive
                    ? 'bg-primary text-primary-foreground font-bold shadow-sm'
                    : 'text-muted-foreground hover:text-foreground hover:bg-surface-2'
                )}
              >
                <Icon className="size-3.5" />
                <span>{item.label}</span>
                {item.count !== undefined && (
                  <span
                    className={cn(
                      'px-1.5 py-0.2 text-[9px] rounded font-bold',
                      isActive ? 'bg-black/25 text-white' : 'bg-surface-2 text-muted-foreground'
                    )}
                  >
                    {item.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Level 3: Active Evidence Domain Workspace */}
      <div className="space-y-4">
        {/* DOMAIN 1: OVERVIEW (30-Second Executive Summary) */}
        {activeDomain === 'overview' && (
          <OverviewSummary
            findings={findings}
            spf={spf}
            dkim={dkim}
            dmarc={dmarc}
            relayCount={relayPath.length}
            iocCount={iocs.length}
            attachmentCount={rawAttachments.length}
            topIocs={iocs}
            onSelectTab={setActiveDomain}
          />
        )}

        {/* DOMAIN 2: AUTHENTICATION */}
        {activeDomain === 'auth' && (
          <AuthenticationPanel spf={spf} dkim={dkim} dmarc={dmarc} />
        )}

        {/* DOMAIN 3: RELAY PATH */}
        {activeDomain === 'relay' && (
          <RelayPathViewer hops={relayPath} emailId={emailId} />
        )}

        {/* DOMAIN 4: GEOLOCATION */}
        {activeDomain === 'geo' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-border/50 pb-2.5">
              <div>
                <h3 className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                  <Globe className="size-4 text-primary" />
                  Origin Geolocation & Transmission Path
                </h3>
                <p className="label-mono text-[10px]">MTA TRANSMISSION ROUTING & SATELLITE TRIANGULATION</p>
              </div>

              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate(`/map?emailId=${emailId}`)}
                className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border"
              >
                <span>Full Map Explorer</span>
                <ExternalLink className="size-3" />
              </Button>
            </div>

            <div className="h-[460px] rounded border border-border overflow-hidden">
              <TraceMap hops={geoHops} />
            </div>
          </div>
        )}

        {/* DOMAIN 5: INDICATORS OF COMPROMISE */}
        {activeDomain === 'iocs' && (
          <IOCTable iocs={iocs} emailId={emailId} />
        )}

        {/* DOMAIN 6: BODY & URLS */}
        {activeDomain === 'body' && (
          <EmailBodyViewer
            bodyText={email.body_text}
            bodyHtml={email.body_html}
            urls={rawUrls}
          />
        )}

        {/* DOMAIN 7: ATTACHMENTS */}
        {activeDomain === 'attachments' && (
          <AttachmentViewer attachments={rawAttachments} />
        )}

        {/* DOMAIN 8: HEADER INSPECTOR */}
        {activeDomain === 'headers' && (
          <HeaderInspector headers={rawHeaders} />
        )}

        {/* DOMAIN 9: DOSSIER REPORT */}
        {activeDomain === 'dossier' && (
          <div className="panel p-4 sm:p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/50 pb-3">
              <div>
                <h3 className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                  <FileText className="size-4 text-primary" />
                  Cryptographic Forensic Threat Dossier
                </h3>
                <p className="label-mono text-[10px]">RAW EVIDENTIARY MONOSPACE ARTIFACT & EXPORT CONTROLS</p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCopyReport}
                  className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border"
                >
                  {reportCopied ? <Check className="size-3 text-clean" /> : <Copy className="size-3" />}
                  <span>{reportCopied ? 'Copied' : 'Copy Text'}</span>
                </Button>

                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleDownloadJson}
                  disabled={isExportingJson}
                  className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border"
                >
                  <Download className="size-3" />
                  <span>JSON</span>
                </Button>

                <Button
                  size="sm"
                  onClick={handleDownloadPdf}
                  disabled={isExportingPdf}
                  className="h-7 px-2.5 text-xs font-mono gap-1.5 bg-primary text-primary-foreground font-semibold"
                >
                  <Download className="size-3" />
                  <span>{isExportingPdf ? 'Exporting…' : 'PDF Report'}</span>
                </Button>

                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => navigate(`/reports?emailId=${emailId}`)}
                  className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border"
                >
                  <ExternalLink className="size-3" />
                  <span>A4 Console</span>
                </Button>
              </div>
            </div>

            <div className="rounded border border-border bg-background p-4 overflow-hidden">
              <pre className="font-mono text-xs text-foreground/90 leading-relaxed whitespace-pre-wrap max-h-[550px] overflow-y-auto select-all">
                {reportText}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Main Page Orchestrator (Zero Conditional Hook Violations)
// ============================================================================
export default function EmailAnalysisPage() {
  const navigate = useNavigate();
  const { emailId } = useParams<{ emailId: string }>();
  const { data: email, isLoading: emailLoading, isError: emailError } = useEmail(emailId!);
  const {
    data: analysis,
    isLoading: analysisLoading,
    isError: analysisError,
    error: analysisErrorObj,
    refetch: refetchAnalysis,
    isFetching: analysisFetching,
  } = useAnalysisHook(emailId!);
  const { mutate: reanalyze, isPending: isReanalyzing } = useReanalyzeEmail();

  if (emailLoading || (analysisLoading && !analysis && !emailError)) {
    return <EmailAnalysisLoadingSkeleton />;
  }

  if (emailError || !email) {
    return <EmailAnalysisNotFound emailId={emailId} onBack={() => navigate('/ingest')} />;
  }

  const analysisStatus = analysis?.status || (email.status ? String(email.status) : 'pending');
  const isPendingOrProcessing = analysisStatus === 'pending' || analysisStatus === 'processing';
  const isFailed = analysisStatus === 'error' || (analysisError && !analysis);

  if (isPendingOrProcessing) {
    return (
      <EmailAnalysisProcessingView
        email={email}
        status={analysisStatus}
        isFetching={analysisFetching}
        onRefresh={() => refetchAnalysis()}
        onBack={() => navigate('/ingest')}
      />
    );
  }

  if (isFailed) {
    return (
      <EmailAnalysisErrorView
        email={email}
        emailId={emailId!}
        errorMessage={
          analysis?.error_message ||
          (analysisErrorObj as any)?.message ||
          'The pipeline was unable to complete automated analysis for this email evidence artifact.'
        }
        isReanalyzing={isReanalyzing}
        onRetry={() => reanalyze(emailId!)}
        onBack={() => navigate('/ingest')}
      />
    );
  }

  return (
    <EmailAnalysisCompleteView
      email={email}
      emailId={emailId!}
      analysis={analysis}
    />
  );
}
