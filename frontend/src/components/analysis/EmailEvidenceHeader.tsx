import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Share2,
  MapPin,
  FolderPlus,
  Copy,
  Check,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Download,
  FileCheck2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';

import { getSeverityTokens } from '@/lib/severity';
import { cn, safeFormatDate } from '@/lib/utils';

export interface EmailEvidenceHeaderProps {
  emailId: string;
  subject?: string;
  sender?: string;
  recipients?: string;
  ingestedAt?: string;
  status?: string;
  riskScore: number;
  verdict: string;
  attributionCategory?: string;
  attributionConfidence?: number | null;
  originIp?: string;
  originLocation?: string;
  onExportPdf?: () => void;
  onExportJson?: () => void;
  isExportingPdf?: boolean;
}

export function EmailEvidenceHeader({
  emailId,
  subject,
  sender,
  recipients,
  ingestedAt,
  status = 'analyzed',
  riskScore,
  verdict,
  attributionCategory,
  attributionConfidence,
  originIp,
  originLocation,
  onExportPdf,
  isExportingPdf = false,
}: EmailEvidenceHeaderProps) {
  const navigate = useNavigate();
  const [copiedId, setCopiedId] = useState(false);
  const tokens = getSeverityTokens(riskScore, verdict);

  const handleCopyId = () => {
    navigator.clipboard.writeText(emailId);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 1800);
  };

  const handleBack = () => {
    if (window.history.length > 1) {
      navigate(-1);
    } else {
      navigate('/ingest');
    }
  };

  return (
    <div className="panel p-4 sm:p-5 space-y-4">
      {/* Top Metadata Strip & Action Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/50 pb-3">
        {/* Left: Return & Identification */}
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleBack}
            className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border hover:bg-surface-2"
            title="Return to Previous Screen"
          >
            <ArrowLeft className="size-3.5" />
            <span>Back</span>
          </Button>

          {/* Envelope ID Chip */}
          <button
            onClick={handleCopyId}
            className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border border-border bg-surface-2 hover:bg-surface-3 text-[10px] font-mono text-muted-foreground hover:text-foreground transition-colors"
            title="Copy Evidence Identifier"
          >
            <span>ID: {emailId.substring(0, 12)}…</span>
            {copiedId ? <Check className="size-3 text-clean" /> : <Copy className="size-3" />}
          </button>

          {/* Status Badge */}
          <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-surface-2 border border-border text-foreground/80 uppercase">
            ● {status}
          </span>

          {ingestedAt && (
            <span className="label-mono text-[10px] hidden md:inline-block">
              Ingested: {safeFormatDate(ingestedAt)}
            </span>
          )}
        </div>

        {/* Right: Rapid Investigation Pivot Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate(`/map?emailId=${emailId}`)}
            className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border hover:bg-surface-2 text-foreground"
            title="Inspect MTA Relay Geolocation"
          >
            <MapPin className="size-3 text-accent" />
            <span>Trace Map</span>
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate(`/graph?emailId=${emailId}`)}
            className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border hover:bg-surface-2 text-foreground"
            title="Explore IOC Threat Actor Graph"
          >
            <Share2 className="size-3 text-primary" />
            <span>Threat Graph</span>
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate(`/cases?new=true&emailId=${emailId}&title=${encodeURIComponent(subject || 'Suspicious Email Investigation')}`)}
            className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border hover:bg-surface-2 text-foreground"
            title="Promote / Attach to Case"
          >
            <FolderPlus className="size-3 text-muted-foreground" />
            <span>Attach Case</span>
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate(`/reports?emailId=${emailId}`)}
            className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border hover:bg-surface-2 text-foreground"
            title="Inspect and Export Forensic Report Dossier"
          >
            <FileCheck2 className="size-3 text-purple-400" />
            <span>Report Dossier</span>
          </Button>

          {onExportPdf && (
            <Button
              size="sm"
              disabled={isExportingPdf}
              onClick={onExportPdf}
              className="h-7 px-2.5 text-xs font-mono gap-1.5 font-semibold bg-primary text-primary-foreground hover:bg-primary/90"
              title="Quick Download Forensic PDF"
            >
              <Download className="size-3" />
              <span>{isExportingPdf ? 'Exporting…' : 'Quick PDF'}</span>
            </Button>
          )}
        </div>
      </div>

      {/* Main Identity & Verdict Section */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        {/* Left: Subject & Core Telemetry Metadata */}
        <div className="space-y-2.5 min-w-0 flex-1">
          {/* Subject Line */}
          <div className="space-y-0.5">
            <span className="label-mono text-[9px]">EVIDENCE SUBJECT</span>
            <h1 className="text-lg sm:text-xl font-bold tracking-tight text-foreground break-words" title={subject}>
              {subject || '(No Subject Header)'}
            </h1>
          </div>

          {/* Metadata Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-2.5 pt-1 text-xs font-mono">
            <div className="p-2 rounded bg-surface-2 border border-border/70 min-w-0">
              <span className="label-mono text-[9px] block">FROM (SENDER)</span>
              <p className="font-semibold text-foreground truncate" title={sender}>
                {sender || 'Unknown Sender'}
              </p>
            </div>

            <div className="p-2 rounded bg-surface-2 border border-border/70 min-w-0">
              <span className="label-mono text-[9px] block">TO (RECIPIENT)</span>
              <p className="text-muted-foreground truncate" title={recipients}>
                {recipients || 'Undisclosed Recipients'}
              </p>
            </div>

            <div className="p-2 rounded bg-surface-2 border border-border/70 min-w-0">
              <span className="label-mono text-[9px] block">ATTRIBUTION</span>
              <p className="font-semibold text-accent truncate">
                {attributionCategory || 'Undetermined'}
                {attributionConfidence ? ` (${attributionConfidence}%)` : ''}
              </p>
            </div>

            <div className="p-2 rounded bg-surface-2 border border-border/70 min-w-0">
              <span className="label-mono text-[9px] block">ORIGIN TELEMETRY</span>
              <p className="text-foreground truncate" title={`${originIp} (${originLocation})`}>
                <span className="text-primary font-semibold">{originIp || '—'}</span>
                {originLocation ? ` · ${originLocation}` : ''}
              </p>
            </div>
          </div>
        </div>

        {/* Right: High-Density Verdict & Threat Risk Tile */}
        <div
          className={cn(
            'p-3.5 rounded border flex flex-row lg:flex-col items-center justify-between lg:justify-center gap-3 shrink-0 min-w-[200px] bg-surface-2/60',
            tokens.borderColor
          )}
        >
          <div className="flex items-center gap-2">
            {tokens.level === 'critical' ? (
              <ShieldAlert className="size-5 text-critical" />
            ) : tokens.level === 'high' || tokens.level === 'medium' ? (
              <AlertTriangle className="size-5 text-high" />
            ) : (
              <ShieldCheck className="size-5 text-clean" />
            )}
            <div>
              <span className="label-mono text-[9px] block">COMPOSITE THREAT SCORE</span>
              <span className={cn('text-2xl font-bold font-mono tracking-tight tabular-nums', tokens.textColor)}>
                {riskScore} <span className="text-xs text-muted-foreground font-normal">/ 100</span>
              </span>
            </div>
          </div>

          <div
            className={cn(
              'px-2.5 py-1 rounded font-mono text-[11px] font-bold uppercase tracking-wider border text-center',
              tokens.badgeClass
            )}
          >
            {verdict}
          </div>
        </div>
      </div>
    </div>
  );
}

export default EmailEvidenceHeader;
