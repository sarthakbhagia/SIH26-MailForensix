import {
  ShieldCheck,
  Layers,
  Link2,
  FileCode2,
  Server,
  ArrowRight,
} from 'lucide-react';
import { FindingCard } from '@/components/forensics/FindingCard';
import { AuthPill } from '@/components/forensics/AuthPill';
import { cn } from '@/lib/utils';
import { getSeverityTokens, defangUrl, defangIp } from '@/lib/severity';

export interface OverviewSummaryProps {
  findings: Array<{ severity: string; category: string; title: string; detail: string; weight?: number }>;
  spf: any;
  dkim: any;
  dmarc: any;
  relayCount: number;
  iocCount: number;
  attachmentCount: number;
  topIocs: Array<{ type: string; value: string; risk_score: number }>;
  onSelectTab: (tab: string) => void;
}

export function OverviewSummary({
  findings,
  spf,
  dkim,
  dmarc,
  relayCount,
  iocCount,
  attachmentCount,
  topIocs = [],
  onSelectTab,
}: OverviewSummaryProps) {
  const isAligned = Boolean(dmarc?.alignment_spf || dmarc?.alignment_dkim);
  const alignmentStatus = isAligned ? 'PASS' : (dmarc?.alignment_spf === false && dmarc?.alignment_dkim === false ? 'FAIL' : 'UNAVAILABLE');

  return (
    <div className="space-y-4">
      {/* 1. Authentication Status Strip */}
      <div className="panel p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-border/50 pb-2.5">
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
              Authentication Protocol Verification
            </h3>
            <p className="label-mono text-[9px]">SPF · DKIM · DMARC · IDENTITY ALIGNMENT</p>
          </div>

          <button
            onClick={() => onSelectTab('auth')}
            className="inline-flex items-center gap-1 font-mono text-[11px] text-primary hover:underline"
          >
            <span>Deep Auth Ledger</span>
            <ArrowRight className="size-3" />
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          <AuthPill
            protocol="SPF"
            status={spf?.status || 'none'}
            domain={spf?.domain || undefined}
            details={spf?.details || (spf?.ip ? `Sender IP ${spf.ip}` : undefined)}
          />
          <AuthPill
            protocol="DKIM"
            status={dkim?.status || 'none'}
            domain={dkim?.domain || undefined}
            details={dkim?.details || (dkim?.selector ? `Selector: ${dkim.selector}` : undefined)}
          />
          <AuthPill
            protocol="DMARC"
            status={dmarc?.status || 'none'}
            domain={dmarc?.domain || undefined}
            details={dmarc?.details || (dmarc?.policy ? `Enforcement: ${dmarc.policy.toUpperCase()}` : undefined)}
          />
          <AuthPill
            protocol="ALIGNMENT"
            status={alignmentStatus}
            domain={dmarc?.domain || spf?.domain || undefined}
            details={`SPF: ${dmarc?.alignment_spf ? 'PASS' : 'FAIL'} · DKIM: ${dmarc?.alignment_dkim ? 'PASS' : 'FAIL'}`}
          />
        </div>
      </div>

      {/* 2. Primary Evidence Grid: Threat Findings vs Quick Telemetry Ledger */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
        {/* Left Column: Key Threat Findings (7 cols) */}
        <div className="lg:col-span-7 panel p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-border/50 pb-2.5">
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                Forensic Threat Findings ({findings.length})
              </h3>
              <p className="label-mono text-[9px]">HEURISTIC, AUTHENTICATION & NLP ANOMALIES</p>
            </div>
            <span className="label-mono text-[10px]">{findings.length} findings logged</span>
          </div>

          <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
            {findings.length === 0 ? (
              <div className="p-8 text-center text-muted-foreground">
                <ShieldCheck className="size-8 text-clean mx-auto mb-2 opacity-70" />
                <p className="text-xs font-semibold text-foreground">No critical threat vectors logged</p>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  Message complies with standard authentication, relay routing, and content heuristics.
                </p>
              </div>
            ) : (
              findings.map((f, idx) => (
                <FindingCard
                  key={idx}
                  severity={f.severity}
                  category={f.category}
                  title={f.title}
                  detail={f.detail}
                  weight={f.weight}
                />
              ))
            )}
          </div>
        </div>

        {/* Right Column: Key Forensic Indicators & Pivots (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          {/* IOC Snapshot Panel */}
          <div className="panel p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-border/50 pb-2">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                Extracted IOCs ({iocCount})
              </h4>
              <button
                onClick={() => onSelectTab('iocs')}
                className="inline-flex items-center gap-1 font-mono text-[11px] text-primary hover:underline"
              >
                <span>View All</span>
                <ArrowRight className="size-3" />
              </button>
            </div>

            {topIocs.length === 0 ? (
              <p className="text-xs text-muted-foreground py-2 text-center font-mono">
                No active indicators of compromise extracted.
              </p>
            ) : (
              <div className="space-y-1.5">
                {topIocs.slice(0, 4).map((ioc, i) => {
                  const tokens = getSeverityTokens(ioc.risk_score);
                  const displayVal = ioc.type.toUpperCase() === 'URL' ? defangUrl(ioc.value) : ioc.type.toUpperCase() === 'IP' ? defangIp(ioc.value) : ioc.value;
                  return (
                    <div
                      key={i}
                      className="p-2 rounded bg-surface-2 border border-border flex items-center justify-between gap-2 text-xs font-mono"
                    >
                      <div className="truncate min-w-0">
                        <span className="label-mono text-[9px] block text-muted-foreground">{ioc.type}</span>
                        <span className="font-semibold text-foreground truncate block select-all" title={ioc.value}>
                          {displayVal}
                        </span>
                      </div>
                      <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-bold border tabular-nums shrink-0', tokens.badgeClass)}>
                        {ioc.risk_score}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Quick Domain Navigation Pivots */}
          <div className="panel p-4 space-y-2.5">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground border-b border-border/50 pb-2">
              Investigation Modules
            </h4>

            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              <button
                onClick={() => onSelectTab('relay')}
                className="p-2.5 rounded bg-surface-2 hover:bg-surface-3 border border-border text-left transition-colors flex flex-col justify-between"
              >
                <div className="flex items-center justify-between">
                  <span className="label-mono text-[9px]">RELAY HOPS</span>
                  <Layers className="size-3.5 text-primary" />
                </div>
                <span className="font-bold text-foreground mt-1">{relayCount} Recorded</span>
              </button>

              <button
                onClick={() => onSelectTab('attachments')}
                className="p-2.5 rounded bg-surface-2 hover:bg-surface-3 border border-border text-left transition-colors flex flex-col justify-between"
              >
                <div className="flex items-center justify-between">
                  <span className="label-mono text-[9px]">ATTACHMENTS</span>
                  <FileCode2 className="size-3.5 text-accent" />
                </div>
                <span className="font-bold text-foreground mt-1">{attachmentCount} Files</span>
              </button>

              <button
                onClick={() => onSelectTab('headers')}
                className="p-2.5 rounded bg-surface-2 hover:bg-surface-3 border border-border text-left transition-colors flex flex-col justify-between"
              >
                <div className="flex items-center justify-between">
                  <span className="label-mono text-[9px]">RFC-822</span>
                  <Server className="size-3.5 text-clean" />
                </div>
                <span className="font-bold text-foreground mt-1">Header Grid</span>
              </button>

              <button
                onClick={() => onSelectTab('body')}
                className="p-2.5 rounded bg-surface-2 hover:bg-surface-3 border border-border text-left transition-colors flex flex-col justify-between"
              >
                <div className="flex items-center justify-between">
                  <span className="label-mono text-[9px]">PAYLOAD</span>
                  <Link2 className="size-3.5 text-high" />
                </div>
                <span className="font-bold text-foreground mt-1">Body Text</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default OverviewSummary;
