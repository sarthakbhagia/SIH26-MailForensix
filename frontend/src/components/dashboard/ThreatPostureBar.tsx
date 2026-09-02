import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Upload,
  Briefcase,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { getSeverityTokens } from '@/lib/severity';

export interface ThreatPostureBarProps {
  avgRiskScore?: number;
  totalEmails?: number;
  threatsDetected?: number;
  unackAlerts?: number;
  activeCases?: number;
  isLoading?: boolean;
}

export function ThreatPostureBar({
  avgRiskScore = 0,
  unackAlerts = 0,
  activeCases = 0,
}: ThreatPostureBarProps) {
  const navigate = useNavigate();
  const tokens = getSeverityTokens(avgRiskScore);

  const getPostureTitle = (score: number) => {
    if (score >= 75) return 'CRITICAL THREAT POSTURE';
    if (score >= 50) return 'ELEVATED RISK LEVEL';
    if (score >= 25) return 'MODERATE ADVISORY LEVEL';
    return 'NOMINAL ENVIRONMENT STATUS';
  };

  const getPostureDescription = (score: number) => {
    if (score >= 75) {
      return 'High volume of critical/BEC vectors detected. Immediate triage and case escalation recommended.';
    }
    if (score >= 50) {
      return 'Elevated phishing and authentication mismatch anomalies observed across ingested traffic.';
    }
    if (score >= 25) {
      return 'Moderate suspicious activity detected; monitor ingestion feeds and verify anomalous headers.';
    }
    return 'All telemetry systems operating nominally with low threat density across monitored mail streams.';
  };

  return (
    <div
      className={cn(
        'panel p-4 sm:p-5 border-l-4 transition-all',
        tokens.level === 'critical'
          ? 'border-l-critical bg-surface'
          : tokens.level === 'high'
          ? 'border-l-high bg-surface'
          : tokens.level === 'medium'
          ? 'border-l-medium bg-surface'
          : 'border-l-clean bg-surface'
      )}
    >
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        {/* Left: Overall Threat Posture & Status */}
        <div className="flex items-start gap-3.5 min-w-0 flex-1">
          <div
            className={cn(
              'p-2.5 rounded border shrink-0 mt-0.5',
              tokens.level === 'critical'
                ? 'bg-critical/15 text-critical border-critical/35'
                : tokens.level === 'high'
                ? 'bg-high/15 text-high border-high/35'
                : tokens.level === 'medium'
                ? 'bg-medium/15 text-medium border-medium/35'
                : 'bg-clean/15 text-clean border-clean/35'
            )}
          >
            {tokens.level === 'critical' || tokens.level === 'high' ? (
              <ShieldAlert className="size-6" />
            ) : tokens.level === 'medium' ? (
              <AlertTriangle className="size-6" />
            ) : (
              <ShieldCheck className="size-6" />
            )}
          </div>

          <div className="space-y-1 min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className={cn('font-mono text-xs font-bold tracking-wider uppercase', tokens.textColor)}>
                {getPostureTitle(avgRiskScore)}
              </span>
              <span className="text-muted-foreground/50 text-xs">·</span>
              <span className={cn('font-mono text-[10px] font-bold px-2 py-0.5 rounded border tabular-nums', tokens.badgeClass)}>
                SCORE {avgRiskScore.toFixed(1)} / 100
              </span>
              {unackAlerts > 0 && (
                <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-critical/15 text-critical border border-critical/35 animate-pulse">
                  {unackAlerts} UNACKNOWLEDGED ALERTS
                </span>
              )}
            </div>

            <p className="text-xs text-muted-foreground leading-relaxed max-w-3xl">
              {getPostureDescription(avgRiskScore)}
            </p>
          </div>
        </div>

        {/* Right: Operational Metric Highlights & Quick Triage Pivots */}
        <div className="flex flex-wrap items-center gap-2 shrink-0 pt-3 lg:pt-0 border-t lg:border-t-0 border-border/40">
          <div className="flex items-center gap-2 text-xs font-mono pr-2 border-r border-border/40 hidden sm:flex">
            <div className="px-2.5 py-1 rounded bg-surface-2 border border-border">
              <span className="label-mono text-[9px] block">ACTIVE CASES</span>
              <span className="font-bold text-foreground tabular-nums">{activeCases}</span>
            </div>
          </div>

          <Button
            size="sm"
            onClick={() => navigate('/ingest')}
            className="h-8 px-3 text-xs font-mono font-semibold gap-1.5"
          >
            <Upload className="size-3.5" />
            INGEST EVIDENCE
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate('/cases')}
            className="h-8 px-3 text-xs font-mono gap-1.5 border-border hover:bg-surface-2"
          >
            <Briefcase className="size-3.5" />
            OPEN CASES
          </Button>
        </div>
      </div>
    </div>
  );
}

export default ThreatPostureBar;
