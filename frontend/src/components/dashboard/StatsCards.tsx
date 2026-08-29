
import { useNavigate } from 'react-router-dom';
import { Mail, ShieldAlert, FolderKanban, Activity, ArrowUpRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import { getSeverityTokens } from '@/lib/severity';

export interface StatsCardsProps {
  data?: {
    total_emails?: number;
    threats_detected?: number;
    active_cases?: number;
    avg_risk_score?: number;
  };
  isLoading?: boolean;
}

export function StatsCards({ data, isLoading = false }: StatsCardsProps) {
  const navigate = useNavigate();

  if (isLoading) {
    return (
      <div className="grid gap-3 grid-cols-1 sm:grid-cols-2 xl:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="panel p-3.5 animate-pulse space-y-2.5">
            <div className="flex justify-between items-center">
              <div className="h-3 w-20 bg-muted/60 rounded" />
              <div className="size-6 rounded bg-muted/50" />
            </div>
            <div className="h-6 w-16 bg-muted/60 rounded" />
            <div className="h-2.5 w-24 bg-muted/40 rounded" />
          </div>
        ))}
      </div>
    );
  }

  const totalEmails = data?.total_emails ?? 0;
  const threatsDetected = data?.threats_detected ?? 0;
  const activeCases = data?.active_cases ?? 0;
  const avgRiskScore = data?.avg_risk_score ?? 0.0;

  const riskTokens = getSeverityTokens(avgRiskScore);
  const threatPercentage = totalEmails > 0 ? ((threatsDetected / totalEmails) * 100).toFixed(1) : '0';
  const cleanEmails = Math.max(0, totalEmails - threatsDetected);

  const metrics = [
    {
      id: 'metric-ingested',
      label: 'TOTAL ENVELOPES ANALYZED',
      value: totalEmails.toLocaleString(),
      subtext: `${cleanEmails} clean / ${threatsDetected} flagged`,
      icon: Mail,
      accentColor: 'text-primary',
      badgeClass: 'bg-primary/10 text-primary border-primary/20',
      action: () => navigate('/ingest'),
      actionLabel: 'View Ledger',
    },
    {
      id: 'metric-threats',
      label: 'THREATS & PHISHING FLAGGED',
      value: threatsDetected.toLocaleString(),
      subtext: `${threatPercentage}% of monitored volume (Score > 50)`,
      icon: ShieldAlert,
      accentColor: 'text-critical',
      badgeClass: 'bg-critical/10 text-critical border-critical/25',
      action: () => navigate('/ingest'),
      actionLabel: 'Triage Vectors',
    },
    {
      id: 'metric-cases',
      label: 'ACTIVE SOC INVESTIGATIONS',
      value: activeCases.toLocaleString(),
      subtext: 'Open & in-progress case files',
      icon: FolderKanban,
      accentColor: 'text-accent',
      badgeClass: 'bg-accent/10 text-accent border-accent/25',
      action: () => navigate('/cases'),
      actionLabel: 'Manage Cases',
    },
    {
      id: 'metric-score',
      label: 'ENVIRONMENT RISK RATING',
      value: avgRiskScore.toFixed(1),
      subtext: `${riskTokens.label} SEVERITY TIER`,
      icon: Activity,
      accentColor: riskTokens.textColor,
      badgeClass: riskTokens.badgeClass,
      action: () => navigate('/map'),
      actionLabel: 'Inspect Telemetry',
    },
  ];

  return (
    <div className="grid gap-3 grid-cols-1 sm:grid-cols-2 xl:grid-cols-4">
      {metrics.map((metric) => {
        const Icon = metric.icon;
        return (
          <div
            key={metric.id}
            onClick={metric.action}
            className="panel p-3.5 transition-all duration-150 hover:border-border-strong hover:bg-surface-2 cursor-pointer group flex flex-col justify-between"
          >
            {/* Top Label & Icon */}
            <div className="flex items-center justify-between gap-2 pb-1.5 border-b border-border/40">
              <span className="label-mono text-[10px] text-muted-foreground group-hover:text-foreground transition-colors truncate">
                {metric.label}
              </span>
              <div className={cn('p-1 rounded border shrink-0', metric.badgeClass)}>
                <Icon className="size-3.5" />
              </div>
            </div>

            {/* Main Numeric Metric */}
            <div className="pt-2 space-y-0.5">
              <div className="text-2xl font-bold font-mono tracking-tight text-foreground tabular-nums">
                {metric.value}
              </div>
              <p className="text-[11px] font-mono text-muted-foreground truncate">
                {metric.subtext}
              </p>
            </div>

            {/* Subtle Hover Action Footer */}
            <div className="pt-2 mt-2 border-t border-border/30 flex items-center justify-between text-[10px] font-mono text-muted-foreground group-hover:text-primary transition-colors">
              <span>{metric.actionLabel}</span>
              <ArrowUpRight className="size-3 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default StatsCards;
