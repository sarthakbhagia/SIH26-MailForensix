import { Mail, ShieldAlert, FolderKanban, Activity } from 'lucide-react';
import { cn } from '@/lib/utils';

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
  if (isLoading) {
    return (
      <div className="grid gap-3.5 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="panel p-4.5 animate-pulse space-y-3">
            <div className="flex justify-between items-center">
              <div className="h-3 w-20 bg-muted/60 rounded" />
              <div className="size-7 rounded bg-muted/50" />
            </div>
            <div className="h-7 w-16 bg-muted/60 rounded" />
            <div className="h-2.5 w-28 bg-muted/40 rounded" />
          </div>
        ))}
      </div>
    );
  }

  const totalEmails = data?.total_emails ?? 0;
  const threatsDetected = data?.threats_detected ?? 0;
  const activeCases = data?.active_cases ?? 0;
  const avgRiskScore = data?.avg_risk_score ?? 0.0;

  const stats = [
    {
      title: 'TOTAL INGESTION',
      value: totalEmails.toLocaleString(),
      icon: Mail,
      subtext: totalEmails === 1 ? '1 Processed Envelope' : `${totalEmails.toLocaleString()} Processed Envelopes`,
      color: 'text-primary',
      borderAccent: 'hover:border-primary/50',
      badgeBg: 'bg-primary/10 text-primary border-primary/20',
    },
    {
      title: 'THREATS FLAGGED',
      value: threatsDetected.toLocaleString(),
      icon: ShieldAlert,
      subtext: 'Composite Risk ≥ 50.0',
      color: 'text-critical',
      borderAccent: 'hover:border-critical/50',
      badgeBg: 'bg-critical/10 text-critical border-critical/25',
    },
    {
      title: 'ACTIVE CASES',
      value: activeCases.toLocaleString(),
      icon: FolderKanban,
      subtext: 'Open SOC Investigations',
      color: 'text-accent',
      borderAccent: 'hover:border-accent/50',
      badgeBg: 'bg-accent/10 text-accent border-accent/25',
    },
    {
      title: 'AVERAGE RISK SCORE',
      value: avgRiskScore.toFixed(1),
      icon: Activity,
      subtext:
        avgRiskScore >= 75
          ? 'CRITICAL SEVERITY TIER'
          : avgRiskScore >= 50
          ? 'HIGH / ELEVATED TIER'
          : avgRiskScore >= 25
          ? 'MEDIUM / MODERATE TIER'
          : 'NOMINAL / CLEAN TIER',
      color:
        avgRiskScore >= 75
          ? 'text-critical'
          : avgRiskScore >= 50
          ? 'text-high'
          : avgRiskScore >= 25
          ? 'text-medium'
          : 'text-clean',
      borderAccent:
        avgRiskScore >= 75
          ? 'hover:border-critical/50'
          : avgRiskScore >= 50
          ? 'hover:border-high/50'
          : 'hover:border-clean/50',
      badgeBg:
        avgRiskScore >= 75
          ? 'bg-critical/10 text-critical border-critical/25'
          : avgRiskScore >= 50
          ? 'bg-high/10 text-high border-high/25'
          : 'bg-clean/10 text-clean border-clean/25',
    },
  ];

  return (
    <div className="grid gap-3.5 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
      {stats.map((stat, index) => {
        const Icon = stat.icon;
        return (
          <div
            key={index}
            className={cn(
              'panel p-4.5 transition-all duration-200 group flex flex-col justify-between',
              stat.borderAccent
            )}
          >
            <div className="flex items-center justify-between gap-2 pb-2">
              <span className="label-mono font-semibold tracking-wider text-[10px]">
                {stat.title}
              </span>
              <div className={cn('p-1.5 rounded border', stat.badgeBg)}>
                <Icon className="size-3.5" />
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-2xl lg:text-3xl font-bold font-mono tracking-tight text-foreground">
                {stat.value}
              </div>
              <p className="label-mono text-[10px] text-muted-foreground truncate">
                <span className={cn('font-semibold', stat.color)}>{stat.subtext}</span>
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default StatsCards;



