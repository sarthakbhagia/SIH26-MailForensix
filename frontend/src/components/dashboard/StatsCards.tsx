import { Mail, ShieldAlert, FolderKanban, Activity } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface StatsCardsProps {
  data?: {
    total_emails?: number;
    threats_detected?: number;
    active_cases?: number;
    avg_risk_score?: number;
  };
  isLoading?: boolean;
}

export default function StatsCards({ data, isLoading = false }: StatsCardsProps) {
  if (isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <Card key={i} className="bg-card/50 backdrop-blur-sm border border-border/50 animate-pulse p-4">
            <div className="flex justify-between items-center mb-3">
              <div className="h-3.5 w-24 bg-muted/60 rounded" />
              <div className="w-8 h-8 rounded-full bg-muted/50" />
            </div>
            <div className="h-8 w-16 bg-muted/60 rounded mb-2" />
            <div className="h-3 w-32 bg-muted/40 rounded" />
          </Card>
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
      title: 'Total Emails',
      value: totalEmails.toLocaleString(),
      icon: Mail,
      subtext: totalEmails === 1 ? '1 Ingested Record' : `${totalEmails.toLocaleString()} Ingested Records`,
      color: 'text-sky-400',
      borderGlow: 'hover:border-sky-500/30',
      bg: 'bg-sky-500/10',
    },
    {
      title: 'Threats Detected',
      value: threatsDetected.toLocaleString(),
      icon: ShieldAlert,
      subtext: 'Composite Risk > 50.0',
      color: 'text-red-400',
      borderGlow: 'hover:border-red-500/30',
      bg: 'bg-red-500/10',
    },
    {
      title: 'Active Cases',
      value: activeCases.toLocaleString(),
      icon: FolderKanban,
      subtext: 'Open & Investigating',
      color: 'text-amber-400',
      borderGlow: 'hover:border-amber-500/30',
      bg: 'bg-amber-500/10',
    },
    {
      title: 'Average Risk Score',
      value: avgRiskScore.toFixed(1),
      icon: Activity,
      subtext:
        avgRiskScore >= 75
          ? 'Critical Threat Tier'
          : avgRiskScore >= 50
          ? 'Elevated Risk Tier'
          : 'Low / Nominal Risk',
      color:
        avgRiskScore >= 75
          ? 'text-red-400'
          : avgRiskScore >= 50
          ? 'text-amber-400'
          : 'text-emerald-400',
      borderGlow:
        avgRiskScore >= 75
          ? 'hover:border-red-500/30'
          : avgRiskScore >= 50
          ? 'hover:border-amber-500/30'
          : 'hover:border-emerald-500/30',
      bg:
        avgRiskScore >= 75
          ? 'bg-red-500/10'
          : avgRiskScore >= 50
          ? 'bg-amber-500/10'
          : 'bg-emerald-500/10',
    },
  ];

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {stats.map((stat, index) => {
        const Icon = stat.icon;
        return (
          <Card
            key={index}
            className={cn(
              'overflow-hidden bg-card/60 backdrop-blur-md border border-border/50 shadow-sm transition-all duration-200 hover:shadow-md',
              stat.borderGlow
            )}
          >
            <CardHeader className="flex flex-row items-center justify-between pb-2 pt-4 px-4">
              <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                {stat.title}
              </CardTitle>
              <div className={cn('p-2 rounded-lg border border-border/40', stat.bg)}>
                <Icon className={cn('h-4 w-4', stat.color)} />
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-4 pt-0">
              <div className="text-2xl font-bold tracking-tight text-foreground font-mono">
                {stat.value}
              </div>
              <p className="text-[11px] text-muted-foreground mt-1 font-medium">
                <span className={cn(stat.color, 'font-semibold')}>{stat.subtext}</span>
              </p>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}


