import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Radio, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import StatsCards from '@/components/dashboard/StatsCards';
import ThreatChart from '@/components/dashboard/ThreatChart';
import RecentAlerts from '@/components/dashboard/RecentAlerts';
import IngestionTimeline from '@/components/dashboard/IngestionTimeline';

export default function DashboardPage() {
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());

  const {
    data: statsData,
    isLoading,
    isError,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ['dashboardStats'],
    queryFn: async () => {
      const res = await api.getDashboardStats();
      setLastRefreshed(new Date());
      return res.data;
    },
    refetchInterval: 15000,
    staleTime: 10000,
  });

  const handleManualRefresh = async () => {
    await refetch();
  };

  return (
    <div className="space-y-6">
      {/* Top SOC Dashboard Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border/40 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-bold tracking-tight text-foreground">SOC Command Center</h1>
            <span className="flex items-center gap-1.5 text-[11px] font-medium px-2 py-0.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 font-mono">
              <Radio className="w-3 h-3 animate-pulse" />
              Live Telemetry
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            Real-time threat monitoring, automated NLP email classification, and incident ledger.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-[11px] text-muted-foreground font-mono hidden md:block">
            Updated {lastRefreshed.toLocaleTimeString()}
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={handleManualRefresh}
            disabled={isFetching}
            className="h-8 text-xs gap-1.5 font-medium border-border/60 bg-card/60 hover:bg-muted/60"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin' : ''}`} />
            <span>{isFetching ? 'Refreshing...' : 'Refresh'}</span>
          </Button>
        </div>
      </div>

      {/* Error Banner */}
      {isError && (
        <div className="flex items-center justify-between p-3.5 rounded-xl border border-destructive/40 bg-destructive/10 text-destructive text-xs">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Failed to sync live dashboard statistics with the backend API.</span>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            className="h-7 text-xs border-destructive/40 hover:bg-destructive/20 text-destructive"
          >
            Retry Connection
          </Button>
        </div>
      )}

      {/* Top 4 Key Metric Cards */}
      <StatsCards data={statsData} isLoading={isLoading} />

      {/* Threat Distribution & Live Recent Alerts Grid */}
      <div className="grid gap-6 grid-cols-1 lg:grid-cols-3">
        <div className="lg:col-span-1">
          <ThreatChart
            threatDistribution={statsData?.threat_distribution}
            riskDistribution={statsData?.risk_distribution}
            isLoading={isLoading}
          />
        </div>
        <div className="lg:col-span-2">
          <RecentAlerts />
        </div>
      </div>

      {/* 7-Day Ingestion & Detection Velocity Area Chart */}
      <div className="w-full">
        <IngestionTimeline timeline={statsData?.ingestion_timeline} isLoading={isLoading} />
      </div>
    </div>
  );
}


