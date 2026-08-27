import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Radio, RefreshCw, Cpu } from 'lucide-react';
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
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      {/* Top SOC Dashboard Header */}
      <div className="panel relative p-5 overflow-hidden">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
                <Cpu className="size-5 text-primary" />
                SOC Command Center
              </h1>

              <span className="flex items-center gap-1.5 text-[10px] font-mono px-2 py-0.5 rounded border border-primary/30 bg-primary/10 text-primary">
                <Radio className="size-3 animate-pulse" />
                LIVE TELEMETRY STREAM
              </span>
            </div>

            <p className="text-xs text-muted-foreground">
              Real-time threat monitoring, automated NLP email classification, and tactical incident ledger.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="label-mono text-[10px] hidden md:block">
              SYNCED {lastRefreshed.toLocaleTimeString()}
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={handleManualRefresh}
              disabled={isFetching}
              className="h-8 text-xs font-mono gap-1.5 border-border bg-surface hover:bg-muted"
            >
              <RefreshCw className={`size-3.5 ${isFetching ? 'animate-spin' : ''}`} />
              <span>{isFetching ? 'Syncing...' : 'Sync Feed'}</span>
            </Button>
          </div>
        </div>
      </div>

      {/* Error Banner */}
      {isError && (
        <div className="panel p-4 border-critical/40 bg-critical/10 text-critical text-xs flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="size-4 shrink-0" />
            <span>Failed to sync live dashboard statistics with the backend API.</span>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            className="h-7 text-xs font-mono border-critical/40 hover:bg-critical/20 text-critical"
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



