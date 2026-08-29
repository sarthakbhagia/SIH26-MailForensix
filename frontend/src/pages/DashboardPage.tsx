import { useQuery } from '@tanstack/react-query';
import { AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import ThreatPostureBar from '@/components/dashboard/ThreatPostureBar';
import StatsCards from '@/components/dashboard/StatsCards';
import ThreatChart from '@/components/dashboard/ThreatChart';
import RecentAlerts from '@/components/dashboard/RecentAlerts';
import IngestionTimeline from '@/components/dashboard/IngestionTimeline';

export default function DashboardPage() {
  const {
    data: statsData,
    isLoading,
    isError,
    refetch,
  } = useQuery({
    queryKey: ['dashboardStats'],
    queryFn: async () => {
      const res = await api.getDashboardStats();
      return res.data;
    },
    refetchInterval: 15000,
    staleTime: 10000,
  });

  return (
    <div className="space-y-4 max-w-full pb-6">
      {/* Level 1: Primary Threat Posture Banner */}
      <ThreatPostureBar
        avgRiskScore={statsData?.avg_risk_score}
        totalEmails={statsData?.total_emails}
        threatsDetected={statsData?.threats_detected}
        unackAlerts={statsData?.unacknowledged_alerts}
        activeCases={statsData?.active_cases}
        isLoading={isLoading}
      />

      {/* Error Callout if API sync fails */}
      {isError && (
        <div className="panel p-3.5 border-critical/40 bg-critical/10 text-critical text-xs flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="size-4 shrink-0" />
            <span>Failed to synchronize live dashboard telemetry with the backend server.</span>
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

      {/* Level 2: Compact Telemetry Metric Matrix */}
      <StatsCards data={statsData} isLoading={isLoading} />

      {/* Level 3: Active Alert Triage Queue & Threat Distribution Grid */}
      <div className="grid gap-4 grid-cols-1 lg:grid-cols-12 items-stretch">
        {/* Active Alert Triage Queue: 7 cols */}
        <div className="lg:col-span-7 h-full">
          <RecentAlerts />
        </div>

        {/* Threat Distribution & Risk Tiers: 5 cols */}
        <div className="lg:col-span-5 h-full">
          <ThreatChart
            threatDistribution={statsData?.threat_distribution}
            riskDistribution={statsData?.risk_distribution}
            isLoading={isLoading}
          />
        </div>
      </div>

      {/* Level 4: Velocity Trends & Ingestion Contour */}
      <div className="w-full">
        <IngestionTimeline timeline={statsData?.ingestion_timeline} isLoading={isLoading} />
      </div>
    </div>
  );
}
