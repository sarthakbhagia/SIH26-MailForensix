import { useState, useMemo } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { AlertCircle, PieChart as PieIcon, BarChart3 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const NLP_COLOR_MAP: Record<string, string> = {
  Legitimate: '#22c55e',
  legitimate: '#22c55e',
  Suspicious: '#eab308',
  suspicious: '#eab308',
  Phishing: '#ef4444',
  phishing: '#ef4444',
  BEC: '#a855f7',
  bec: '#a855f7',
  'BEC/Fraud': '#a855f7',
  Impersonation: '#f97316',
  impersonation: '#f97316',
  Malware: '#dc2626',
  malware: '#dc2626',
  Unclassified: '#64748b',
};

const RISK_TIER_COLORS: Record<string, string> = {
  low: '#22c55e',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
};

const DEFAULT_PALETTE = ['#3b82f6', '#8b5cf6', '#ec4899', '#14b8a6', '#f59e0b', '#06b6d4'];

interface ThreatChartProps {
  threatDistribution?: Record<string, number>;
  riskDistribution?: {
    low?: number;
    medium?: number;
    high?: number;
    critical?: number;
  };
  isLoading?: boolean;
}

export default function ThreatChart({
  threatDistribution,
  riskDistribution,
  isLoading = false,
}: ThreatChartProps) {
  const [viewMode, setViewMode] = useState<'nlp' | 'risk'>('nlp');

  const nlpChartData = useMemo(() => {
    if (!threatDistribution || Object.keys(threatDistribution).length === 0) return [];
    return Object.entries(threatDistribution)
      .filter(([_, count]) => count > 0)
      .map(([name, value], idx) => ({
        name,
        value,
        color: NLP_COLOR_MAP[name] || DEFAULT_PALETTE[idx % DEFAULT_PALETTE.length],
      }));
  }, [threatDistribution]);

  const riskChartData = useMemo(() => {
    if (!riskDistribution) return [];
    const items = [
      { name: 'Low (<=25)', key: 'low', value: riskDistribution.low || 0, color: RISK_TIER_COLORS.low },
      { name: 'Medium (<=50)', key: 'medium', value: riskDistribution.medium || 0, color: RISK_TIER_COLORS.medium },
      { name: 'High (<=75)', key: 'high', value: riskDistribution.high || 0, color: RISK_TIER_COLORS.high },
      { name: 'Critical (>75)', key: 'critical', value: riskDistribution.critical || 0, color: RISK_TIER_COLORS.critical },
    ];
    return items.filter((item) => item.value > 0);
  }, [riskDistribution]);

  const activeData = viewMode === 'nlp' ? nlpChartData : riskChartData;
  const totalCount = activeData.reduce((acc, curr) => acc + curr.value, 0);

  return (
    <Card className="h-full flex flex-col bg-card/60 backdrop-blur-md border border-border/50 shadow-sm">
      <CardHeader className="pb-3 pt-4 px-5 shrink-0 border-b border-border/40 flex flex-row items-center justify-between space-y-0">
        <div className="flex items-center gap-2">
          <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
            <PieIcon className="w-4 h-4 text-primary" />
            Threat Distribution
          </CardTitle>
        </div>

        {/* Mode Selector Toggle */}
        <div className="flex items-center bg-background/50 border border-border/60 rounded-lg p-0.5">
          <button
            onClick={() => setViewMode('nlp')}
            className={`flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-md transition-all ${
              viewMode === 'nlp'
                ? 'bg-primary text-primary-foreground font-semibold shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            NLP Labels
          </button>
          <button
            onClick={() => setViewMode('risk')}
            className={`flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-md transition-all ${
              viewMode === 'risk'
                ? 'bg-primary text-primary-foreground font-semibold shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            <BarChart3 className="w-3 h-3" />
            Risk Tiers
          </button>
        </div>
      </CardHeader>

      <CardContent className="flex-1 flex flex-col items-center justify-center p-4 min-h-[320px]">
        {isLoading && (
          <div className="w-full h-full flex flex-col items-center justify-center gap-2 text-muted-foreground">
            <div className="w-32 h-32 rounded-full border-4 border-muted border-t-primary animate-spin" />
            <span className="text-xs font-medium mt-2">Loading threat classifications...</span>
          </div>
        )}

        {!isLoading && totalCount === 0 && (
          <div className="flex flex-col items-center justify-center p-6 text-center text-muted-foreground">
            <AlertCircle className="w-8 h-8 opacity-40 mb-2" />
            <p className="text-xs font-semibold text-foreground">No threats classified yet</p>
            <p className="text-[11px] text-muted-foreground mt-0.5 max-w-[220px]">
              Ingest and analyze emails to populate real-time threat categorization.
            </p>
          </div>
        )}

        {!isLoading && totalCount > 0 && (
          <div className="w-full h-full min-h-[300px] flex flex-col items-center justify-center">
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={activeData}
                  cx="50%"
                  cy="45%"
                  innerRadius={60}
                  outerRadius={92}
                  paddingAngle={3}
                  dataKey="value"
                  stroke="none"
                >
                  {activeData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      const percentage = totalCount > 0 ? ((data.value / totalCount) * 100).toFixed(1) : '0';
                      return (
                        <div className="bg-popover/95 backdrop-blur-md border border-border/80 shadow-lg rounded-lg p-2.5 text-xs">
                          <p className="font-semibold text-foreground flex items-center gap-1.5">
                            <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: data.color }} />
                            {data.name}
                          </p>
                          <div className="flex items-center justify-between gap-4 text-muted-foreground mt-1 font-mono">
                            <span>Count: {data.value}</span>
                            <span className="text-foreground font-bold">{percentage}%</span>
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Legend
                  verticalAlign="bottom"
                  height={40}
                  wrapperStyle={{
                    color: 'hsl(var(--foreground))',
                    fontSize: '11px',
                    paddingTop: '8px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}


