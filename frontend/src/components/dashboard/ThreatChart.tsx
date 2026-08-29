import { useState, useMemo } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { AlertCircle, PieChart as PieIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { getSeverityColorVar } from '@/lib/severity';

const DEFAULT_PALETTE = ['#00e5ff', '#ffb020', '#ff2a55', '#00e676', '#a855f7', '#38bdf8'];

export interface ThreatChartProps {
  threatDistribution?: Record<string, number>;
  riskDistribution?: {
    low?: number;
    medium?: number;
    high?: number;
    critical?: number;
  };
  isLoading?: boolean;
}

export function ThreatChart({
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
        color: getSeverityColorVar(name) || DEFAULT_PALETTE[idx % DEFAULT_PALETTE.length],
      }));
  }, [threatDistribution]);

  const riskChartData = useMemo(() => {
    if (!riskDistribution) return [];
    const items = [
      { name: 'Low (0–25)', key: 'low', value: riskDistribution.low || 0, color: getSeverityColorVar('low') },
      { name: 'Medium (26–50)', key: 'medium', value: riskDistribution.medium || 0, color: getSeverityColorVar('medium') },
      { name: 'High (51–75)', key: 'high', value: riskDistribution.high || 0, color: getSeverityColorVar('high') },
      { name: 'Critical (76–100)', key: 'critical', value: riskDistribution.critical || 0, color: getSeverityColorVar('critical') },
    ];
    return items.filter((item) => item.value > 0);
  }, [riskDistribution]);

  const activeData = viewMode === 'nlp' ? nlpChartData : riskChartData;
  const totalCount = activeData.reduce((acc, curr) => acc + curr.value, 0);

  return (
    <div className="panel h-full flex flex-col p-4 sm:p-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-3">
        <div className="flex items-center gap-2">
          <PieIcon className="size-4 text-primary" />
          <h3 className="text-sm font-semibold tracking-tight text-foreground">Threat Distribution Telemetry</h3>
        </div>

        {/* View Mode Switcher */}
        <div className="flex items-center rounded border border-border bg-surface-2 p-0.5">
          <button
            onClick={() => setViewMode('nlp')}
            className={cn(
              'px-2 py-0.5 text-[10px] font-mono uppercase rounded transition-colors',
              viewMode === 'nlp'
                ? 'bg-primary text-primary-foreground font-semibold shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            NLP Categories
          </button>
          <button
            onClick={() => setViewMode('risk')}
            className={cn(
              'px-2 py-0.5 text-[10px] font-mono uppercase rounded transition-colors',
              viewMode === 'risk'
                ? 'bg-primary text-primary-foreground font-semibold shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            Risk Tiers
          </button>
        </div>
      </div>

      {/* Content Body */}
      <div className="flex-1 flex flex-col items-center justify-center min-h-[260px] pt-2">
        {isLoading && (
          <div className="w-full h-full flex flex-col items-center justify-center gap-2 text-muted-foreground">
            <div className="size-7 rounded-full border-2 border-muted border-t-primary animate-spin" />
            <span className="label-mono text-[10px] mt-1">CALCULATING THREAT MATRIX...</span>
          </div>
        )}

        {!isLoading && totalCount === 0 && (
          <div className="flex flex-col items-center justify-center p-6 text-center text-muted-foreground">
            <AlertCircle className="size-6 opacity-40 mb-2" />
            <p className="text-xs font-semibold text-foreground">No classification vectors recorded</p>
            <p className="text-[11px] text-muted-foreground mt-0.5 max-w-[200px]">
              Ingest email evidence to render real-time threat distribution telemetry.
            </p>
          </div>
        )}

        {!isLoading && totalCount > 0 && (
          <div className="w-full flex-1 flex flex-col items-center justify-between">
            <div className="w-full h-[200px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={activeData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={78}
                    paddingAngle={3}
                    dataKey="value"
                    stroke="rgba(0,0,0,0.4)"
                    strokeWidth={1}
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
                          <div className="panel p-2.5 text-xs shadow-xl min-w-[130px]">
                            <p className="font-semibold text-foreground flex items-center gap-1.5 font-mono text-[11px]">
                              <span className="size-2 rounded-full" style={{ backgroundColor: data.color }} />
                              {data.name}
                            </p>
                            <div className="flex items-center justify-between gap-3 text-muted-foreground mt-1 font-mono text-[10px]">
                              <span>Count: {data.value}</span>
                              <span className="text-primary font-bold">{percentage}%</span>
                            </div>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* Compact Breakdown Grid */}
            <div className="w-full pt-2 border-t border-border/40 grid grid-cols-2 gap-1.5 text-xs font-mono">
              {activeData.map((item) => {
                const percentage = totalCount > 0 ? ((item.value / totalCount) * 100).toFixed(0) : '0';
                return (
                  <div key={item.name} className="flex items-center justify-between px-2 py-1 rounded bg-surface-2/60 border border-border/40 text-[11px]">
                    <div className="flex items-center gap-1.5 truncate">
                      <span className="size-2 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                      <span className="truncate text-foreground/80">{item.name}</span>
                    </div>
                    <span className="font-bold text-foreground shrink-0 tabular-nums">{item.value} ({percentage}%)</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default ThreatChart;
