import { useMemo } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { CalendarDays, Inbox } from 'lucide-react';

export interface IngestionTimelineProps {
  timeline?: { date: string; ingested: number; threats: number }[];
  isLoading?: boolean;
}

export function IngestionTimeline({ timeline, isLoading = false }: IngestionTimelineProps) {
  const chartData = useMemo(() => {
    if (timeline && timeline.length > 0) {
      return timeline.map((item) => {
        const parts = item.date.split('-');
        const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const month = parseInt(parts[1], 10) - 1;
        const day = parseInt(parts[2], 10);
        const name = `${monthNames[month] || ''} ${day}`;
        return {
          name,
          date: item.date,
          ingested: item.ingested,
          threats: item.threats,
        };
      });
    }

    // Default contiguous 7-day date slots
    const now = new Date();
    const defaultList = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const iso = d.toISOString().split('T')[0];
      const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      defaultList.push({
        name: `${monthNames[d.getMonth()]} ${d.getDate()}`,
        date: iso,
        ingested: 0,
        threats: 0,
      });
    }
    return defaultList;
  }, [timeline]);

  const totalIngested = chartData.reduce((acc, curr) => acc + curr.ingested, 0);
  const totalThreats = chartData.reduce((acc, curr) => acc + curr.threats, 0);

  return (
    <div className="panel p-4 sm:p-5 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/50 pb-3">
        <div className="space-y-0.5">
          <h3 className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
            <CalendarDays className="size-4 text-primary" />
            7-Day Ingestion & Threat Detection Velocity
          </h3>
          <p className="label-mono text-[10px]">DIURNAL ENVELOPE VOLUMES VS. SUSPICIOUS INCIDENTS</p>
        </div>

        <div className="flex items-center gap-2.5 font-mono text-[11px]">
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-primary/10 text-primary border border-primary/25">
            <span className="size-1.5 rounded-full bg-primary animate-pulse" />
            {totalIngested} Ingested
          </span>
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-critical/10 text-critical border border-critical/25">
            <span className="size-1.5 rounded-full bg-critical" />
            {totalThreats} Threats Flagged
          </span>
        </div>
      </div>

      {/* Chart Canvas */}
      <div className="pt-2">
        {isLoading && (
          <div className="h-[250px] w-full flex flex-col items-center justify-center gap-2 text-muted-foreground">
            <div className="size-8 rounded-full border-2 border-muted border-t-primary animate-spin" />
            <span className="label-mono text-[10px] mt-2">AGGREGATING VELOCITY TIME-SERIES...</span>
          </div>
        )}

        {!isLoading && totalIngested === 0 && totalThreats === 0 && (
          <div className="h-[250px] w-full flex flex-col items-center justify-center p-6 text-center text-muted-foreground">
            <Inbox className="size-8 opacity-40 mb-2" />
            <p className="text-xs font-semibold text-foreground">No ingestion telemetry recorded in the last 7 days</p>
            <p className="text-[11px] text-muted-foreground mt-0.5 max-w-[260px]">
              Ingested messages will automatically generate real-time volume velocity contours here.
            </p>
          </div>
        )}

        {!isLoading && (totalIngested > 0 || totalThreats > 0) && (
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorIngested" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00e5ff" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#00e5ff" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff3366" stopOpacity={0.45} />
                    <stop offset="95%" stopColor="#ff3366" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="name"
                  stroke="var(--muted-foreground)"
                  fontFamily="var(--font-mono, monospace)"
                  fontSize={10}
                  tickLine={false}
                  axisLine={false}
                  dy={8}
                />
                <YAxis
                  stroke="var(--muted-foreground)"
                  fontFamily="var(--font-mono, monospace)"
                  fontSize={10}
                  tickLine={false}
                  axisLine={false}
                  allowDecimals={false}
                />
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                <Tooltip
                  content={({ active, payload, label }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      return (
                        <div className="panel p-3 text-xs shadow-xl min-w-[150px]">
                          <p className="font-semibold text-foreground mb-2 border-b border-border/50 pb-1 font-mono text-[11px]">
                            {label} ({data.date})
                          </p>
                          <div className="space-y-1 font-mono text-[10px]">
                            <div className="flex items-center justify-between text-primary">
                              <span>Total Ingested:</span>
                              <span className="font-bold">{data.ingested}</span>
                            </div>
                            <div className="flex items-center justify-between text-critical">
                              <span>Threats Detected:</span>
                              <span className="font-bold">{data.threats}</span>
                            </div>
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="ingested"
                  name="Total Ingested"
                  stroke="#00e5ff"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorIngested)"
                />
                <Area
                  type="monotone"
                  dataKey="threats"
                  name="Threats Detected"
                  stroke="#ff3366"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorThreats)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}

export default IngestionTimeline;



