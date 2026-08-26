import { useMemo } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Activity, CalendarDays, Inbox } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface IngestionTimelineProps {
  timeline?: { date: string; ingested: number; threats: number }[];
  isLoading?: boolean;
}

export default function IngestionTimeline({ timeline, isLoading = false }: IngestionTimelineProps) {
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
    <Card className="bg-card/60 backdrop-blur-md border border-border/50 shadow-sm">
      <CardHeader className="border-b border-border/40 pb-3.5 pt-4 px-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-0.5">
            <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
              <CalendarDays className="w-4 h-4 text-primary" />
              7-Day Ingestion & Detection Velocity
            </CardTitle>
            <p className="text-xs text-muted-foreground">
              Daily telemetry tracking volume of processed emails vs. flagged high-risk threats.
            </p>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono">
            <span className="flex items-center gap-1.5 text-sky-400 bg-sky-500/10 px-2 py-0.5 rounded border border-sky-500/20">
              <span className="w-2 h-2 rounded-full bg-sky-400" />
              {totalIngested} Ingested
            </span>
            <span className="flex items-center gap-1.5 text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
              <span className="w-2 h-2 rounded-full bg-red-400" />
              {totalThreats} Threats Flagged
            </span>
          </div>
        </div>
      </CardHeader>

      <CardContent className="pt-6 px-4 pb-4">
        {isLoading && (
          <div className="h-[280px] w-full flex flex-col items-center justify-center gap-2 text-muted-foreground">
            <Activity className="w-6 h-6 animate-spin text-primary" />
            <span className="text-xs font-medium">Aggregating 7-day telemetry...</span>
          </div>
        )}

        {!isLoading && totalIngested === 0 && totalThreats === 0 && (
          <div className="h-[280px] w-full flex flex-col items-center justify-center p-6 text-center text-muted-foreground">
            <Inbox className="w-9 h-9 opacity-40 mb-2" />
            <p className="text-xs font-semibold text-foreground">No ingestion telemetry in the last 7 days</p>
            <p className="text-[11px] text-muted-foreground mt-0.5 max-w-[280px]">
              Ingested email files will automatically populate real-time daily volume curves here.
            </p>
          </div>
        )}

        {!isLoading && (totalIngested > 0 || totalThreats > 0) && (
          <div className="h-[280px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorIngested" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="name"
                  stroke="#888"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                  dy={10}
                />
                <YAxis
                  stroke="#888"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                  allowDecimals={false}
                />
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border) / 0.5)" vertical={false} />
                <Tooltip
                  content={({ active, payload, label }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      return (
                        <div className="bg-popover/95 backdrop-blur-md border border-border/80 shadow-lg rounded-lg p-3 text-xs min-w-[140px]">
                          <p className="font-semibold text-foreground mb-2 border-b border-border/40 pb-1">
                            {label} ({data.date})
                          </p>
                          <div className="space-y-1 font-mono">
                            <div className="flex items-center justify-between text-sky-400">
                              <span>Total Ingested:</span>
                              <span className="font-bold">{data.ingested}</span>
                            </div>
                            <div className="flex items-center justify-between text-red-400">
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
                  stroke="#38bdf8"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorIngested)"
                />
                <Area
                  type="monotone"
                  dataKey="threats"
                  name="Threats Detected"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorThreats)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}


