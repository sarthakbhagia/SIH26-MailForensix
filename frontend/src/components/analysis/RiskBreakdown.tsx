import { cn } from '@/lib/utils';
import { BarChart3 } from 'lucide-react';
import { getSeverityTokens } from '@/lib/severity';

export interface RiskFactor {
  name: string;
  score: number;
  percentage?: number;
  color?: string;
}

export interface RiskBreakdownProps {
  overallScore: number;
  factors?: RiskFactor[];
  breakdownMap?: Record<string, number | { raw_score?: number; weight?: number }>;
}

export function RiskBreakdown({ overallScore, factors, breakdownMap }: RiskBreakdownProps) {
  let renderedFactors: RiskFactor[] = [];

  if (breakdownMap && Object.keys(breakdownMap).length > 0) {
    renderedFactors = Object.entries(breakdownMap).map(([key, val]) => {
      const score = typeof val === 'number' ? val : val?.raw_score ?? 0;
      const formattedName = key
        .replace(/_/g, ' ')
        .replace(/\b\w/g, (c) => c.toUpperCase());
      return {
        name: formattedName,
        score: Math.min(100, Math.max(0, Math.round(score))),
      };
    });
  } else if (factors && factors.length > 0) {
    renderedFactors = factors;
  } else {
    renderedFactors = [];
  }

  return (
    <div className="panel p-4 sm:p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-border/50 pb-3">
        <div className="flex items-center gap-2">
          <BarChart3 className="size-4 text-primary" />
          <h3 className="text-sm font-semibold tracking-tight text-foreground">Risk Vector Assessment</h3>
        </div>
        <div className="flex items-center gap-2">
          <span className="label-mono text-[10px]">COMPOSITE</span>
          <span className="font-mono text-sm font-bold text-primary tabular-nums">{overallScore}/100</span>
        </div>
      </div>

      <div className="space-y-3 pt-1">
        {renderedFactors.length === 0 ? (
          <div className="text-center py-4 text-xs font-mono text-muted-foreground">
            No anomalous risk vector factors detected.
          </div>
        ) : (
          renderedFactors.map((factor, idx) => {
            const tokens = getSeverityTokens(factor.score);
            return (
              <div key={idx} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-foreground/90 font-medium">{factor.name}</span>
                  <span className={cn('font-bold tabular-nums', tokens.textColor)}>{factor.score}%</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-surface-2 overflow-hidden border border-border/40">
                  <div
                    className={cn('h-full rounded-full transition-all duration-500', tokens.dotClass)}
                    style={{ width: `${factor.score}%` }}
                  />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

export default RiskBreakdown;
