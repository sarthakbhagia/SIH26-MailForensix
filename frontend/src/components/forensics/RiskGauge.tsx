import React from 'react';
import { cn } from '@/lib/utils';
import { getSeverityTokens, getVerdictForScore } from '@/lib/severity';

export type Verdict = string;

export function verdictColor(verdict: Verdict): string {
  return getSeverityTokens(verdict).colorVar;
}

export function defaultVerdictForScore(score: number): string {
  return getVerdictForScore(score);
}

export interface RiskGaugeProps extends React.HTMLAttributes<HTMLDivElement> {
  score: number;
  verdict?: Verdict;
  size?: number;
  label?: string;
  showVerdictBadge?: boolean;
}

export function RiskGauge({
  score,
  verdict,
  size = 144,
  label = 'RISK / 100',
  showVerdictBadge = true,
  className,
  ...props
}: RiskGaugeProps) {
  const normalizedScore = Math.min(100, Math.max(0, Math.round(score)));
  const displayVerdict = verdict || defaultVerdictForScore(normalizedScore);
  const tokens = getSeverityTokens(normalizedScore, displayVerdict);

  const strokeWidth = 10;
  const radius = (size - strokeWidth * 2) / 2;
  const center = size / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  return (
    <div className={cn('flex flex-col items-center gap-2.5 select-none', className)} {...props}>
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
          {/* Background track */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke="var(--surface-2)"
            strokeWidth={strokeWidth}
          />
          {/* Active arc */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={tokens.hex}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            style={{ transition: 'stroke-dashoffset 600ms ease, stroke 300ms ease' }}
          />
        </svg>

        {/* Centered Score & Label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="font-mono text-3xl sm:text-4xl font-bold tracking-tight tabular-nums" style={{ color: tokens.hex }}>
            {normalizedScore}
          </span>
          <span className="label-mono text-[9px] mt-0.5">{label}</span>
        </div>
      </div>

      {/* Verdict Capsule */}
      {showVerdictBadge && (
        <div
          className={cn(
            'rounded px-3 py-0.5 font-mono text-xs uppercase tracking-wider font-semibold border',
            tokens.badgeClass
          )}
        >
          {displayVerdict}
        </div>
      )}
    </div>
  );
}

export default RiskGauge;
