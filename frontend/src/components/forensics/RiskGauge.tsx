import React from 'react';
import { cn } from '@/lib/utils';

export type Verdict = 'fraud' | 'phishing' | 'impersonation' | 'suspicious' | 'legitimate' | 'clean' | 'critical' | 'high' | 'medium' | 'low' | string;

export function verdictColor(verdict: Verdict): string {
  const v = verdict.toLowerCase();
  if (v.includes('fraud') || v.includes('critical') || v.includes('malware') || v.includes('bec')) {
    return 'var(--critical)';
  }
  if (v.includes('phishing') || v.includes('high')) {
    return 'var(--high)';
  }
  if (v.includes('impersonation') || v.includes('medium')) {
    return 'var(--medium)';
  }
  if (v.includes('suspicious') || v.includes('low')) {
    return 'var(--low)';
  }
  return 'var(--clean)';
}

export function defaultVerdictForScore(score: number): string {
  if (score >= 80) return 'Fraud / BEC';
  if (score >= 60) return 'Phishing';
  if (score >= 40) return 'Impersonation';
  if (score >= 20) return 'Suspicious';
  return 'Legitimate';
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
  size = 156,
  label = 'risk / 100',
  showVerdictBadge = true,
  className,
  ...props
}: RiskGaugeProps) {
  const normalizedScore = Math.min(100, Math.max(0, Math.round(score)));
  const displayVerdict = verdict || defaultVerdictForScore(normalizedScore);
  const color = verdictColor(displayVerdict);

  const strokeWidth = 12;
  const radius = (size - strokeWidth * 2) / 2;
  const center = size / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  return (
    <div className={cn('flex flex-col items-center gap-3 select-none', className)} {...props}>
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
          {/* Background track */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke="var(--muted)"
            strokeWidth={strokeWidth}
          />
          {/* Animated active arc */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            style={{ transition: 'stroke-dashoffset 700ms ease, stroke 400ms ease' }}
          />
        </svg>

        {/* Centered Score & Label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="font-mono text-4xl font-bold tracking-tight" style={{ color }}>
            {normalizedScore}
          </span>
          <span className="label-mono mt-0.5">{label}</span>
        </div>
      </div>

      {/* Verdict Capsule */}
      {showVerdictBadge && (
        <div
          className="rounded-full border px-4 py-1 font-mono text-xs uppercase tracking-widest font-semibold transition-colors"
          style={{ color, borderColor: color, backgroundColor: `color-mix(in oklch, ${color} 10%, transparent)` }}
        >
          {displayVerdict}
        </div>
      )}
    </div>
  );
}

export default RiskGauge;
