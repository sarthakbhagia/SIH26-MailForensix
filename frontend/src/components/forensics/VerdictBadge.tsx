import React from 'react';
import { cn } from '@/lib/utils';
import { verdictColor, Verdict } from './RiskGauge';

export interface VerdictBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  verdict: Verdict;
  size?: 'sm' | 'md' | 'lg';
  outline?: boolean;
}

export function VerdictBadge({
  verdict,
  size = 'md',
  outline = false,
  className,
  ...props
}: VerdictBadgeProps) {
  const color = verdictColor(verdict);

  const sizeClasses = {
    sm: 'px-2.5 py-0.5 text-[10px]',
    md: 'px-3.5 py-1 text-xs',
    lg: 'px-4 py-1.5 text-sm',
  };

  return (
    <span
      className={cn(
        'inline-flex items-center justify-center rounded-full font-mono uppercase font-bold tracking-widest border transition-colors select-none',
        sizeClasses[size],
        className
      )}
      style={{
        color,
        borderColor: color,
        backgroundColor: outline ? 'transparent' : `color-mix(in oklch, ${color} 12%, transparent)`,
      }}
      {...props}
    >
      {verdict}
    </span>
  );
}

export default VerdictBadge;
