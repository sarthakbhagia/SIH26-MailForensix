import React from 'react';
import { cn } from '@/lib/utils';
import { getSeverityTokens, getVerdictForScore } from '@/lib/severity';

export interface VerdictBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  verdict?: string;
  score?: number;
  size?: 'sm' | 'md' | 'lg';
  outline?: boolean;
}

export function VerdictBadge({
  verdict,
  score,
  size = 'md',
  outline = false,
  className,
  ...props
}: VerdictBadgeProps) {
  const displayVerdict = verdict || (score !== undefined ? getVerdictForScore(score) : 'Undetermined');
  const tokens = getSeverityTokens(score !== undefined ? score : displayVerdict, displayVerdict);

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-[10px]',
    md: 'px-2.5 py-0.5 text-xs',
    lg: 'px-3.5 py-1 text-xs sm:text-sm',
  };

  return (
    <span
      className={cn(
        'inline-flex items-center justify-center rounded font-mono uppercase font-bold tracking-wider border transition-colors select-none',
        tokens.textColor,
        tokens.borderColor,
        outline ? 'bg-transparent' : tokens.bgColor,
        sizeClasses[size],
        className
      )}
      {...props}
    >
      {displayVerdict}
    </span>
  );
}

export default VerdictBadge;
