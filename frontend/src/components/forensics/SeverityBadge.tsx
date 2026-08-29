import React from 'react';
import { cn } from '@/lib/utils';
import { getSeverityTokens, SeverityLevel } from '@/lib/severity';

export interface SeverityBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  severity: SeverityLevel | string | number;
  label?: string;
  weight?: number;
  outline?: boolean;
  showDot?: boolean;
}

export function SeverityBadge({
  severity,
  label,
  weight,
  outline = false,
  showDot = false,
  className,
  ...props
}: SeverityBadgeProps) {
  const tokens = getSeverityTokens(severity, label);

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-mono text-[11px] uppercase font-semibold tracking-wide border transition-colors select-none',
        tokens.textColor,
        tokens.borderColor,
        outline ? 'bg-transparent' : tokens.bgColor,
        className
      )}
      {...props}
    >
      {showDot && <span className={cn('size-1.5 rounded-full', tokens.dotClass)} />}
      <span>{tokens.label}</span>
      {weight !== undefined && (
        <span className="opacity-80 text-[10px] lowercase font-normal">+{weight} risk</span>
      )}
    </span>
  );
}

export default SeverityBadge;
