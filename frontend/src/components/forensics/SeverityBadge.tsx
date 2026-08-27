import React from 'react';
import { cn } from '@/lib/utils';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'info' | string;

interface SeverityBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  severity: SeverityLevel;
  label?: string;
  weight?: number;
  outline?: boolean;
}

const SEVERITY_STYLES: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: 'text-critical', bg: 'bg-critical/15', border: 'border-critical/40' },
  high: { color: 'text-high', bg: 'bg-high/15', border: 'border-high/40' },
  medium: { color: 'text-medium', bg: 'bg-medium/15', border: 'border-medium/40' },
  low: { color: 'text-low', bg: 'bg-low/15', border: 'border-low/40' },
  clean: { color: 'text-clean', bg: 'bg-clean/15', border: 'border-clean/40' },
  info: { color: 'text-muted-foreground', bg: 'bg-muted/40', border: 'border-border' },
};

export function SeverityBadge({
  severity,
  label,
  weight,
  outline = false,
  className,
  ...props
}: SeverityBadgeProps) {
  const sevKey = String(severity).toLowerCase();
  const style = SEVERITY_STYLES[sevKey] || SEVERITY_STYLES.info;
  const displayLabel = label || severity;

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full font-mono text-[10px] uppercase font-semibold tracking-wider border transition-colors',
        style.color,
        style.border,
        outline ? 'bg-transparent' : style.bg,
        className
      )}
      {...props}
    >
      <span>{displayLabel}</span>
      {weight !== undefined && (
        <span className="opacity-80 text-[9px] lowercase font-normal">+{weight} risk</span>
      )}
    </span>
  );
}
