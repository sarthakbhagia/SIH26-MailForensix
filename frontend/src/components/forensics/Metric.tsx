import React from 'react';
import { cn } from '@/lib/utils';

export interface MetricProps extends React.HTMLAttributes<HTMLDivElement> {
  label: string;
  value: React.ReactNode;
  subtext?: string;
  valueClassName?: string;
}

export function Metric({ label, value, subtext, valueClassName, className, ...props }: MetricProps) {
  return (
    <div className={cn('panel p-3 sm:p-3.5 space-y-1', className)} {...props}>
      <p className="label-mono">{label}</p>
      <p className={cn('break-all font-mono text-xs sm:text-sm text-foreground font-semibold tabular-nums', valueClassName)}>
        {value}
      </p>
      {subtext && <p className="text-[11px] text-muted-foreground truncate">{subtext}</p>}
    </div>
  );
}

export default Metric;
