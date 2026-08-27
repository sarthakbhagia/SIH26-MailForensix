import React from 'react';
import { cn } from '@/lib/utils';

interface MetricProps extends React.HTMLAttributes<HTMLDivElement> {
  label: string;
  value: React.ReactNode;
  subtext?: string;
  valueClassName?: string;
}

export function Metric({ label, value, subtext, valueClassName, className, ...props }: MetricProps) {
  return (
    <div className={cn('panel px-4 py-3', className)} {...props}>
      <p className="label-mono">{label}</p>
      <p className={cn('mt-1 break-all font-mono text-sm text-foreground font-medium', valueClassName)}>
        {value}
      </p>
      {subtext && <p className="mt-1 text-xs text-muted-foreground">{subtext}</p>}
    </div>
  );
}
