import React from 'react';
import { cn } from '@/lib/utils';

interface TelemetryValueProps extends React.HTMLAttributes<HTMLSpanElement> {
  value: React.ReactNode;
  highlight?: boolean;
}

export function TelemetryValue({ value, highlight, className, ...props }: TelemetryValueProps) {
  return (
    <span
      className={cn(
        'font-mono text-xs break-all',
        highlight ? 'text-primary font-semibold' : 'text-foreground',
        className
      )}
      {...props}
    >
      {value}
    </span>
  );
}
