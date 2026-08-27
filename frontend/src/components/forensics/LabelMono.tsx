import React from 'react';
import { cn } from '@/lib/utils';

interface LabelMonoProps extends React.HTMLAttributes<HTMLSpanElement> {
  children: React.ReactNode;
}

export function LabelMono({ children, className, ...props }: LabelMonoProps) {
  return (
    <span className={cn('label-mono', className)} {...props}>
      {children}
    </span>
  );
}
