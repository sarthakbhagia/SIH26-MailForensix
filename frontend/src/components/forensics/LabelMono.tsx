import React from 'react';
import { cn } from '@/lib/utils';

export interface LabelMonoProps extends React.HTMLAttributes<HTMLSpanElement> {
  children: React.ReactNode;
}

export function LabelMono({ children, className, ...props }: LabelMonoProps) {
  return (
    <span className={cn('label-mono', className)} {...props}>
      {children}
    </span>
  );
}

export default LabelMono;
