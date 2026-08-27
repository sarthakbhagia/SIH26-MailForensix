import React from 'react';
import { cn } from '@/lib/utils';

interface PanelProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  grid?: boolean;
}

export function Panel({ children, grid, className, ...props }: PanelProps) {
  return (
    <div className={cn('panel', grid && 'grid-bg', className)} {...props}>
      {children}
    </div>
  );
}
