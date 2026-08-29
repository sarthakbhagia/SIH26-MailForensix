import React from 'react';
import { cn } from '@/lib/utils';

export interface PanelProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  elevated?: boolean;
  subtle?: boolean;
  interactive?: boolean;
  grid?: boolean;
}

export function Panel({ children, elevated, subtle, interactive, grid, className, ...props }: PanelProps) {
  return (
    <div
      className={cn(
        'panel',
        elevated && 'panel-elevated',
        subtle && 'panel-subtle',
        interactive && 'panel-interactive',
        grid && 'grid-bg',
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export default Panel;
