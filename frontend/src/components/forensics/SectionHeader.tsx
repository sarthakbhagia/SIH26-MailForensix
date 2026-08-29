import React from 'react';
import { cn } from '@/lib/utils';
import { Radar } from 'lucide-react';

export interface SectionHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
  title: string;
  eyebrow?: string;
  description?: string;
  icon?: React.ComponentType<{ className?: string }>;
  actions?: React.ReactNode;
}

export function SectionHeader({
  title,
  eyebrow = 'FORENSIC INTELLIGENCE CONSOLE',
  description,
  icon: Icon = Radar,
  actions,
  className,
  ...props
}: SectionHeaderProps) {
  return (
    <div
      className={cn(
        'flex flex-col gap-3 border-b border-border pb-4 md:flex-row md:items-end md:justify-between',
        className
      )}
      {...props}
    >
      <div>
        {eyebrow && (
          <p className="label-mono flex items-center gap-1.5">
            <Icon className="size-3 text-primary" /> {eyebrow}
          </p>
        )}
        <h1 className="mt-1 text-xl md:text-2xl font-bold tracking-tight text-foreground">
          {title}
        </h1>
        {description && (
          <p className="mt-1 max-w-2xl text-xs leading-relaxed text-muted-foreground">
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </div>
  );
}

export default SectionHeader;
