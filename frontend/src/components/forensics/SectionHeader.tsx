import React from 'react';
import { cn } from '@/lib/utils';
import { Radar } from 'lucide-react';

interface SectionHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
  title: string;
  eyebrow?: string;
  description?: string;
  icon?: React.ComponentType<{ className?: string }>;
  actions?: React.ReactNode;
}

export function SectionHeader({
  title,
  eyebrow = 'forensic intelligence console',
  description,
  icon: Icon = Radar,
  actions,
  className,
  ...props
}: SectionHeaderProps) {
  return (
    <div
      className={cn(
        'flex flex-col gap-4 border-b border-border/60 pb-5 md:flex-row md:items-end md:justify-between',
        className
      )}
      {...props}
    >
      <div>
        {eyebrow && (
          <p className="label-mono flex items-center gap-2">
            <Icon className="size-3.5 text-primary" /> {eyebrow}
          </p>
        )}
        <h1 className="mt-2 text-2xl md:text-3xl font-semibold tracking-tight text-foreground">
          {title}
        </h1>
        {description && (
          <p className="mt-1.5 max-w-2xl text-xs md:text-sm leading-relaxed text-muted-foreground">
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2.5 shrink-0">{actions}</div>}
    </div>
  );
}
