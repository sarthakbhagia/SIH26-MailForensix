import React from 'react';
import { cn } from '@/lib/utils';
import { AlertCircle, AlertTriangle, ShieldAlert, CheckCircle } from 'lucide-react';

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'info' | string;

export interface FindingCardProps extends React.HTMLAttributes<HTMLDivElement> {
  severity: FindingSeverity;
  category?: string;
  title: string;
  detail?: string;
  weight?: number;
  tags?: string[];
}

export function getFindingColor(severity: FindingSeverity): string {
  const s = String(severity || '').toLowerCase();
  if (s === 'critical' || s === 'fraud' || s === 'malware') return 'var(--critical)';
  if (s === 'high' || s === 'phishing') return 'var(--high)';
  if (s === 'medium' || s === 'impersonation' || s === 'suspicious') return 'var(--medium)';
  if (s === 'low') return 'var(--low)';
  if (s === 'clean' || s === 'legitimate') return 'var(--clean)';
  return 'var(--muted-foreground)';
}

export function FindingCard({
  severity,
  category,
  title,
  detail,
  weight,
  tags,
  className,
  ...props
}: FindingCardProps) {
  const s = String(severity || 'info').toLowerCase();
  const color = getFindingColor(s);

  const getSeverityIcon = () => {
    if (s === 'critical' || s === 'fraud') return <ShieldAlert className="size-4" style={{ color }} />;
    if (s === 'high' || s === 'phishing') return <AlertTriangle className="size-4" style={{ color }} />;
    if (s === 'medium' || s === 'suspicious') return <AlertCircle className="size-4" style={{ color }} />;
    return <CheckCircle className="size-4" style={{ color }} />;
  };

  return (
    <div
      className={cn('panel border-l-2 p-4 transition-all hover:border-l-4', className)}
      style={{ borderLeftColor: color }}
      {...props}
    >
      {/* Header Info */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          {getSeverityIcon()}
          <span className="font-mono text-xs uppercase font-bold tracking-wider" style={{ color }}>
            {severity}
          </span>
          {category && (
            <>
              <span className="text-muted-foreground/50 text-xs">·</span>
              <span className="label-mono text-[10px] text-muted-foreground">{category}</span>
            </>
          )}
        </div>

        {weight !== undefined && weight > 0 && (
          <span
            className="rounded-full border px-2.5 py-0.5 font-mono text-[10px] font-semibold"
            style={{
              color,
              borderColor: color,
              backgroundColor: `color-mix(in oklch, ${color} 10%, transparent)`,
            }}
          >
            +{weight} risk
          </span>
        )}
      </div>

      {/* Finding Title */}
      <p className="mt-2 text-sm font-semibold text-foreground leading-snug">{title}</p>

      {/* Finding Detail */}
      {detail && (
        <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground whitespace-pre-wrap">{detail}</p>
      )}

      {/* Optional Metadata Tags */}
      {tags && tags.length > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-1.5 pt-2 border-t border-border/40">
          {tags.map((tag, idx) => (
            <span
              key={idx}
              className="rounded bg-surface px-2 py-0.5 font-mono text-[10px] text-muted-foreground border border-border/60"
            >
              {tag}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export default FindingCard;
