import React from 'react';
import { cn } from '@/lib/utils';
import { AlertCircle, AlertTriangle, ShieldAlert, CheckCircle } from 'lucide-react';
import { getSeverityTokens, SeverityLevel } from '@/lib/severity';

export type FindingSeverity = SeverityLevel | string;

export interface FindingCardProps extends React.HTMLAttributes<HTMLDivElement> {
  severity: FindingSeverity;
  category?: string;
  title: string;
  detail?: string;
  weight?: number;
  tags?: string[];
}

export function getFindingColor(severity: FindingSeverity): string {
  return getSeverityTokens(severity).colorVar;
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
  const tokens = getSeverityTokens(severity);

  const getSeverityIcon = () => {
    if (tokens.level === 'critical') return <ShieldAlert className="size-4 text-critical" />;
    if (tokens.level === 'high') return <AlertTriangle className="size-4 text-high" />;
    if (tokens.level === 'medium') return <AlertCircle className="size-4 text-medium" />;
    return <CheckCircle className="size-4 text-clean" />;
  };

  return (
    <div
      className={cn('panel border-l-2 p-3.5 transition-all hover:border-l-4', className)}
      style={{ borderLeftColor: tokens.hex }}
      {...props}
    >
      {/* Header Info */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          {getSeverityIcon()}
          <span className={cn('font-mono text-xs uppercase font-bold tracking-wider', tokens.textColor)}>
            {severity}
          </span>
          {category && (
            <>
              <span className="text-muted-foreground/50 text-xs">·</span>
              <span className="label-mono text-[10px]">{category}</span>
            </>
          )}
        </div>

        {weight !== undefined && weight > 0 && (
          <span
            className={cn('px-2 py-0.5 rounded font-mono text-[10px] font-semibold border', tokens.badgeClass)}
          >
            +{weight} risk
          </span>
        )}
      </div>

      {/* Finding Title */}
      <p className="mt-2 text-xs sm:text-sm font-semibold text-foreground leading-snug">{title}</p>

      {/* Finding Detail */}
      {detail && (
        <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground whitespace-pre-wrap">{detail}</p>
      )}

      {/* Optional Metadata Tags */}
      {tags && tags.length > 0 && (
        <div className="mt-2.5 flex flex-wrap items-center gap-1.5 pt-2 border-t border-border/40">
          {tags.map((tag, idx) => (
            <span
              key={idx}
              className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground border border-border"
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
