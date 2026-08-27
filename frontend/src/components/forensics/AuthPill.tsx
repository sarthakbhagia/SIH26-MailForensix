import React from 'react';
import { cn } from '@/lib/utils';
import { CheckCircle2, XCircle, AlertTriangle, HelpCircle, Loader2 } from 'lucide-react';

export type AuthStatus = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unavailable' | string;

export interface AuthPillProps extends React.HTMLAttributes<HTMLDivElement> {
  protocol: 'SPF' | 'DKIM' | 'DMARC' | 'ALIGNMENT' | string;
  status: AuthStatus;
  domain?: string;
  details?: string;
  dnsState?: 'verified' | 'disagrees' | 'pending' | null;
  record?: string;
}

export function getAuthColor(status: AuthStatus): string {
  const s = String(status || '').toLowerCase();
  if (s === 'pass' || s === 'true' || s === 'aligned') return 'var(--clean)';
  if (s === 'fail' || s === 'false') return 'var(--critical)';
  if (s === 'softfail') return 'var(--high)';
  if (s === 'neutral') return 'var(--medium)';
  return 'var(--muted-foreground)';
}

export function AuthPill({
  protocol,
  status,
  domain,
  details,
  dnsState,
  record,
  className,
  ...props
}: AuthPillProps) {
  const s = String(status || 'unavailable').toLowerCase();
  const color = getAuthColor(s);

  const getStatusIcon = () => {
    if (s === 'pass' || s === 'true' || s === 'aligned') {
      return <CheckCircle2 className="size-3.5" style={{ color }} />;
    }
    if (s === 'fail' || s === 'false') {
      return <XCircle className="size-3.5" style={{ color }} />;
    }
    if (s === 'softfail' || s === 'neutral') {
      return <AlertTriangle className="size-3.5" style={{ color }} />;
    }
    return <HelpCircle className="size-3.5" style={{ color }} />;
  };

  return (
    <div className={cn('panel flex flex-col justify-between gap-2 p-4 transition-colors', className)} {...props}>
      {/* Header Row */}
      <div className="flex items-center justify-between">
        <span className="label-mono font-bold tracking-wider">{protocol}</span>
        <div className="flex items-center gap-1.5 font-mono text-xs uppercase font-bold" style={{ color }}>
          {getStatusIcon()}
          <span>{status || 'NONE'}</span>
        </div>
      </div>

      {/* Domain / Details */}
      {(domain || details) && (
        <div className="space-y-0.5">
          {domain && <p className="font-mono text-xs text-foreground truncate">{domain}</p>}
          {details && <p className="text-[11px] text-muted-foreground line-clamp-2 leading-relaxed">{details}</p>}
        </div>
      )}

      {/* Raw Record / DNS State */}
      {(dnsState || record) && (
        <div className="pt-2 border-t border-border/40 flex items-center justify-between gap-2 text-[10px] font-mono text-muted-foreground">
          {record ? (
            <span className="truncate max-w-[200px]" title={record}>
              {record}
            </span>
          ) : (
            <span className="opacity-60">no DNS record</span>
          )}

          {dnsState && (
            <div className="flex items-center gap-1 shrink-0">
              {dnsState === 'pending' ? (
                <>
                  <Loader2 className="size-2.5 animate-spin text-muted-foreground" />
                  <span className="text-[9px]">verifying</span>
                </>
              ) : dnsState === 'verified' ? (
                <>
                  <CheckCircle2 className="size-2.5 text-clean" />
                  <span className="text-[9px] text-clean">verified</span>
                </>
              ) : (
                <>
                  <XCircle className="size-2.5 text-critical" />
                  <span className="text-[9px] text-critical">mismatch</span>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default AuthPill;
