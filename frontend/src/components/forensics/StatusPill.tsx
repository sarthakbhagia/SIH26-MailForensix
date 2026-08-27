import React from 'react';
import { cn } from '@/lib/utils';
import { Loader2, CheckCircle2, XCircle } from 'lucide-react';

interface StatusPillProps extends React.HTMLAttributes<HTMLDivElement> {
  label: string;
  state: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unavailable' | string;
  dnsState?: 'verified' | 'disagrees' | 'pending' | null;
}

export function StatusPill({ label, state, dnsState, className, ...props }: StatusPillProps) {
  const s = String(state).toLowerCase();
  const color =
    s === 'pass'
      ? 'var(--clean)'
      : s === 'fail'
      ? 'var(--critical)'
      : s === 'softfail'
      ? 'var(--high)'
      : s === 'neutral'
      ? 'var(--medium)'
      : 'var(--muted-foreground)';

  return (
    <div className={cn('panel flex flex-col gap-1.5 px-4 py-3', className)} {...props}>
      <div className="flex items-center justify-between">
        <span className="label-mono">{label}</span>
        <span className="font-mono text-sm uppercase font-semibold" style={{ color }}>
          {state}
        </span>
      </div>
      {dnsState && (
        <div className="flex items-center gap-1.5 mt-0.5">
          {dnsState === 'pending' ? (
            <>
              <Loader2 className="size-2.5 animate-spin text-muted-foreground" />
              <span className="font-mono text-[0.55rem] text-muted-foreground">dns lookup…</span>
            </>
          ) : dnsState === 'verified' ? (
            <>
              <CheckCircle2 className="size-2.5 text-clean" />
              <span className="font-mono text-[0.55rem] text-clean">dns verified</span>
            </>
          ) : (
            <>
              <XCircle className="size-2.5 text-critical" />
              <span className="font-mono text-[0.55rem] text-critical">dns disagrees</span>
            </>
          )}
        </div>
      )}
    </div>
  );
}
