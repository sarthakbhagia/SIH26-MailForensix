import React from 'react';
import { cn } from '@/lib/utils';
import { Loader2, CheckCircle2, XCircle } from 'lucide-react';
import { getAuthStatusTokens } from '@/lib/severity';

export interface StatusPillProps extends React.HTMLAttributes<HTMLDivElement> {
  label: string;
  state: string;
  dnsState?: 'verified' | 'disagrees' | 'pending' | null;
}

export function StatusPill({ label, state, dnsState, className, ...props }: StatusPillProps) {
  const authInfo = getAuthStatusTokens(state);

  return (
    <div className={cn('panel flex flex-col gap-1.5 px-3.5 py-2.5', className)} {...props}>
      <div className="flex items-center justify-between">
        <span className="label-mono">{label}</span>
        <span className={cn('font-mono text-xs uppercase font-semibold', authInfo.tokens.textColor)}>
          {state}
        </span>
      </div>
      {dnsState && (
        <div className="flex items-center gap-1.5 mt-0.5">
          {dnsState === 'pending' ? (
            <>
              <Loader2 className="size-2.5 animate-spin text-muted-foreground" />
              <span className="font-mono text-[10px] text-muted-foreground">dns lookup…</span>
            </>
          ) : dnsState === 'verified' ? (
            <>
              <CheckCircle2 className="size-2.5 text-clean" />
              <span className="font-mono text-[10px] text-clean">dns verified</span>
            </>
          ) : (
            <>
              <XCircle className="size-2.5 text-critical" />
              <span className="font-mono text-[10px] text-critical">dns disagrees</span>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default StatusPill;
