import React from 'react';
import { cn } from '@/lib/utils';
import { RelayHop } from '@/types/analysis';
import { AlertTriangle, Clock } from 'lucide-react';

export interface RelayHopNodeProps extends React.HTMLAttributes<HTMLDivElement> {
  hop: RelayHop;
  index?: number;
  totalHops?: number;
  isOrigin?: boolean;
  isDestination?: boolean;
}

export function RelayHopNode({
  hop,
  index = 0,
  totalHops = 1,
  isOrigin,
  isDestination,
  className,
  ...props
}: RelayHopNodeProps) {
  const hopNumber = hop.hop_number ?? index + 1;
  const isFirst = isOrigin ?? index === 0;
  const isLast = isDestination ?? (totalHops > 1 && index === totalHops - 1);

  const nodeRole = isFirst ? 'origin node' : isLast ? 'final delivery' : 'intermediate relay';
  const protocol = hop.protocol || 'ESMTP';
  const geo = hop.geo;
  const ipClass =
    geo?.infrastructure_type ||
    (geo?.hosting ? 'hosting' : geo?.vpn ? 'vpn' : geo?.tor ? 'tor' : geo?.proxy ? 'proxy' : 'public');

  const rawHop = hop as any;
  const fromHost = rawHop.from_host || rawHop.from || hop.hostname || '—';
  const byHost = rawHop.by_host || rawHop.by || '—';
  const delaySec = rawHop.delay_seconds != null ? Math.round(Number(rawHop.delay_seconds)) : null;
  const anomalies: string[] = Array.isArray(rawHop.anomaly_flags) ? rawHop.anomaly_flags : [];

  return (
    <div className={cn('panel relative p-4 md:p-5 transition-all', className)} {...props}>
      {/* Top Header: Hop Badge, Role, Protocol */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-3">
        <div className="flex items-center gap-3">
          <div className="flex size-7 items-center justify-center rounded-full border border-primary/60 bg-primary/10 font-mono text-xs font-bold text-primary shrink-0">
            {hopNumber}
          </div>
          <div>
            <span className="label-mono">{nodeRole}</span>
            <span className="ml-2 font-mono text-xs text-muted-foreground">via {protocol}</span>
          </div>
        </div>

        {hop.timestamp && (
          <div className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
            <Clock className="size-3 text-muted-foreground/70" />
            <span>{hop.timestamp}</span>
            {delaySec !== null && delaySec > 0 && (
              <span className="ml-1 rounded bg-muted/60 px-1.5 py-0.5 text-[10px] text-muted-foreground">
                +{delaySec}s delay
              </span>
            )}
          </div>
        )}
      </div>

      {/* 3-Column Routing Telemetry Grid */}
      <div className="mt-3.5 grid gap-3 sm:grid-cols-3">
        {/* Column 1: From */}
        <div className="space-y-1">
          <p className="label-mono">from / host</p>
          <p className="font-mono text-xs font-medium text-foreground break-all" title={fromHost}>
            {fromHost}
          </p>
        </div>

        {/* Column 2: Relay IP & Classification */}
        <div className="space-y-1">
          <p className="label-mono">relay ip</p>
          <p className="font-mono text-xs font-semibold text-primary break-all">
            {hop.ip || '—'}
          </p>
          {(ipClass || geo?.country || geo?.org || geo?.isp) && (
            <p className="font-mono text-[10px] text-muted-foreground truncate">
              {geo?.country && <span>[{geo.country}] </span>}
              {geo?.city && <span>{geo.city}, </span>}
              {geo?.org || geo?.isp || ipClass}
            </p>
          )}
        </div>

        {/* Column 3: Received By */}
        <div className="space-y-1">
          <p className="label-mono">received by</p>
          <p className="font-mono text-xs font-medium text-foreground break-all" title={byHost}>
            {byHost}
          </p>
        </div>
      </div>

      {/* Anomaly Warnings Callout */}
      {anomalies.length > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-2 pt-2.5 border-t border-border/40">
          {anomalies.map((flag: string, idx: number) => (
            <div
              key={idx}
              className="flex items-center gap-1.5 rounded bg-high/10 border border-high/30 px-2 py-0.5 font-mono text-[10px] text-high font-medium"
            >
              <AlertTriangle className="size-3 shrink-0" />
              <span>{flag}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default RelayHopNode;
