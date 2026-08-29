import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RelayHop } from '@/types/analysis';
import { RelayHopNode } from '@/components/forensics/RelayHopNode';
import {
  Route,
  Layers,
  Clock,
  Globe,
  MapPin,
  ExternalLink,
  Copy,
  Check,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { getInfrastructureTokens } from '@/lib/severity';

export interface RelayPathViewerProps {
  hops: RelayHop[];
  emailId?: string;
  onSelectHop?: (index: number) => void;
  selectedHopIndex?: number | null;
}

export function RelayPathViewer({
  hops,
  emailId,
  onSelectHop,
  selectedHopIndex = null,
}: RelayPathViewerProps) {
  const navigate = useNavigate();
  const [viewMode, setViewMode] = useState<'pipeline' | 'detailed'>('pipeline');
  const [copiedIp, setCopiedIp] = useState<string | null>(null);

  const handleCopyIp = (ip: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 1800);
  };

  if (!hops || hops.length === 0) {
    return (
      <div className="panel p-12 text-center text-muted-foreground flex flex-col items-center justify-center">
        <Route className="size-8 opacity-40 mb-2" />
        <h3 className="text-sm font-semibold text-foreground">No Transmission Relay Hops Recorded</h3>
        <p className="text-xs text-muted-foreground mt-0.5 max-w-sm">
          No Received RFC-5322 transit headers were extracted from this email envelope.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/50 pb-3">
        <div>
          <h3 className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
            <Layers className="size-4 text-primary" />
            MTA Transmission Pipeline ({hops.length} {hops.length === 1 ? 'Hop' : 'Hops'})
          </h3>
          <p className="label-mono text-[10px] mt-0.5">INGRESS → INTERMEDIATE RELAYS → EGRESS DESTINATION</p>
        </div>

        <div className="flex items-center gap-2">
          {/* Pipeline vs Detailed Ledger Toggle */}
          <div className="flex items-center rounded border border-border bg-surface-2 p-0.5 font-mono text-xs">
            <button
              onClick={() => setViewMode('pipeline')}
              className={cn(
                'px-2.5 py-0.5 rounded transition-colors',
                viewMode === 'pipeline'
                  ? 'bg-primary text-primary-foreground font-semibold shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              Pipeline
            </button>
            <button
              onClick={() => setViewMode('detailed')}
              className={cn(
                'px-2.5 py-0.5 rounded transition-colors',
                viewMode === 'detailed'
                  ? 'bg-primary text-primary-foreground font-semibold shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              Detailed Ledger
            </button>
          </div>

          {emailId && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate(`/map?emailId=${emailId}`)}
              className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border hover:bg-surface-2"
              title="Launch interactive Trace Map"
            >
              <MapPin className="size-3 text-accent" />
              <span>Trace Map</span>
              <ExternalLink className="size-2.5 text-muted-foreground" />
            </Button>
          )}
        </div>
      </div>

      {/* PIPELINE VIEW */}
      {viewMode === 'pipeline' && (
        <div className="space-y-3">
          {/* Horizontal Step Flow on Desktop */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {hops.map((hop, idx) => {
              const isFirst = idx === 0;
              const isLast = idx === hops.length - 1;
              const isSelected = selectedHopIndex === idx;
              const rawHop = hop as any;
              const geo = hop.geo;
              const infraType = geo?.infrastructure_type || (geo?.hosting ? 'hosting' : geo?.vpn ? 'vpn' : geo?.tor ? 'tor' : 'standard');
              const infra = getInfrastructureTokens(infraType);
              const isAnonymized = infra.category === 'tor' || infra.category === 'vpn';
              const delaySec = rawHop.delay_seconds != null ? Math.round(Number(rawHop.delay_seconds)) : null;
              const anomalies: string[] = Array.isArray(rawHop.anomaly_flags) ? rawHop.anomaly_flags : [];

              return (
                <div
                  key={idx}
                  onClick={() => onSelectHop?.(idx)}
                  className={cn(
                    'panel p-3.5 space-y-2.5 transition-all duration-150 relative cursor-pointer group',
                    isSelected
                      ? 'border-primary ring-1 ring-primary bg-primary/5'
                      : isAnonymized
                      ? 'border-critical/60 bg-critical/5 hover:border-critical'
                      : 'hover:border-border-strong hover:bg-surface-2'
                  )}
                >
                  {/* Hop Card Header */}
                  <div className="flex items-center justify-between gap-2 border-b border-border/40 pb-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={cn(
                          'size-5 rounded-full flex items-center justify-center font-mono text-[10px] font-bold',
                          isFirst
                            ? 'bg-primary text-primary-foreground'
                            : isLast
                            ? 'bg-clean text-clean-foreground'
                            : 'bg-surface-2 text-foreground border border-border'
                        )}
                      >
                        {idx + 1}
                      </span>
                      <span className="label-mono text-[10px] font-bold">
                        {isFirst ? 'ORIGIN INGRESS' : isLast ? 'FINAL DELIVERY' : `HOP #${idx + 1}`}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5">
                      {hop.protocol && (
                        <span className="label-mono text-[9px] text-muted-foreground px-1.5 py-0.2 rounded bg-surface border border-border">
                          {hop.protocol}
                        </span>
                      )}
                      {isAnonymized && (
                        <span className="font-mono text-[9px] font-bold px-1.5 py-0.2 rounded bg-critical/15 text-critical border border-critical/30 uppercase">
                          {infraType}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* IP and Geolocation */}
                  <div className="space-y-1 text-xs font-mono">
                    <div className="flex items-center justify-between gap-1">
                      <span className="font-bold text-foreground truncate select-all" title={hop.ip}>
                        {hop.ip || 'Unknown IP'}
                      </span>
                      {hop.ip && (
                        <button
                          onClick={(e) => handleCopyIp(hop.ip!, e)}
                          className="p-1 rounded text-muted-foreground hover:text-foreground hover:bg-surface-2 transition-colors"
                          title="Copy IP"
                        >
                          {copiedIp === hop.ip ? <Check className="size-3 text-clean" /> : <Copy className="size-3" />}
                        </button>
                      )}
                    </div>

                    {geo && (
                      <div className="text-[11px] text-muted-foreground truncate flex items-center gap-1">
                        <Globe className="size-3 shrink-0" />
                        <span className="truncate">
                          {geo.city ? `${geo.city}, ` : ''}{geo.country || 'Unknown'}
                          {geo.org ? ` · ${geo.org}` : ''}
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Latency & Host Details */}
                  <div className="pt-2 border-t border-border/30 flex items-center justify-between text-[10px] font-mono text-muted-foreground">
                    <span className="truncate max-w-[140px]" title={rawHop.from_host || rawHop.hostname}>
                      {rawHop.from_host || rawHop.hostname || '—'}
                    </span>
                    {delaySec !== null && (
                      <span className="flex items-center gap-0.5 text-foreground font-semibold">
                        <Clock className="size-2.5" />
                        +{delaySec}s
                      </span>
                    )}
                  </div>

                  {/* Anomaly Alerts */}
                  {anomalies.length > 0 && (
                    <div className="pt-1 flex flex-wrap gap-1">
                      {anomalies.map((flag, fIdx) => (
                        <span
                          key={fIdx}
                          className="font-mono text-[9px] px-1.5 py-0.2 rounded bg-high/10 text-high border border-high/30 font-semibold"
                        >
                          {flag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* DETAILED LEDGER VIEW */}
      {viewMode === 'detailed' && (
        <div className="space-y-3">
          {hops.map((hop, index) => (
            <RelayHopNode
              key={index}
              hop={hop}
              index={index}
              totalHops={hops.length}
              isOrigin={index === 0}
              isDestination={index === hops.length - 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default RelayPathViewer;
