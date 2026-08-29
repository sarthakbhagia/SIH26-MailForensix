import { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { formatDistanceToNow } from 'date-fns';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ExternalLink,
  Loader2,
  RefreshCw,
  ShieldAlert,
  FolderPlus,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { SeverityBadge } from '@/components/forensics/SeverityBadge';
import { useAlerts } from '@/hooks/useAlerts';
import { Alert } from '@/types/alert';
import { cn } from '@/lib/utils';
import { getSeverityTokens } from '@/lib/severity';

export default function RecentAlerts() {
  const navigate = useNavigate();
  const {
    alerts,
    stats,
    liveAlerts,
    isLoading,
    isError,
    acknowledge,
    isAcknowledging,
    refetch,
  } = useAlerts({ page_size: 15 });

  const [activeFilter, setActiveFilter] = useState<'all' | 'unack' | 'critical'>('all');
  const [highlightedIds, setHighlightedIds] = useState<Set<string>>(new Set());
  const [acknowledgingId, setAcknowledgingId] = useState<string | null>(null);

  // Animate newly received live alerts
  useEffect(() => {
    if (liveAlerts.length > 0) {
      const newest = liveAlerts[0];
      setHighlightedIds((prev) => new Set(prev).add(newest.id));

      const timer = setTimeout(() => {
        setHighlightedIds((prev) => {
          const next = new Set(prev);
          next.delete(newest.id);
          return next;
        });
      }, 4000);

      return () => clearTimeout(timer);
    }
  }, [liveAlerts]);

  // Combine and deduplicate alerts
  const allAlerts: Alert[] = useMemo(() => {
    const map = new Map<string, Alert>();
    liveAlerts.forEach((a) => map.set(a.id, a));
    alerts.forEach((a) => {
      if (!map.has(a.id)) map.set(a.id, a);
    });
    return Array.from(map.values());
  }, [liveAlerts, alerts]);

  const filteredAlerts = useMemo(() => {
    return allAlerts.filter((alert) => {
      if (activeFilter === 'unack') return !alert.acknowledged;
      if (activeFilter === 'critical') {
        const sev = String(alert.severity || '').toLowerCase();
        return sev === 'critical' || sev === 'high' || (alert.risk_score || 0) >= 50;
      }
      return true;
    });
  }, [allAlerts, activeFilter]);

  const handleAcknowledge = async (alertId: string) => {
    try {
      setAcknowledgingId(alertId);
      await acknowledge(alertId);
    } catch (err) {
      console.error('Failed to acknowledge alert:', err);
    } finally {
      setAcknowledgingId(null);
    }
  };

  const formatTimestamp = (created_at: string) => {
    try {
      return formatDistanceToNow(new Date(created_at), { addSuffix: true });
    } catch {
      return 'recently';
    }
  };

  return (
    <div className="panel h-full flex flex-col p-4 sm:p-5 space-y-3.5">
      {/* Triage Queue Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/50 pb-3">
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="size-4 text-primary" />
          <h3 className="text-sm font-semibold tracking-tight text-foreground">Operational Alert Triage Queue</h3>

          {stats && stats.unacknowledged > 0 && (
            <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-critical/15 text-critical border border-critical/35 animate-pulse">
              {stats.unacknowledged} PENDING
            </span>
          )}
        </div>

        {/* Triage Queue Filter Pills */}
        <div className="flex items-center gap-1.5">
          <div className="flex items-center rounded border border-border bg-surface-2 p-0.5">
            <button
              onClick={() => setActiveFilter('all')}
              className={cn(
                'px-2 py-0.5 text-[10px] font-mono uppercase rounded transition-colors',
                activeFilter === 'all'
                  ? 'bg-primary text-primary-foreground font-semibold shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              All ({allAlerts.length})
            </button>
            <button
              onClick={() => setActiveFilter('unack')}
              className={cn(
                'px-2 py-0.5 text-[10px] font-mono uppercase rounded transition-colors',
                activeFilter === 'unack'
                  ? 'bg-primary text-primary-foreground font-semibold shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              Unacked ({stats?.unacknowledged ?? 0})
            </button>
            <button
              onClick={() => setActiveFilter('critical')}
              className={cn(
                'px-2 py-0.5 text-[10px] font-mono uppercase rounded transition-colors',
                activeFilter === 'critical'
                  ? 'bg-primary text-primary-foreground font-semibold shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              High/Crit
            </button>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            className="h-7 px-2 border-border text-xs"
            title="Refresh alerts"
          >
            <RefreshCw className="size-3" />
          </Button>
        </div>
      </div>

      {/* Alert Cards List */}
      <div className="flex-1 overflow-y-auto space-y-2.5 max-h-[380px] pr-1">
        {isLoading ? (
          <div className="py-12 flex flex-col items-center justify-center gap-2 text-muted-foreground">
            <Loader2 className="size-7 animate-spin text-primary" />
            <span className="label-mono text-[10px]">SYNCING INCIDENT STREAM...</span>
          </div>
        ) : isError ? (
          <div className="py-12 text-center text-muted-foreground">
            <AlertTriangle className="size-7 text-medium mx-auto mb-2" />
            <p className="text-xs font-semibold text-foreground">Failed to synchronize alerts</p>
            <Button variant="outline" size="sm" onClick={() => refetch()} className="mt-3 text-xs font-mono">
              Retry Sync
            </Button>
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="py-12 text-center text-muted-foreground flex flex-col items-center justify-center">
            <CheckCircle2 className="size-8 text-clean mb-2 opacity-70" />
            <p className="text-xs font-semibold text-foreground">Triage Queue Clear</p>
            <p className="text-[11px] text-muted-foreground mt-0.5 max-w-[220px]">
              No unacknowledged or high-priority threat alerts pending in the current stream.
            </p>
          </div>
        ) : (
          filteredAlerts.map((alert) => {
            const isHighlighted = highlightedIds.has(alert.id);
            const isPendingAck = acknowledgingId === alert.id || (isAcknowledging && acknowledgingId === alert.id);
            const title =
              (typeof alert.contributing_factors === 'object' &&
                !Array.isArray(alert.contributing_factors) &&
                alert.contributing_factors?.title) ||
              alert.message;
            const riskTokens = getSeverityTokens(alert.risk_score || 0);

            return (
              <div
                key={alert.id}
                className={cn(
                  'panel p-3 transition-all duration-150 space-y-2',
                  isHighlighted
                    ? 'border-accent bg-accent/10 shadow-glow'
                    : alert.acknowledged
                    ? 'opacity-65 hover:opacity-100 bg-surface/50 border-border/40'
                    : 'border-border hover:border-border-strong bg-surface'
                )}
              >
                {/* Alert Top Row */}
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={alert.severity} showDot />
                    <span className={cn('font-mono text-[10px] font-bold px-2 py-0.5 rounded border tabular-nums', riskTokens.badgeClass)}>
                      RISK {alert.risk_score ? alert.risk_score.toFixed(0) : '0'}
                    </span>
                  </div>

                  <span className="label-mono text-[10px]">
                    {formatTimestamp(alert.created_at)}
                  </span>
                </div>

                {/* Alert Title */}
                <p className="text-xs text-foreground font-semibold leading-snug">
                  {title}
                </p>

                {/* Bottom Action Strip */}
                <div className="flex items-center justify-between pt-1.5 border-t border-border/40 text-xs font-mono">
                  <div className="flex items-center gap-2">
                    {alert.email_id && (
                      <button
                        onClick={() => navigate(`/emails/${alert.email_id}`)}
                        className="inline-flex items-center gap-1 text-[11px] text-primary hover:underline font-semibold"
                      >
                        <span>Analyze Envelope</span>
                        <ExternalLink className="size-3" />
                      </button>
                    )}

                    <button
                      onClick={() =>
                        navigate(
                          `/cases?new=true&title=${encodeURIComponent(title)}${
                            alert.email_id ? `&emailId=${alert.email_id}` : ''
                          }`
                        )
                      }
                      className="inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"
                    >
                      <FolderPlus className="size-3" />
                      <span>Promote to Case</span>
                    </button>
                  </div>

                  <div>
                    {alert.acknowledged ? (
                      <span className="inline-flex items-center gap-1 text-[10px] text-clean font-semibold uppercase">
                        <Check className="size-3" />
                        Acked
                      </span>
                    ) : (
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={isPendingAck}
                        onClick={() => handleAcknowledge(alert.id)}
                        className="h-6 px-2 text-[10px] font-mono border-border hover:bg-clean/15 hover:text-clean hover:border-clean/40 gap-1 transition-colors"
                      >
                        {isPendingAck ? (
                          <Loader2 className="size-2.5 animate-spin" />
                        ) : (
                          <Check className="size-2.5" />
                        )}
                        Acknowledge
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
