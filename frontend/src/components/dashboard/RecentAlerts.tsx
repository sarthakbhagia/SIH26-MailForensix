import { useEffect, useState } from 'react';
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
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAlerts } from '@/hooks/useAlerts';
import { Alert } from '@/types/alert';
import { cn } from '@/lib/utils';

export default function RecentAlerts() {
  const navigate = useNavigate();
  const {
    alerts,
    stats,
    liveAlerts,
    connectionStatus,
    isLoading,
    isError,
    acknowledge,
    isAcknowledging,
    refetch,
  } = useAlerts({ page_size: 5 });

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

  // Combine and deduplicate top 5 alerts
  const displayAlerts: Alert[] = Array.from(
    new Map([...liveAlerts, ...alerts].map((a) => [a.id, a])).values()
  ).slice(0, 5);

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

  const renderSeverityBadge = (severity: string) => {
    const s = severity?.toLowerCase();
    if (s === 'critical') {
      return (
        <span className="px-2 py-0.5 rounded font-mono text-[9px] font-bold uppercase tracking-wider bg-critical/15 text-critical border border-critical/40 flex items-center gap-1">
          <ShieldAlert className="size-3" />
          Critical
        </span>
      );
    }
    if (s === 'high') {
      return (
        <span className="px-2 py-0.5 rounded font-mono text-[9px] font-bold uppercase tracking-wider bg-high/15 text-high border border-high/40 flex items-center gap-1">
          <AlertTriangle className="size-3" />
          High
        </span>
      );
    }
    if (s === 'medium') {
      return (
        <span className="px-2 py-0.5 rounded font-mono text-[9px] font-bold uppercase tracking-wider bg-medium/15 text-medium border border-medium/40">
          Medium
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded font-mono text-[9px] font-bold uppercase tracking-wider bg-muted text-muted-foreground border border-border">
        {severity}
      </span>
    );
  };

  const formatTimestamp = (created_at: string) => {
    try {
      return formatDistanceToNow(new Date(created_at), { addSuffix: true });
    } catch {
      return 'recently';
    }
  };

  return (
    <div className="panel h-full flex flex-col p-4 sm:p-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-3">
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="size-4 text-primary" />
          <h3 className="text-sm font-semibold tracking-tight text-foreground">Recent Threat Alerts</h3>

          {/* Connection status indicator */}
          <div
            className="flex items-center gap-1.5 text-[10px] font-mono px-2 py-0.5 rounded border border-border bg-surface text-muted-foreground"
            title={`WebSocket status: ${connectionStatus}`}
          >
            <span
              className={cn(
                'size-1.5 rounded-full',
                connectionStatus === 'connected'
                  ? 'bg-clean animate-pulse'
                  : connectionStatus === 'connecting' || connectionStatus === 'reconnecting'
                  ? 'bg-medium animate-pulse'
                  : 'bg-muted-foreground'
              )}
            />
            <span className="uppercase">{connectionStatus === 'connected' ? 'LIVE FEED' : connectionStatus}</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {stats && (
            <span
              className={cn(
                'font-mono text-[10px] font-bold uppercase px-2 py-0.5 rounded border',
                stats.unacknowledged > 0
                  ? 'bg-critical/15 text-critical border-critical/30'
                  : 'bg-surface text-muted-foreground border-border'
              )}
            >
              {stats.unacknowledged} UNACKNOWLEDGED
            </span>
          )}
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-hidden pt-3 flex flex-col justify-between">
        <div className="space-y-2.5 max-h-[350px] overflow-y-auto pr-1">
          {/* Loading State */}
          {isLoading && (
            <div className="space-y-2.5">
              {[1, 2, 3].map((n) => (
                <div key={n} className="p-3.5 rounded bg-surface/50 border border-border/40 animate-pulse space-y-2">
                  <div className="flex justify-between items-center">
                    <div className="h-3.5 w-16 bg-muted rounded" />
                    <div className="h-3 w-12 bg-muted rounded" />
                  </div>
                  <div className="h-3.5 w-3/4 bg-muted rounded" />
                </div>
              ))}
            </div>
          )}

          {/* Error State */}
          {!isLoading && isError && (
            <div className="h-full flex flex-col items-center justify-center p-6 text-center">
              <AlertTriangle className="size-7 text-medium mb-2" />
              <p className="text-xs font-semibold text-foreground">Failed to synchronize alerts</p>
              <p className="text-[11px] text-muted-foreground mt-0.5 mb-3">
                Could not retrieve latest threat alerts.
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetch()}
                className="h-7 text-xs font-mono gap-1.5"
              >
                <RefreshCw className="size-3" />
                Retry
              </Button>
            </div>
          )}

          {/* Empty State */}
          {!isLoading && !isError && displayAlerts.length === 0 && (
            <div className="h-full flex flex-col items-center justify-center p-6 text-center">
              <CheckCircle2 className="size-8 text-clean mb-2 opacity-80" />
              <p className="text-xs font-semibold text-foreground">No active threat alerts</p>
              <p className="text-[11px] text-muted-foreground mt-0.5 max-w-[220px]">
                No critical or high-risk incidents detected in the current telemetry stream.
              </p>
            </div>
          )}

          {/* Alert List */}
          {!isLoading &&
            !isError &&
            displayAlerts.map((alert) => {
              const isHighlighted = highlightedIds.has(alert.id);
              const isPendingAck = acknowledgingId === alert.id || (isAcknowledging && acknowledgingId === alert.id);
              const title =
                (typeof alert.contributing_factors === 'object' &&
                  !Array.isArray(alert.contributing_factors) &&
                  alert.contributing_factors?.title) ||
                alert.message;

              return (
                <div
                  key={alert.id}
                  className={cn(
                    'relative flex flex-col gap-2 p-3 rounded border transition-all duration-300',
                    isHighlighted
                      ? 'border-accent/80 bg-accent/10 shadow-glow'
                      : alert.acknowledged
                      ? 'border-border/30 bg-surface/30 opacity-70 hover:opacity-100 hover:bg-surface'
                      : 'border-border/60 bg-surface/60 hover:bg-surface hover:border-border'
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      {renderSeverityBadge(alert.severity)}
                      <span className="font-mono text-[10px] font-bold text-foreground px-2 py-0.5 rounded bg-surface-2 border border-border">
                        RISK {alert.risk_score ? alert.risk_score.toFixed(0) : '0'}
                      </span>
                    </div>
                    <span className="label-mono text-[10px]">
                      {formatTimestamp(alert.created_at)}
                    </span>
                  </div>

                  <p className="text-xs text-foreground/90 font-medium leading-snug line-clamp-2">
                    {title}
                  </p>

                  <div className="flex items-center justify-between pt-1.5 mt-0.5 border-t border-border/30">
                    <div>
                      {alert.email_id && (
                        <button
                          onClick={() => navigate(`/emails/${alert.email_id}`)}
                          className="inline-flex items-center gap-1 font-mono text-[11px] text-primary hover:text-primary/80 transition-colors"
                        >
                          <span>Analyze Evidence</span>
                          <ExternalLink className="size-3" />
                        </button>
                      )}
                    </div>

                    <div>
                      {alert.acknowledged ? (
                        <span className="inline-flex items-center gap-1 font-mono text-[10px] text-clean font-semibold uppercase">
                          <Check className="size-3" />
                          Acked
                        </span>
                      ) : (
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={isPendingAck}
                          onClick={() => handleAcknowledge(alert.id)}
                          className="h-6 px-2 text-[10px] font-mono border-border/70 hover:bg-clean/15 hover:text-clean hover:border-clean/40 gap-1 transition-colors"
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
            })}
        </div>
      </div>
    </div>
  );
}


