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

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useAlerts } from '@/hooks/useAlerts';
import { Alert } from '@/types/alert';

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
        <Badge
          variant="destructive"
          className="bg-red-500/20 text-red-400 border border-red-500/40 text-[10px] font-bold tracking-wider uppercase px-2 py-0.5 flex items-center gap-1"
        >
          <ShieldAlert className="w-3 h-3 text-red-400" />
          Critical
        </Badge>
      );
    }
    if (s === 'high') {
      return (
        <Badge
          variant="secondary"
          className="bg-amber-500/20 text-amber-400 border border-amber-500/40 text-[10px] font-bold tracking-wider uppercase px-2 py-0.5 flex items-center gap-1"
        >
          <AlertTriangle className="w-3 h-3 text-amber-400" />
          High
        </Badge>
      );
    }
    return (
      <Badge
        variant="outline"
        className="bg-muted text-muted-foreground text-[10px] font-bold tracking-wider uppercase px-2 py-0.5"
      >
        {severity}
      </Badge>
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
    <Card className="h-full flex flex-col bg-card/60 backdrop-blur-md border border-border/50 shadow-sm">
      <CardHeader className="pb-3.5 pt-4 px-5 shrink-0 border-b border-border/40 flex flex-row items-center justify-between space-y-0">
        <div className="flex items-center gap-2.5">
          <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-primary" />
            Recent Alerts
          </CardTitle>

          {/* Connection status indicator */}
          <div
            className="flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-full border bg-background/50 text-muted-foreground"
            title={`WebSocket: ${connectionStatus}`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                connectionStatus === 'connected'
                  ? 'bg-emerald-500 animate-pulse'
                  : connectionStatus === 'connecting' || connectionStatus === 'reconnecting'
                  ? 'bg-amber-500 animate-pulse'
                  : 'bg-muted-foreground'
              }`}
            />
            <span className="capitalize text-[10px]">{connectionStatus === 'connected' ? 'Live' : connectionStatus}</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {stats && (
            <Badge
              variant={stats.unacknowledged > 0 ? 'destructive' : 'outline'}
              className={`text-[11px] font-semibold px-2 py-0.5 ${
                stats.unacknowledged > 0
                  ? 'bg-red-500/15 text-red-400 border-red-500/30'
                  : 'bg-muted/50 text-muted-foreground border-border/50'
              }`}
            >
              {stats.unacknowledged} unacknowledged
            </Badge>
          )}
        </div>
      </CardHeader>

      <CardContent className="flex-1 overflow-hidden p-0 flex flex-col justify-between">
        <div className="space-y-2.5 h-[340px] overflow-y-auto p-4 scrollbar-thin scrollbar-thumb-border scrollbar-track-transparent">
          {/* Loading State */}
          {isLoading && (
            <div className="space-y-2.5">
              {[1, 2, 3].map((n) => (
                <div
                  key={n}
                  className="p-3.5 rounded-xl border border-border/40 bg-muted/20 animate-pulse space-y-2"
                >
                  <div className="flex justify-between items-center">
                    <div className="h-4 w-16 bg-muted rounded" />
                    <div className="h-3 w-12 bg-muted rounded" />
                  </div>
                  <div className="h-4 w-3/4 bg-muted rounded" />
                  <div className="h-3 w-1/2 bg-muted rounded" />
                </div>
              ))}
            </div>
          )}

          {/* Error State */}
          {!isLoading && isError && (
            <div className="h-full flex flex-col items-center justify-center p-6 text-center">
              <AlertTriangle className="w-8 h-8 text-amber-400 mb-2" />
              <p className="text-sm font-medium text-foreground">Failed to load alerts</p>
              <p className="text-xs text-muted-foreground mt-1 mb-3">
                Could not retrieve latest threat alerts.
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetch()}
                className="h-8 text-xs gap-1.5"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Retry
              </Button>
            </div>
          )}

          {/* Empty State */}
          {!isLoading && !isError && displayAlerts.length === 0 && (
            <div className="h-full flex flex-col items-center justify-center p-6 text-center">
              <CheckCircle2 className="w-9 h-9 text-emerald-400 mb-2 opacity-80" />
              <p className="text-sm font-medium text-foreground">No active threat alerts</p>
              <p className="text-xs text-muted-foreground mt-1 max-w-[240px]">
                No critical or high-risk incidents detected in the current stream.
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
                  className={`relative flex flex-col gap-2 p-3.5 rounded-xl border transition-all duration-300 ${
                    isHighlighted
                      ? 'border-amber-500/70 bg-amber-500/10 shadow-md shadow-amber-500/10 ring-1 ring-amber-500/50'
                      : alert.acknowledged
                      ? 'border-border/30 bg-background/20 opacity-75 hover:opacity-100 hover:bg-muted/30'
                      : 'border-border/60 bg-background/40 hover:bg-muted/40 shadow-sm'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      {renderSeverityBadge(alert.severity)}
                      <span className="text-xs font-semibold px-2 py-0.5 rounded bg-muted/60 text-foreground/80 border border-border/40">
                        Risk: {alert.risk_score ? alert.risk_score.toFixed(0) : '0'}
                      </span>
                    </div>
                    <span className="text-[11px] text-muted-foreground font-medium whitespace-nowrap">
                      {formatTimestamp(alert.created_at)}
                    </span>
                  </div>

                  <p className="text-xs font-medium text-foreground/90 leading-snug line-clamp-2">
                    {title}
                  </p>

                  <div className="flex items-center justify-between pt-1 mt-0.5 border-t border-border/20">
                    <div className="flex items-center gap-2">
                      {alert.email_id && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => navigate(`/emails/${alert.email_id}`)}
                          className="h-6 px-2 text-[11px] text-primary hover:text-primary/80 hover:bg-primary/10 gap-1 font-medium -ml-1"
                        >
                          View Analysis
                          <ExternalLink className="w-3 h-3" />
                        </Button>
                      )}
                    </div>

                    <div>
                      {alert.acknowledged ? (
                        <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-medium px-2 py-0.5">
                          <Check className="w-3 h-3" />
                          Acknowledged
                        </span>
                      ) : (
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={isPendingAck}
                          onClick={() => handleAcknowledge(alert.id)}
                          className="h-6 px-2 text-[11px] border-border/60 hover:bg-emerald-500/10 hover:text-emerald-400 hover:border-emerald-500/30 gap-1 font-medium transition-colors"
                        >
                          {isPendingAck ? (
                            <Loader2 className="w-3 h-3 animate-spin" />
                          ) : (
                            <Check className="w-3 h-3" />
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
      </CardContent>
    </Card>
  );
}

