import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api';
import { ConnectionStatus, wsManager } from '../lib/websocket';
import { Alert, AlertFilterParams, AlertStats } from '../types/alert';

export interface UseAlertsOptions extends AlertFilterParams {
  autoConnect?: boolean;
}

export function useAlerts(options: UseAlertsOptions = {}) {
  const queryClient = useQueryClient();
  const [liveAlerts, setLiveAlerts] = useState<Alert[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>(wsManager.status);

  const { page, page_size, limit, offset, severity, acknowledged, autoConnect = true } = options;

  // 1. Fetch paginated alerts query
  const alertsQuery = useQuery({
    queryKey: ['alerts', { page, page_size, limit, offset, severity, acknowledged }],
    queryFn: async () => {
      const res = await api.getAlerts({ page, page_size, limit, offset, severity, acknowledged });
      return res.data;
    },
  });

  // 2. Fetch alert statistics query
  const statsQuery = useQuery({
    queryKey: ['alerts', 'stats'],
    queryFn: async () => {
      const res = await api.getAlertStats();
      return res.data;
    },
  });

  // 3. Acknowledge alert mutation
  const acknowledgeMutation = useMutation({
    mutationFn: async (alertId: string) => {
      const res = await api.acknowledgeAlert(alertId);
      return res.data;
    },
    onSuccess: (_, alertId) => {
      setLiveAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, acknowledged: true } : a))
      );
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      queryClient.invalidateQueries({ queryKey: ['alerts', 'stats'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });

  // 4. WebSocket live stream listener
  useEffect(() => {
    const unsubStatus = wsManager.onStatusChange(setConnectionStatus);

    const unsubAlert = wsManager.subscribe((incomingAlert: Alert) => {
      setLiveAlerts((prev) => {
        if (prev.some((a) => a.id === incomingAlert.id)) {
          return prev;
        }
        return [incomingAlert, ...prev];
      });

      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      queryClient.invalidateQueries({ queryKey: ['alerts', 'stats'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    });

    if (autoConnect) {
      wsManager.connect();
    }

    return () => {
      unsubStatus();
      unsubAlert();
    };
  }, [queryClient, autoConnect]);

  const acknowledge = useCallback(
    async (alertId: string) => {
      await acknowledgeMutation.mutateAsync(alertId);
    },
    [acknowledgeMutation]
  );

  return {
    alerts: alertsQuery.data?.items ?? [],
    total: alertsQuery.data?.total ?? 0,
    stats: statsQuery.data as AlertStats | undefined,
    liveAlerts,
    connectionStatus,
    isLoading: alertsQuery.isLoading,
    isError: alertsQuery.isError,
    error: alertsQuery.error,
    isStatsLoading: statsQuery.isLoading,
    acknowledge,
    isAcknowledging: acknowledgeMutation.isPending,
    refetch: alertsQuery.refetch,
    refetchStats: statsQuery.refetch,
  };
}

export function useAlertWebSocket() {
  const { liveAlerts, connectionStatus } = useAlerts();
  return { liveAlerts, connectionStatus };
}

