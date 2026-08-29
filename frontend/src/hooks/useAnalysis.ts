import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import { AnalysisResult } from '../types/analysis';

export function useAnalysis(emailId: string) {
  return useQuery<AnalysisResult, Error>({
    queryKey: ['analysis', emailId],
    queryFn: () => api.getAnalysis(emailId).then((res) => res.data),
    enabled: !!emailId,
    refetchInterval: (query) => {
      const data = query.state.data;
      // Auto-poll if analysis is still in progress (pending or processing)
      if (data && (data.status === 'pending' || data.status === 'processing')) {
        return 2000;
      }
      // If query failed (e.g., initial 404 while backend is ingesting), poll briefly
      if (query.state.error && query.state.errorUpdateCount < 10) {
        return 2500;
      }
      return false;
    },
    retry: (failureCount, error: any) => {
      // Allow initial 404 retries during ingestion transition window
      if (error?.response?.status === 404 && failureCount < 4) {
        return true;
      }
      return failureCount < 2;
    },
  });
}

export function useReanalyzeEmail() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (emailId: string) => api.reanalyzeEmail(emailId).then((res) => res.data),
    onSuccess: (_, emailId) => {
      queryClient.invalidateQueries({ queryKey: ['analysis', emailId] });
      queryClient.invalidateQueries({ queryKey: ['email', emailId] });
      queryClient.invalidateQueries({ queryKey: ['emails'] });
    },
  });
}

