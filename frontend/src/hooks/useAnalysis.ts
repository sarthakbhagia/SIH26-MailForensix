import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';

export function useAnalysis(emailId: string) {
  return useQuery({
    queryKey: ['analysis', emailId],
    queryFn: () => api.getAnalysis(emailId).then((res) => res.data),
    enabled: !!emailId,
  });
}
