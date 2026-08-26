import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';

export function useEmails(page = 1, filters = {}) {
  return useQuery({
    queryKey: ['emails', page, filters],
    queryFn: () => api.getEmails(page, 10, filters).then((res) => res.data),
  });
}

export function useEmail(id: string) {
  return useQuery({
    queryKey: ['email', id],
    queryFn: () => api.getEmail(id).then((res) => res.data),
    enabled: !!id,
  });
}

export function useUploadEmail() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (file: File) => api.uploadEmail(file).then((res) => res.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['emails'] });
    },
  });
}
