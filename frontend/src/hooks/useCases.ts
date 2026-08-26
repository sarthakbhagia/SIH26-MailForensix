import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import {
  Case,
  CaseFilterParams,
  CaseNote,
  CaseTimelineItem,
  CreateCaseInput,
  CreateCaseNoteInput,
  UpdateCaseInput,
} from '@/types/case';

/**
 * Hook to fetch paginated/filtered cases list.
 */
export function useCases(params?: CaseFilterParams) {
  return useQuery<Case[]>({
    queryKey: ['cases', params],
    queryFn: async () => {
      const response = await api.getCases(params);
      return response.data;
    },
    staleTime: 15000,
  });
}

/**
 * Hook to fetch single case details.
 */
export function useCase(caseId: string | null | undefined) {
  return useQuery<Case>({
    queryKey: ['case', caseId],
    queryFn: async () => {
      if (!caseId) throw new Error('Case ID is required');
      const response = await api.getCase(caseId);
      return response.data;
    },
    enabled: Boolean(caseId),
    staleTime: 15000,
  });
}

/**
 * Hook to fetch emails associated with a case.
 */
export function useCaseEmails(caseId: string | null | undefined) {
  return useQuery({
    queryKey: ['case', caseId, 'emails'],
    queryFn: async () => {
      if (!caseId) return [];
      const response = await api.getCaseEmails(caseId);
      return response.data;
    },
    enabled: Boolean(caseId),
    staleTime: 15000,
  });
}

/**
 * Hook to fetch notes for a specific case.
 */
export function useCaseNotes(caseId: string | null | undefined) {
  return useQuery<CaseNote[]>({
    queryKey: ['case', caseId, 'notes'],
    queryFn: async () => {
      if (!caseId) return [];
      const response = await api.getCaseNotes(caseId);
      return response.data;
    },
    enabled: Boolean(caseId),
    staleTime: 10000,
  });
}

/**
 * Hook to fetch the unified chronological timeline for a case.
 */
export function useCaseTimeline(caseId: string | null | undefined) {
  return useQuery<CaseTimelineItem[]>({
    queryKey: ['case', caseId, 'timeline'],
    queryFn: async () => {
      if (!caseId) return [];
      const response = await api.getCaseTimeline(caseId);
      return response.data;
    },
    enabled: Boolean(caseId),
    staleTime: 10000,
  });
}

/**
 * Hook to create a new case.
 */
export function useCreateCase() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (data: CreateCaseInput | Partial<Case>) => {
      const response = await api.createCase(data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
    },
  });
}

/**
 * Hook to update an existing case.
 */
export function useUpdateCase() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ id, data }: { id: string; data: UpdateCaseInput | Partial<Case> }) => {
      const response = await api.updateCase(id, data);
      return response.data;
    },
    onSuccess: (updatedCase) => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      queryClient.invalidateQueries({ queryKey: ['case', updatedCase.id] });
      queryClient.invalidateQueries({ queryKey: ['case', updatedCase.id, 'timeline'] });
    },
  });
}

/**
 * Hook to delete a case.
 */
export function useDeleteCase() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      const response = await api.deleteCase(id);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
    },
  });
}

/**
 * Hook to add an analyst investigation note to a case.
 */
export function useAddCaseNote() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ caseId, note }: { caseId: string; note: CreateCaseNoteInput }) => {
      const response = await api.addCaseNote(caseId, note);
      return response.data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['case', variables.caseId, 'notes'] });
      queryClient.invalidateQueries({ queryKey: ['case', variables.caseId, 'timeline'] });
      queryClient.invalidateQueries({ queryKey: ['case', variables.caseId] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
    },
  });
}

/**
 * Hook to link an email evidence record to a case.
 */
export function useLinkCaseEmail() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ caseId, emailId }: { caseId: string; emailId: string }) => {
      const response = await api.linkCaseEmail(caseId, emailId);
      return response.data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['case', variables.caseId, 'emails'] });
      queryClient.invalidateQueries({ queryKey: ['case', variables.caseId, 'timeline'] });
      queryClient.invalidateQueries({ queryKey: ['case', variables.caseId] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
    },
  });
}

/**
 * Hook to unlink an email from a case.
 */
export function useUnlinkCaseEmail() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ caseId, emailId }: { caseId: string; emailId: string }) => {
      const response = await api.unlinkCaseEmail(caseId, emailId);
      return response.data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['case', variables.caseId, 'emails'] });
      queryClient.invalidateQueries({ queryKey: ['case', variables.caseId, 'timeline'] });
      queryClient.invalidateQueries({ queryKey: ['case', variables.caseId] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
    },
  });
}
