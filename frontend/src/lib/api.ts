import axios from 'axios';
import { EmailSummary, EmailDetail, EmailUploadResponse } from '../types/email';
import { AnalysisResult } from '../types/analysis';
import { Case } from '../types/case';
import { AlertFilterParams, AlertListResponse, AlertStats } from '../types/alert';

const apiClient = axios.create({
  baseURL: '/api',
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error);
    return Promise.reject(error);
  }
);

export const api = {
  uploadEmail: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return apiClient.post<EmailUploadResponse>('/emails/upload', formData);
  },
  uploadEmails: (files: File[]) => {
    const formData = new FormData();
    files.forEach(file => formData.append('files', file));
    return apiClient.post<EmailUploadResponse[]>('/emails/upload-batch', formData);
  },
  getEmails: (page = 1, pageSize = 10, filters = {}) =>
    apiClient.get<{ items: EmailSummary[]; total: number; page: number; page_size: number }>('/emails', {
      params: { page, page_size: pageSize, ...filters },
    }),
  getEmail: (id: string) => apiClient.get<EmailDetail>(`/emails/${id}`),
  getAnalysis: (emailId: string) => apiClient.get<AnalysisResult>(`/analysis/${emailId}`),
  getCases: (params?: import('../types/case').CaseFilterParams) =>
    apiClient.get<Case[]>('/cases', { params }),
  getCase: (id: string) => apiClient.get<Case>(`/cases/${id}`),
  createCase: (data: import('../types/case').CreateCaseInput | Partial<Case>) =>
    apiClient.post<Case>('/cases', data),
  updateCase: (id: string, data: import('../types/case').UpdateCaseInput | Partial<Case>) =>
    apiClient.put<Case>(`/cases/${id}`, data),
  deleteCase: (id: string) =>
    apiClient.delete<{ status: string; case_id: string }>(`/cases/${id}`),
  linkCaseEmail: (caseId: string, emailId: string) =>
    apiClient.post<{ status: string; case_id: string; email_id: string }>(`/cases/${caseId}/emails/${emailId}`),
  unlinkCaseEmail: (caseId: string, emailId: string) =>
    apiClient.delete<{ status: string; case_id: string; email_id: string }>(`/cases/${caseId}/emails/${emailId}`),
  addCaseNote: (caseId: string, note: import('../types/case').CreateCaseNoteInput) =>
    apiClient.post<import('../types/case').CaseNote>(`/cases/${caseId}/notes`, note),
  getCaseNotes: (caseId: string) =>
    apiClient.get<import('../types/case').CaseNote[]>(`/cases/${caseId}/notes`),
  getCaseEmails: (caseId: string) =>
    apiClient.get<{ id: string; sender: string; subject: string; status: string; ingested_at?: string; raw_hash_sha256?: string }[]>(`/cases/${caseId}/emails`),
  getCaseTimeline: (caseId: string) =>
    apiClient.get<import('../types/case').CaseTimelineItem[]>(`/cases/${caseId}/timeline`),

  getAlerts: (params?: AlertFilterParams) =>
    apiClient.get<AlertListResponse>('/alerts', { params }),
  getAlertStats: () => apiClient.get<AlertStats>('/alerts/stats'),
  acknowledgeAlert: (id: string) =>
    apiClient.put<{ status: string; alert_id: string; acknowledged: boolean }>(`/alerts/${id}/acknowledge`),
  getDashboardStats: () => apiClient.get('/dashboard/stats'),
  getReportPdf: (emailId: string) => apiClient.get(`/reports/${emailId}/pdf`, { responseType: 'blob' }),
  getReportJson: (emailId: string) => apiClient.get(`/reports/${emailId}/json`),
  getGraph: () => apiClient.get<import('../types/graph').GraphDataResponse>('/graph'),
  getEmailGraph: (emailId: string) => apiClient.get<{ nodes: import('../types/graph').GraphNode[]; links: import('../types/graph').GraphLink[] }>(`/graph/email/${emailId}`),
  getCampaigns: () => apiClient.get<import('../types/graph').Campaign[]>('/graph/campaigns'),
  getCampaignDetail: (campaignId: string) => apiClient.get<{ campaign: import('../types/graph').Campaign; subgraph: { nodes: import('../types/graph').GraphNode[]; links: import('../types/graph').GraphLink[] } }>(`/graph/campaigns/${campaignId}`),
  getNodeConnections: (nodeId: string) => apiClient.get<{ node_id: string; connections: any[]; degree: number }>(`/graph/node/${encodeURIComponent(nodeId)}/connections`),
};
