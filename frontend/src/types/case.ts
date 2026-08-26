export type CaseStatus = 'open' | 'investigating' | 'closed';
export type CaseSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface Case {
  id: string;
  title: string;
  description?: string;
  status: CaseStatus;
  severity: CaseSeverity;
  created_at: string;
  updated_at: string;
  assigned_to?: string;
  email_ids?: string[];
  notes?: CaseNote[];
}

export interface CaseNote {
  id: string;
  case_id?: string;
  author: string;
  content: string;
  created_at: string;
}

export interface CaseTimelineItem {
  type: 'case_created' | 'email_linked' | 'note_added' | 'audit_event' | string;
  timestamp: string;
  actor?: string;
  title: string;
  details?: any;
  email_id?: string;
  note_id?: string;
  action?: string;
  severity?: string;
}

export interface CaseFilterParams {
  status?: CaseStatus;
  severity?: CaseSeverity;
  limit?: number;
  offset?: number;
}

export interface CreateCaseInput {
  title: string;
  description: string;
  severity?: CaseSeverity;
  assigned_to?: string;
}

export interface UpdateCaseInput {
  title?: string;
  description?: string;
  status?: CaseStatus;
  severity?: CaseSeverity;
  assigned_to?: string;
}

export interface CreateCaseNoteInput {
  content: string;
  author?: string;
}

