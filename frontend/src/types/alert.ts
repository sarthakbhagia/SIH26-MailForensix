export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface AlertContributingFactors {
  title?: string;
  factors?: string[];
  recommended_action?: string;
  ioc_summary?: Array<{
    type: string;
    value: string;
    risk_score: number;
    reason?: string;
    source?: string;
  }>;
}

export interface Alert {
  id: string;
  email_id?: string;
  severity: AlertSeverity;
  message: string;
  risk_score: number;
  contributing_factors?: AlertContributingFactors | string[] | Record<string, any>;
  acknowledged: boolean;
  created_at: string;
}

export interface AlertListResponse {
  items: Alert[];
  total: number;
}

export interface AlertStats {
  total: number;
  unacknowledged: number;
  critical: number;
}

export interface AlertFilterParams {
  page?: number;
  page_size?: number;
  limit?: number;
  offset?: number;
  severity?: string;
  acknowledged?: boolean;
}

