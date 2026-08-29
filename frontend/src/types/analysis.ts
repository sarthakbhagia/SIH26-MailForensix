export interface NLPResult {
  label: string;
  confidence?: number | null;
  confidence_calibrated?: boolean;
  confidence_method?: string | null;
  evidence_score?: number | null;
  details?: Record<string, any>;
}

export interface AuthResult {
  spf_status: 'pass' | 'softfail' | 'fail' | 'neutral' | 'none' | 'unavailable' | string;
  spf_domain?: string;
  spf_ip?: string;
  spf_record?: string;
  spf_details?: string;
  dkim_status: 'pass' | 'fail' | 'none' | 'unavailable' | string;
  dkim_domain?: string;
  dkim_selector?: string;
  dkim_details?: string;
  dmarc_status: 'pass' | 'fail' | 'none' | 'unavailable' | string;
  dmarc_policy?: 'none' | 'quarantine' | 'reject' | string;
  dmarc_domain?: string;
  dmarc_record?: string;
  dmarc_details?: string;
  alignment_spf?: boolean;
  alignment_dkim?: boolean;
  auth_confidence_score?: number | null;
  details?: Record<string, unknown>;
}

export interface GeoLocation {
  ip: string;
  country: string;
  country_code?: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  isp: string;
  asn: string;
  org: string;
  confidence: 'high' | 'medium' | 'low' | 'unavailable' | string;
  infrastructure_type?: string;
  vpn?: boolean;
  proxy?: boolean;
  tor?: boolean;
  hosting?: boolean;
  source?: string;
}

export interface RelayHop {
  hop_number: number;
  ip: string;
  hostname: string;
  timestamp: string;
  protocol: string;
  geo?: GeoLocation;
}

export interface IOCItem {
  type: 'ip' | 'url' | 'domain' | 'hash' | string;
  value: string;
  risk_score: number;
  reason: string;
  source: string;
}

export interface AnalysisResult {
  email_id: string;
  status?: 'pending' | 'processing' | 'analyzed' | 'error' | string;
  error_message?: string | null;
  nlp_result?: NLPResult | null;
  auth_result?: AuthResult | null;
  relay_path?: RelayHop[];
  geo_data?: GeoLocation[];
  iocs?: IOCItem[];
  composite_risk_score?: number | null;
  risk_breakdown?: Record<string, any>;
  attribution_category?: string | null;
  attribution_confidence?: number | null;
  attribution_confidence_calibrated?: boolean;
  attribution_evidence_score?: number | null;
}

