export interface NLPResult {
  label: string;
  confidence: number;
  details: Record<string, number>;
}

export interface AuthResult {
  spf_status: 'pass' | 'softfail' | 'fail' | 'none';
  dkim_status: 'pass' | 'fail' | 'none';
  dmarc_status: 'pass' | 'fail' | 'none';
  details: Record<string, unknown>;
}

export interface GeoLocation {
  ip: string;
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  isp: string;
  asn: string;
  org: string;
  confidence: 'high' | 'medium' | 'low';
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
  type: 'ip' | 'url' | 'domain' | 'hash';
  value: string;
  risk_score: number;
  reason: string;
  source: string;
}

export interface AnalysisResult {
  email_id: string;
  nlp_result: NLPResult;
  auth_result: AuthResult;
  relay_path: RelayHop[];
  geo_data: GeoLocation[];
  iocs: IOCItem[];
  composite_risk_score: number;
  risk_breakdown: Record<string, number>;
  attribution_category: string;
  attribution_confidence: number;
}
