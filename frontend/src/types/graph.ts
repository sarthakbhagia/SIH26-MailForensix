export type GraphNodeType = 'email' | 'domain' | 'ip' | 'registrar' | 'asn' | 'campaign';

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  color: string;
  risk_score?: number | null;
  val: number;
  // Specific attributes based on type
  subject?: string;
  sender?: string;
  analyzed_at?: string;
  country?: string;
  city?: string;
  isp?: string;
  infrastructure_type?: string;
  registrar?: string;
  age_days?: number;
  is_newly_registered?: boolean;
  org?: string;
  email_count?: number;
  summary?: string;
  confidence?: number;
  // Canvas / layout runtime coordinates
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  [key: string]: any;
}

export interface GraphLink {
  source: string | GraphNode;
  target: string | GraphNode;
  relationship: string;
  weight: number;
  shared_ips?: string[];
  shared_domains?: string[];
  hop_number?: number;
  [key: string]: any;
}

export interface Campaign {
  campaign_id: string;
  email_ids: string[];
  shared_indicators: {
    ips: string[];
    domains: string[];
    asns: string[];
  };
  content_similarity: number;
  temporal_span_hours: number;
  confidence: number;
  attribution: string;
  summary: string;
}

export interface SharedInfrastructure {
  node_id: string;
  type: string;
  label: string;
  connected_emails: string[];
  email_count: number;
}

export interface GraphStats {
  node_count: number;
  edge_count: number;
  density: number;
  connected_components: number;
  email_count: number;
  campaign_count: number;
}

export interface GraphDataResponse {
  nodes: GraphNode[];
  links: GraphLink[];
  stats: GraphStats;
  campaigns: Campaign[];
  shared_infrastructure: SharedInfrastructure[];
}

export interface GraphFilters {
  searchQuery: string;
  nodeTypes: Record<GraphNodeType, boolean>;
  minRiskScore: number;
  selectedCampaignId: string | null;
}
