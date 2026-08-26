export interface EmailSummary {
  id: string;
  sender: string;
  subject: string;
  ingested_at: string;
  status: 'pending' | 'processing' | 'analyzed' | 'error';
  risk_score?: number;
}

export interface EmailUploadResponse {
  case_id?: string | null;
  email_id: string;
  status: string;
  hashes: { sha256: string; sha1?: string; md5?: string };
  ingested_at: string;
}

export interface EmailDetail extends EmailSummary {
  recipients: string[];
  body_text: string;
  body_html: string;
  headers: Record<string, string>;
  attachments: AttachmentInfo[];
  urls: string[];
}

export interface AttachmentInfo {
  filename: string;
  content_type: string;
  size: number;
  sha256: string;
}
