import { useState } from 'react';
import { Paperclip, FileCode2, Copy, Check, Hash } from 'lucide-react';
import { formatBytes } from '@/lib/severity';


export interface AttachmentItem {
  filename: string;
  content_type?: string;
  size?: number;
  sha256?: string;
  risk_score?: number;
  md5?: string;
}

export interface AttachmentViewerProps {
  attachments?: AttachmentItem[];
}

export function AttachmentViewer({ attachments = [] }: AttachmentViewerProps) {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const handleCopy = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 1800);
  };

  return (
    <div className="panel p-4 sm:p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border/50 pb-3">
        <div className="flex items-center gap-2">
          <Paperclip className="size-4 text-primary" />
          <h3 className="text-sm font-semibold tracking-tight text-foreground">
            Evidentiary Attachments & Payloads ({attachments.length})
          </h3>
        </div>
        <span className="label-mono text-[10px]">FORENSIC MIME ATTACHMENT LEDGER</span>
      </div>

      {/* Attachment Cards */}
      {attachments.length === 0 ? (
        <div className="p-12 text-center text-muted-foreground flex flex-col items-center justify-center">
          <Paperclip className="size-8 opacity-30 mb-2" />
          <p className="text-xs font-semibold text-foreground">No file attachments detected</p>
          <p className="text-[11px] text-muted-foreground mt-0.5">
            This message envelope contained only inline or plain text body payloads.
          </p>
        </div>
      ) : (
        <div className="space-y-2.5">
          {attachments.map((att, idx) => (
            <div
              key={idx}
              className="p-3.5 rounded border border-border bg-surface-2/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono"
            >
              <div className="flex items-start gap-3 min-w-0 flex-1">
                <div className="p-2 rounded bg-surface border border-border shrink-0 mt-0.5">
                  <FileCode2 className="size-4 text-accent" />
                </div>

                <div className="min-w-0 space-y-0.5 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-foreground text-xs truncate" title={att.filename}>
                      {att.filename}
                    </span>
                    {att.content_type && (
                      <span className="label-mono text-[9px] px-1.5 py-0.2 rounded bg-surface border border-border">
                        {att.content_type}
                      </span>
                    )}
                  </div>

                  {att.sha256 && (
                    <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground pt-1">
                      <Hash className="size-3 shrink-0" />
                      <span className="truncate select-all text-muted-foreground/80" title={att.sha256}>
                        SHA-256: {att.sha256}
                      </span>
                      <button
                        onClick={() => handleCopy(att.sha256!)}
                        className="p-0.5 hover:text-foreground text-muted-foreground transition-colors shrink-0"
                        title="Copy SHA-256 Hash"
                      >
                        {copiedHash === att.sha256 ? <Check className="size-3 text-clean" /> : <Copy className="size-3" />}
                      </button>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-center justify-between sm:justify-end gap-3 shrink-0 pt-2 sm:pt-0 border-t sm:border-t-0 border-border/40">
                <span className="label-mono text-[10px] text-foreground font-bold">
                  {formatBytes(att.size || 0)}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default AttachmentViewer;
