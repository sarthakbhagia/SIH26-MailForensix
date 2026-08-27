import { EmailDetail as EmailDetailType } from '@/types/email';
import { Paperclip, Link as LinkIcon, FileText } from 'lucide-react';

export interface EmailDetailProps {
  email: EmailDetailType;
}

export function EmailDetail({ email }: EmailDetailProps) {
  return (
    <div className="space-y-5">
      {/* Email Body Inspector */}
      <div className="panel p-5 space-y-3">
        <div className="flex items-center justify-between border-b border-border/50 pb-2.5">
          <div className="flex items-center gap-2">
            <FileText className="size-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">Extracted Body Content</h3>
          </div>
          <span className="label-mono text-[10px]">
            {email.body_html ? 'HTML & TEXT PAYLOAD' : 'PLAIN TEXT PAYLOAD'}
          </span>
        </div>

        <div className="bg-background/80 rounded-md p-4 border border-border/60 max-h-[380px] overflow-y-auto">
          <pre className="font-mono text-xs text-foreground/90 leading-relaxed whitespace-pre-wrap select-all">
            {email.body_text || 'No plain text payload present in this message.'}
          </pre>
        </div>
      </div>

      {/* Attachments & URLs Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Attachments Panel */}
        <div className="panel p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-border/50 pb-2">
            <div className="flex items-center gap-2">
              <Paperclip className="size-3.5 text-accent" />
              <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                Attachments ({email.attachments?.length || 0})
              </h4>
            </div>
            <span className="label-mono text-[9px]">EVIDENTIARY ARTIFACTS</span>
          </div>

          <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
            {(!email.attachments || email.attachments.length === 0) ? (
              <p className="text-xs text-muted-foreground py-3 text-center">No attachments found.</p>
            ) : (
              email.attachments.map((att, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between gap-2 p-2 rounded bg-surface border border-border/60 text-xs"
                >
                  <div className="truncate min-w-0">
                    <p className="font-mono text-xs font-medium text-foreground truncate">{att.filename}</p>
                    {att.content_type && (
                      <p className="text-[10px] text-muted-foreground font-mono">{att.content_type}</p>
                    )}
                  </div>
                  <span className="font-mono text-[10px] text-muted-foreground shrink-0 px-2 py-0.5 rounded bg-muted/60">
                    {att.size ? `${(att.size / 1024).toFixed(1)} KB` : '—'}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Extracted URLs Panel */}
        <div className="panel p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-border/50 pb-2">
            <div className="flex items-center gap-2">
              <LinkIcon className="size-3.5 text-primary" />
              <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                Extracted URLs ({email.urls?.length || 0})
              </h4>
            </div>
            <span className="label-mono text-[9px]">SUSPICIOUS HYPERLINKS</span>
          </div>

          <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
            {(!email.urls || email.urls.length === 0) ? (
              <p className="text-xs text-muted-foreground py-3 text-center">No URLs extracted.</p>
            ) : (
              email.urls.map((url, i) => (
                <div
                  key={i}
                  className="p-2 rounded bg-surface border border-border/60 text-xs font-mono text-primary/90 break-all hover:bg-surface-2 transition-colors select-all"
                  title={url}
                >
                  {url}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default EmailDetail;

