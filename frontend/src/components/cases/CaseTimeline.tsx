import { useNavigate } from 'react-router-dom';
import { formatDistanceToNow } from 'date-fns';
import {
  Activity,
  Clock,
  ExternalLink,
  FileCheck2,
  FolderPlus,
  History,
  Loader2,
  Mail,
  MessageSquare,
  ShieldAlert,
} from 'lucide-react';
import { useCaseTimeline } from '@/hooks/useCases';
import { CaseTimelineItem } from '@/types/case';

interface CaseTimelineProps {
  caseId: string;
  onEmailClick?: (emailId: string) => void;
}

export default function CaseTimeline({ caseId, onEmailClick }: CaseTimelineProps) {
  const navigate = useNavigate();
  const { data: timeline, isLoading, isError, refetch } = useCaseTimeline(caseId);

  const getEventIcon = (type: string, action?: string) => {
    switch (type) {
      case 'case_created':
        return <FolderPlus className="size-3.5 text-clean" />;
      case 'email_linked':
        return <Mail className="size-3.5 text-primary" />;
      case 'note_added':
        return <MessageSquare className="size-3.5 text-medium" />;
      case 'audit_event':
        if (action?.includes('report')) return <FileCheck2 className="size-3.5 text-purple-400" />;
        if (action?.includes('status')) return <Activity className="size-3.5 text-primary" />;
        return <ShieldAlert className="size-3.5 text-medium" />;
      default:
        return <Clock className="size-3.5 text-muted-foreground" />;
    }
  };

  const getEventBadge = (item: CaseTimelineItem) => {
    switch (item.type) {
      case 'case_created':
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-clean/10 text-clean border border-clean/30 uppercase">
            Case Created
          </span>
        );
      case 'email_linked':
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/30 uppercase">
            Evidence Linked
          </span>
        );
      case 'note_added':
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-medium/10 text-medium border border-medium/30 uppercase">
            Analyst Note
          </span>
        );
      case 'audit_event':
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/30 uppercase">
            Audit Trail
          </span>
        );
      default:
        return (
          <span className="font-mono text-[9px] px-1.5 py-0.5 rounded bg-surface border border-border uppercase">
            Activity
          </span>
        );
    }
  };

  const handleEmailNavigate = (emailId: string) => {
    if (onEmailClick) {
      onEmailClick(emailId);
    } else {
      navigate(`/emails/${emailId}`);
    }
  };

  return (
    <div className="space-y-4">
      {isLoading && (
        <div className="panel flex flex-col items-center justify-center p-12 text-muted-foreground gap-2">
          <Loader2 className="size-6 animate-spin text-primary" />
          <span className="label-mono text-[10px]">AGGREGATING CASE AUDIT LEDGER...</span>
        </div>
      )}

      {!isLoading && isError && (
        <div className="panel p-4 text-center text-xs text-medium border-medium/30">
          Failed to load timeline events.{' '}
          <button onClick={() => refetch()} className="underline font-semibold ml-1">
            Retry
          </button>
        </div>
      )}

      {!isLoading && !isError && (!timeline || timeline.length === 0) && (
        <div className="panel flex flex-col items-center justify-center p-8 text-center text-muted-foreground border-dashed">
          <History className="size-8 opacity-40 mb-2 text-muted-foreground" />
          <p className="text-xs font-medium text-foreground">No timeline events recorded yet</p>
          <p className="text-[11px] text-muted-foreground mt-0.5 max-w-xs">
            Activities, notes, and evidence associations will appear here chronologically.
          </p>
        </div>
      )}

      {!isLoading && !isError && timeline && timeline.length > 0 && (
        <div className="relative pl-6 space-y-4 before:absolute before:left-[11px] before:top-2 before:bottom-2 before:w-[2px] before:bg-border/60">
          {timeline.map((item, idx) => (
            <div key={idx} className="relative group">
              {/* Timeline Node */}
              <div className="absolute -left-[23px] top-1.5 size-6 rounded-full bg-background border-2 border-border flex items-center justify-center shadow-sm group-hover:border-primary transition-colors">
                {getEventIcon(item.type, item.action)}
              </div>

              {/* Event Content Card */}
              <div className="panel p-3 space-y-2 hover:border-border transition-all ml-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {getEventBadge(item)}
                    <h4 className="text-xs font-semibold text-foreground">{item.title}</h4>
                  </div>

                  <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-mono">
                    <span>{item.actor || 'System'}</span>
                    <span>•</span>
                    <span>
                      {item.timestamp
                        ? formatDistanceToNow(new Date(item.timestamp), { addSuffix: true })
                        : 'recently'}
                    </span>
                  </div>
                </div>

                {/* Context Details */}
                {item.type === 'email_linked' && item.email_id && (
                  <div className="flex items-center justify-between bg-surface/60 rounded p-2 text-xs border border-border/50">
                    <div className="truncate max-w-[320px] font-mono text-[11px]">
                      <span className="text-muted-foreground">Sender: </span>
                      <span className="text-foreground font-medium">{item.details?.sender || 'Unknown'}</span>
                    </div>
                    <button
                      onClick={() => handleEmailNavigate(item.email_id!)}
                      className="inline-flex items-center gap-1 text-[11px] font-mono font-semibold text-primary hover:underline"
                    >
                      Inspect Analysis
                      <ExternalLink className="size-3" />
                    </button>
                  </div>
                )}

                {item.type === 'note_added' && item.details?.content && (
                  <p className="text-xs text-foreground/90 whitespace-pre-wrap pl-3 border-l-2 border-medium font-mono">
                    {item.details.content}
                  </p>
                )}

                {item.type === 'case_created' && item.details?.description && (
                  <p className="text-xs text-muted-foreground pl-3 border-l-2 border-clean font-mono">
                    {item.details.description}
                  </p>
                )}

                {item.type === 'audit_event' && item.details && (
                  <div className="bg-background/80 rounded p-2 text-[10px] font-mono text-muted-foreground overflow-x-auto border border-border/50">
                    {typeof item.details === 'object'
                      ? JSON.stringify(item.details, null, 2)
                      : String(item.details)}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

