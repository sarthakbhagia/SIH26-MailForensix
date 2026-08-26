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

import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
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
        return <FolderPlus className="w-4 h-4 text-emerald-400" />;
      case 'email_linked':
        return <Mail className="w-4 h-4 text-sky-400" />;
      case 'note_added':
        return <MessageSquare className="w-4 h-4 text-amber-400" />;
      case 'audit_event':
        if (action?.includes('report')) return <FileCheck2 className="w-4 h-4 text-purple-400" />;
        if (action?.includes('status')) return <Activity className="w-4 h-4 text-indigo-400" />;
        return <ShieldAlert className="w-4 h-4 text-amber-400" />;
      default:
        return <Clock className="w-4 h-4 text-muted-foreground" />;
    }
  };

  const getEventBadge = (item: CaseTimelineItem) => {
    switch (item.type) {
      case 'case_created':
        return (
          <Badge variant="outline" className="text-[10px] bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
            Case Created
          </Badge>
        );
      case 'email_linked':
        return (
          <Badge variant="outline" className="text-[10px] bg-sky-500/10 text-sky-400 border-sky-500/30">
            Evidence Linked
          </Badge>
        );
      case 'note_added':
        return (
          <Badge variant="outline" className="text-[10px] bg-amber-500/10 text-amber-400 border-amber-500/30">
            Analyst Note
          </Badge>
        );
      case 'audit_event':
        return (
          <Badge variant="outline" className="text-[10px] bg-purple-500/10 text-purple-400 border-purple-500/30">
            Audit Trail
          </Badge>
        );
      default:
        return (
          <Badge variant="outline" className="text-[10px]">
            Activity
          </Badge>
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
        <div className="flex flex-col items-center justify-center p-12 text-muted-foreground gap-2">
          <Loader2 className="w-6 h-6 animate-spin text-primary" />
          <span className="text-xs">Aggregating case timeline & audit ledger...</span>
        </div>
      )}

      {!isLoading && isError && (
        <div className="p-4 text-center text-xs text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded-lg">
          Failed to load timeline events.{' '}
          <button onClick={() => refetch()} className="underline font-semibold ml-1">
            Retry
          </button>
        </div>
      )}

      {!isLoading && !isError && (!timeline || timeline.length === 0) && (
        <Card className="flex flex-col items-center justify-center p-8 text-center text-muted-foreground border-dashed bg-card/30">
          <History className="w-8 h-8 opacity-40 mb-2 text-muted-foreground" />
          <p className="text-xs font-medium text-foreground">No timeline events recorded yet</p>
          <p className="text-[11px] text-muted-foreground mt-0.5 max-w-xs">
            Activities, notes, and evidence associations will appear here chronologically.
          </p>
        </Card>
      )}

      {!isLoading && !isError && timeline && timeline.length > 0 && (
        <div className="relative pl-6 space-y-6 before:absolute before:left-[11px] before:top-2 before:bottom-2 before:w-[2px] before:bg-border/60">
          {timeline.map((item, idx) => (
            <div key={idx} className="relative group">
              {/* Timeline Node */}
              <div className="absolute -left-[23px] top-1 w-6 h-6 rounded-full bg-background border-2 border-border/80 flex items-center justify-center shadow-sm group-hover:border-primary transition-colors">
                {getEventIcon(item.type, item.action)}
              </div>

              {/* Event Content Card */}
              <Card className="bg-card/50 border-border/50 shadow-sm hover:border-border/80 transition-all ml-2">
                <CardContent className="p-3.5 space-y-2">
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
                    <div className="flex items-center justify-between bg-muted/40 rounded-md p-2 text-xs">
                      <div className="truncate max-w-[320px]">
                        <span className="text-muted-foreground">Sender: </span>
                        <span className="text-foreground font-medium">{item.details?.sender || 'Unknown'}</span>
                      </div>
                      <button
                        onClick={() => handleEmailNavigate(item.email_id!)}
                        className="inline-flex items-center gap-1 text-[11px] font-semibold text-primary hover:underline"
                      >
                        Inspect Analysis
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </div>
                  )}

                  {item.type === 'note_added' && item.details?.content && (
                    <p className="text-xs text-foreground/90 whitespace-pre-wrap pl-3 border-l-2 border-amber-500/40">
                      {item.details.content}
                    </p>
                  )}

                  {item.type === 'case_created' && item.details?.description && (
                    <p className="text-xs text-muted-foreground pl-3 border-l-2 border-emerald-500/40">
                      {item.details.description}
                    </p>
                  )}

                  {item.type === 'audit_event' && item.details && (
                    <div className="bg-muted/20 rounded p-2 text-[11px] font-mono text-muted-foreground overflow-x-auto">
                      {typeof item.details === 'object'
                        ? JSON.stringify(item.details, null, 2)
                        : String(item.details)}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
