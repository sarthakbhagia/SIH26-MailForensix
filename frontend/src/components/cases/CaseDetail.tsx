import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertCircle,
  ExternalLink,
  History,
  Link2,
  Loader2,
  Mail,
  MessageSquare,
  Trash2,
  Unlink,
  Share2,
  MapPin,
  Copy,
  Check,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { SeverityBadge } from '@/components/forensics/SeverityBadge';
import {
  useCase,
  useCaseEmails,
  useDeleteCase,
  useLinkCaseEmail,
  useUnlinkCaseEmail,
  useUpdateCase,
} from '@/hooks/useCases';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { CaseSeverity, CaseStatus } from '@/types/case';
import { cn, safeFormatDateOnly, safeFormatDistanceToNow } from '@/lib/utils';
import CaseNotes from './CaseNotes';
import CaseTimeline from './CaseTimeline';
import { getSeverityTokens } from '@/lib/severity';

export interface CaseDetailProps {
  caseId: string;
  onBack?: () => void;
  className?: string;
}

export function CaseDetail({ caseId, onBack, className }: CaseDetailProps) {
  const navigate = useNavigate();
  const { data: caseItem, isLoading, isError, refetch } = useCase(caseId);
  const { data: linkedEmails, isLoading: isEmailsLoading } = useCaseEmails(caseId);

  const updateCaseMutation = useUpdateCase();
  const deleteCaseMutation = useDeleteCase();
  const linkEmailMutation = useLinkCaseEmail();
  const unlinkEmailMutation = useUnlinkCaseEmail();

  const [activeTab, setActiveTab] = useState<'evidence' | 'notes' | 'timeline'>('evidence');
  const [isLinkModalOpen, setIsLinkModalOpen] = useState(false);
  const [selectedEmailToLink, setSelectedEmailToLink] = useState('');
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState(false);

  // Query available emails for linking
  const { data: availableEmailsData } = useQuery({
    queryKey: ['emails', { page: 1, pageSize: 50 }],
    queryFn: () => api.getEmails(1, 50),
    enabled: isLinkModalOpen,
  });

  const availableEmails = availableEmailsData?.data?.items || [];
  const linkedEmailIds = new Set((linkedEmails || []).map((e: any) => e.id));
  const unlinkedEmails = availableEmails.filter((e) => !linkedEmailIds.has(e.id));

  const handleCopyId = () => {
    navigator.clipboard.writeText(caseId);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 1800);
  };

  const handleStatusChange = async (newStatus: CaseStatus) => {
    try {
      setActionError(null);
      await updateCaseMutation.mutateAsync({
        id: caseId,
        data: { status: newStatus },
      });
    } catch (err: any) {
      console.error('Status update failed:', err);
      setActionError('Failed to update case status.');
    }
  };

  const handleSeverityChange = async (newSeverity: CaseSeverity) => {
    try {
      setActionError(null);
      await updateCaseMutation.mutateAsync({
        id: caseId,
        data: { severity: newSeverity },
      });
    } catch (err: any) {
      console.error('Severity update failed:', err);
      setActionError('Failed to update case severity.');
    }
  };

  const handleDeleteCase = async () => {
    try {
      setActionError(null);
      await deleteCaseMutation.mutateAsync(caseId);
      setIsDeleteConfirmOpen(false);
      if (onBack) onBack();
    } catch (err: any) {
      console.error('Delete case failed:', err);
      setActionError('Failed to delete case.');
    }
  };

  const handleLinkEmail = async () => {
    if (!selectedEmailToLink) return;
    try {
      setActionError(null);
      await linkEmailMutation.mutateAsync({
        caseId,
        emailId: selectedEmailToLink,
      });
      setSelectedEmailToLink('');
      setIsLinkModalOpen(false);
    } catch (err: any) {
      console.error('Link email failed:', err);
      setActionError('Failed to link email evidence.');
    }
  };

  const handleUnlinkEmail = async (emailId: string) => {
    try {
      setActionError(null);
      await unlinkEmailMutation.mutateAsync({
        caseId,
        emailId,
      });
    } catch (err: any) {
      console.error('Unlink email failed:', err);
      setActionError('Failed to unlink email.');
    }
  };

  if (isLoading) {
    return (
      <div className="panel flex flex-col items-center justify-center p-16 text-muted-foreground gap-3 h-full">
        <Loader2 className="size-8 animate-spin text-primary" />
        <span className="label-mono text-[10px]">LOADING CASE INVESTIGATION...</span>
      </div>
    );
  }

  if (isError || !caseItem) {
    return (
      <div className="panel p-8 text-center border-critical/40 my-auto">
        <AlertCircle className="size-10 text-critical mx-auto mb-3" />
        <h3 className="text-base font-semibold text-foreground">Failed to Load Investigation Case</h3>
        <p className="text-xs text-muted-foreground mt-1 mb-4">
          The requested case could not be retrieved from the datastore.
        </p>
        <Button size="sm" onClick={() => refetch()} className="text-xs font-mono">
          Retry
        </Button>
      </div>
    );
  }

  return (
    <div className={cn('flex flex-col h-full space-y-3 min-w-0', className)}>
      {/* 1. Master Header Card */}
      <div className="panel p-4 sm:p-5 space-y-3.5 shrink-0">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/50 pb-3">
          <div className="flex flex-wrap items-center gap-2">
            {onBack && (
              <Button
                variant="outline"
                size="sm"
                onClick={onBack}
                className="h-7 px-2 font-mono text-xs border-border md:hidden"
              >
                Queue
              </Button>
            )}

            {/* Case ID Pill */}
            <button
              onClick={handleCopyId}
              className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border border-border bg-surface-2 hover:bg-surface-3 text-[10px] font-mono text-muted-foreground hover:text-foreground transition-colors"
              title="Copy Case Identifier"
            >
              <span>CASE #{caseId.substring(0, 8)}</span>
              {copiedId ? <Check className="size-3 text-clean" /> : <Copy className="size-3" />}
            </button>

            <SeverityBadge severity={caseItem.severity} />
          </div>

          {/* Status / Severity Controls & Delete */}
          <div className="flex items-center gap-2">
            <select
              value={caseItem.status}
              onChange={(e) => handleStatusChange(e.target.value as CaseStatus)}
              className="h-7 rounded border border-border bg-surface-2 px-2 text-xs font-mono font-semibold text-foreground uppercase focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="open">STATUS: OPEN</option>
              <option value="investigating">STATUS: INVESTIGATING</option>
              <option value="closed">STATUS: CLOSED</option>
            </select>

            <select
              value={caseItem.severity}
              onChange={(e) => handleSeverityChange(e.target.value as CaseSeverity)}
              className="h-7 rounded border border-border bg-surface-2 px-2 text-xs font-mono font-semibold text-foreground uppercase focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="critical">SEV: CRITICAL</option>
              <option value="high">SEV: HIGH</option>
              <option value="medium">SEV: MEDIUM</option>
              <option value="low">SEV: LOW</option>
            </select>

            <Button
              variant="destructive"
              size="sm"
              onClick={() => setIsDeleteConfirmOpen(true)}
              className="h-7 px-2 gap-1 text-xs font-mono"
              title="Purge case record"
            >
              <Trash2 className="size-3" />
            </Button>
          </div>
        </div>

        {actionError && (
          <div className="p-2 rounded bg-critical/10 border border-critical/30 text-critical text-xs font-mono">
            {actionError}
          </div>
        )}

        {/* Case Title & Summary */}
        <div className="space-y-1">
          <h2 className="text-base sm:text-lg font-bold tracking-tight text-foreground break-words">
            {caseItem.title}
          </h2>
          {caseItem.description && (
            <p className="text-xs text-muted-foreground leading-relaxed">
              {caseItem.description}
            </p>
          )}
        </div>

        {/* Telemetry Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono pt-1">
          <div className="p-2 rounded bg-surface-2 border border-border/70">
            <span className="label-mono text-[9px] block">ASSIGNED ANALYST</span>
            <p className="font-semibold text-foreground truncate">{caseItem.assigned_to || 'Unassigned'}</p>
          </div>
          <div className="p-2 rounded bg-surface-2 border border-border/70">
            <span className="label-mono text-[9px] block">EVIDENCE ENVELOPES</span>
            <p className="font-semibold text-foreground">{caseItem.email_ids?.length || 0} Linked</p>
          </div>
          <div className="p-2 rounded bg-surface-2 border border-border/70">
            <span className="label-mono text-[9px] block">CREATED AT</span>
            <p className="font-semibold text-foreground truncate">{safeFormatDateOnly(caseItem.created_at)}</p>
          </div>
          <div className="p-2 rounded bg-surface-2 border border-border/70">
            <span className="label-mono text-[9px] block">LAST AUDITED</span>
            <p className="font-semibold text-foreground truncate">
              {safeFormatDistanceToNow(caseItem.updated_at, { addSuffix: true }, 'Never')}
            </p>
          </div>
        </div>
      </div>

      {/* 2. Investigation Workspace Tabs */}
      <div className="flex items-center gap-1 bg-surface-2 p-1 rounded border border-border shrink-0 select-none">
        <button
          onClick={() => setActiveTab('evidence')}
          className={cn(
            'px-3 py-1 rounded text-xs font-mono font-semibold flex items-center gap-1.5 transition-all',
            activeTab === 'evidence' ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
          )}
        >
          <Mail className="size-3.5" />
          <span>EVIDENCE ENVELOPES ({linkedEmails?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('notes')}
          className={cn(
            'px-3 py-1 rounded text-xs font-mono font-semibold flex items-center gap-1.5 transition-all',
            activeTab === 'notes' ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
          )}
        >
          <MessageSquare className="size-3.5" />
          <span>INVESTIGATOR REMARKS</span>
        </button>

        <button
          onClick={() => setActiveTab('timeline')}
          className={cn(
            'px-3 py-1 rounded text-xs font-mono font-semibold flex items-center gap-1.5 transition-all',
            activeTab === 'timeline' ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
          )}
        >
          <History className="size-3.5" />
          <span>AUDIT TIMELINE</span>
        </button>
      </div>

      {/* 3. Tab Content Viewport */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {activeTab === 'evidence' && (
          <div className="panel p-4 sm:p-5 space-y-3.5">
            <div className="flex items-center justify-between border-b border-border/50 pb-2.5">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                  Associated Email Envelopes ({linkedEmails?.length || 0})
                </h3>
                <p className="label-mono text-[9px]">CORRELATED THREAT EVIDENCE & EVIDENTIARY PIVOTS</p>
              </div>

              <Button
                size="sm"
                onClick={() => setIsLinkModalOpen(true)}
                className="h-7 px-2.5 text-xs font-mono gap-1.5 bg-primary text-primary-foreground font-semibold"
              >
                <Link2 className="size-3" />
                <span>Attach Evidence</span>
              </Button>
            </div>

            {isEmailsLoading ? (
              <div className="py-8 flex flex-col items-center justify-center gap-2 text-muted-foreground">
                <Loader2 className="size-6 animate-spin text-primary" />
                <span className="label-mono text-[10px]">FETCHING LINKED EVIDENCE...</span>
              </div>
            ) : !linkedEmails || linkedEmails.length === 0 ? (
              <div className="py-12 text-center text-muted-foreground flex flex-col items-center justify-center">
                <Mail className="size-8 opacity-30 mb-2" />
                <p className="text-xs font-semibold text-foreground">No email envelopes associated with this case</p>
                <p className="text-[11px] text-muted-foreground mt-0.5 max-w-sm">
                  Attach suspicious emails to correlate indicators of compromise and track incident response.
                </p>
              </div>
            ) : (
              <div className="space-y-2.5">
                {linkedEmails.map((email: any) => {
                  const riskTokens = getSeverityTokens(email.risk_score || 0);
                  return (
                    <div
                      key={email.id}
                      className="p-3 rounded border border-border bg-surface-2/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono hover:bg-surface-2 transition-colors"
                    >
                      <div className="min-w-0 flex-1 space-y-1">
                        <div className="flex items-center gap-2">
                          <span className={cn('px-1.5 py-0.2 rounded text-[10px] font-bold border tabular-nums', riskTokens.badgeClass)}>
                            RISK {email.risk_score ? email.risk_score.toFixed(0) : '0'}
                          </span>
                          <span className="label-mono text-[10px]">
                            {safeFormatDistanceToNow(email.ingested_at, { addSuffix: true })}
                          </span>
                        </div>
                        <p className="text-xs font-semibold text-foreground truncate" title={email.subject}>
                          {email.subject || '(No Subject)'}
                        </p>
                        <p className="text-[11px] text-muted-foreground truncate">
                          From: {email.sender || 'Unknown'}
                        </p>
                      </div>

                      {/* Tactical Investigation Pivots */}
                      <div className="flex flex-wrap items-center gap-1.5 shrink-0 pt-2 sm:pt-0 border-t sm:border-t-0 border-border/40">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => navigate(`/emails/${email.id}`)}
                          className="h-7 px-2 font-mono text-[11px] border-border gap-1"
                          title="Open full Email Analysis Workstation"
                        >
                          <span>Analyze</span>
                          <ExternalLink className="size-3" />
                        </Button>

                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => navigate(`/map?emailId=${email.id}`)}
                          className="h-7 px-2 font-mono text-[11px] border-border gap-1"
                          title="Inspect MTA Relay Trace Map"
                        >
                          <MapPin className="size-3 text-accent" />
                          <span>Map</span>
                        </Button>

                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => navigate(`/graph?emailId=${email.id}`)}
                          className="h-7 px-2 font-mono text-[11px] border-border gap-1"
                          title="Correlate in Threat Attribution Graph"
                        >
                          <Share2 className="size-3 text-primary" />
                          <span>Graph</span>
                        </Button>

                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleUnlinkEmail(email.id)}
                          className="h-7 px-1.5 text-muted-foreground hover:text-critical hover:bg-critical/10"
                          title="Unlink evidence from this case"
                        >
                          <Unlink className="size-3.5" />
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === 'notes' && (
          <CaseNotes caseId={caseId} />
        )}

        {activeTab === 'timeline' && (
          <CaseTimeline caseId={caseId} />
        )}
      </div>

      {/* Link Email Modal */}
      <Dialog open={isLinkModalOpen} onOpenChange={setIsLinkModalOpen}>
        <DialogContent className="max-w-md panel p-5">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base font-bold text-foreground">
              <Link2 className="size-4 text-primary" />
              Attach Email Evidence
            </DialogTitle>
            <DialogDescription className="text-xs text-muted-foreground">
              Select an ingested email envelope to associate with Case #{caseId.substring(0, 8)}.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3 py-2">
            {unlinkedEmails.length === 0 ? (
              <p className="text-xs text-muted-foreground text-center py-4 font-mono">
                No unlinked emails available in the ingestion ledger.
              </p>
            ) : (
              <select
                value={selectedEmailToLink}
                onChange={(e) => setSelectedEmailToLink(e.target.value)}
                className="w-full h-8 rounded border border-border bg-surface px-2.5 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="">-- Choose Ingested Email --</option>
                {unlinkedEmails.map((e: any) => (
                  <option key={e.id} value={e.id}>
                    [{e.risk_score ? `Risk: ${e.risk_score.toFixed(0)}` : 'Unscored'}] {e.subject || e.sender || e.id}
                  </option>
                ))}
              </select>
            )}
          </div>

          <DialogFooter className="gap-2 pt-2 border-t border-border/50">
            <Button variant="outline" size="sm" onClick={() => setIsLinkModalOpen(false)} className="text-xs font-mono border-border">
              Cancel
            </Button>
            <Button
              size="sm"
              disabled={!selectedEmailToLink || linkEmailMutation.isPending}
              onClick={handleLinkEmail}
              className="gap-1.5 font-mono text-xs bg-primary text-primary-foreground font-semibold"
            >
              {linkEmailMutation.isPending && <Loader2 className="size-3 animate-spin" />}
              <span>Attach Evidence</span>
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Modal */}
      <Dialog open={isDeleteConfirmOpen} onOpenChange={setIsDeleteConfirmOpen}>
        <DialogContent className="max-w-md panel p-5">
          <DialogHeader>
            <DialogTitle className="text-critical text-base font-bold">Confirm Case Purge</DialogTitle>
            <DialogDescription className="text-xs text-muted-foreground">
              Are you sure you want to permanently purge Case #{caseId.substring(0, 8)}? All analyst notes and timeline entries will be destroyed. Linked email envelopes will remain in the ingestion ledger.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2 pt-2 border-t border-border/50">
            <Button variant="outline" size="sm" onClick={() => setIsDeleteConfirmOpen(false)} className="text-xs font-mono border-border">
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              disabled={deleteCaseMutation.isPending}
              onClick={handleDeleteCase}
              className="gap-1.5 font-mono text-xs"
            >
              {deleteCaseMutation.isPending && <Loader2 className="size-3 animate-spin" />}
              <span>Confirm Purge</span>
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default CaseDetail;
