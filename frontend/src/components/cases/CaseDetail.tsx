import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { formatDistanceToNow } from 'date-fns';
import {
  AlertCircle,
  ArrowLeft,
  Calendar,
  Clock,
  ExternalLink,
  FileCheck2,
  FileText,
  FolderOpen,
  History,
  Link2,
  Loader2,
  Mail,
  MessageSquare,
  Plus,
  ShieldAlert,
  Trash2,
  Unlink,
  User,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useCase, useCaseEmails, useDeleteCase, useLinkCaseEmail, useUnlinkCaseEmail, useUpdateCase } from '@/hooks/useCases';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { CaseSeverity, CaseStatus } from '@/types/case';
import CaseNotes from './CaseNotes';
import CaseTimeline from './CaseTimeline';
import { cn } from '@/lib/utils';

interface CaseDetailProps {
  caseId: string;
  onBack: () => void;
}

export default function CaseDetail({ caseId, onBack }: CaseDetailProps) {
  const navigate = useNavigate();
  const { data: caseItem, isLoading, isError, refetch } = useCase(caseId);
  const { data: linkedEmails, isLoading: isEmailsLoading } = useCaseEmails(caseId);

  const updateCaseMutation = useUpdateCase();
  const deleteCaseMutation = useDeleteCase();
  const linkEmailMutation = useLinkCaseEmail();
  const unlinkEmailMutation = useUnlinkCaseEmail();

  const [activeTab, setActiveTab] = useState('overview');
  const [isLinkModalOpen, setIsLinkModalOpen] = useState(false);
  const [selectedEmailToLink, setSelectedEmailToLink] = useState('');
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // Query available emails for linking
  const { data: availableEmailsData } = useQuery({
    queryKey: ['emails', { page: 1, pageSize: 50 }],
    queryFn: () => api.getEmails(1, 50),
    enabled: isLinkModalOpen,
  });

  const availableEmails = availableEmailsData?.data?.items || [];
  const linkedEmailIds = new Set((linkedEmails || []).map((e: any) => e.id));
  const unlinkedEmails = availableEmails.filter((e) => !linkedEmailIds.has(e.id));

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
      onBack();
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
      <div className="panel flex flex-col items-center justify-center p-16 text-muted-foreground gap-3">
        <Loader2 className="size-8 animate-spin text-primary" />
        <p className="label-mono text-[10px]">LOADING CASE PROFILE...</p>
      </div>
    );
  }

  if (isError || !caseItem) {
    return (
      <div className="panel p-8 text-center border-critical/40">
        <AlertCircle className="size-10 text-critical mx-auto mb-3" />
        <h3 className="text-base font-semibold text-foreground">Failed to load case</h3>
        <p className="text-xs text-muted-foreground mt-1 mb-4">
          The requested case could not be found or failed to load.
        </p>
        <div className="flex justify-center gap-2">
          <Button variant="outline" size="sm" onClick={onBack} className="text-xs font-mono border-border">
            BACK TO CASES
          </Button>
          <Button size="sm" onClick={() => refetch()} className="text-xs font-mono">
            RETRY
          </Button>
        </div>
      </div>
    );
  }

  const getSeverityBadge = (sev?: string) => {
    switch (sev) {
      case 'critical':
        return <span className="font-mono uppercase font-bold text-[10px] px-2 py-0.5 rounded bg-critical/15 text-critical border border-critical/30">Critical</span>;
      case 'high':
        return <span className="font-mono uppercase font-bold text-[10px] px-2 py-0.5 rounded bg-high/15 text-high border border-high/30">High</span>;
      case 'medium':
        return <span className="font-mono uppercase font-bold text-[10px] px-2 py-0.5 rounded bg-medium/15 text-medium border border-medium/30">Medium</span>;
      default:
        return <span className="font-mono uppercase font-bold text-[10px] px-2 py-0.5 rounded bg-clean/15 text-clean border border-clean/30">Low</span>;
    }
  };

  return (
    <div className="space-y-5">
      {/* Top Breadcrumb & Actions Header */}
      <div className="panel p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={onBack}
            className="size-8 p-0 shrink-0 border-border bg-surface hover:bg-muted"
            title="Back to Cases list"
          >
            <ArrowLeft className="size-4" />
          </Button>

          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h2 className="text-lg sm:text-xl font-bold tracking-tight text-foreground">{caseItem.title}</h2>
              {getSeverityBadge(caseItem.severity)}
            </div>
            <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5 font-mono">
              <span>ID: {caseItem.id.slice(0, 8)}...</span>
              <span>•</span>
              <span className="capitalize">Status: {caseItem.status}</span>
            </div>
          </div>
        </div>

        {/* Status / Severity Quick Dropdowns & Delete */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Status Switcher */}
          <div className="flex items-center bg-surface border border-border rounded p-0.5 font-mono text-[10px]">
            {(['open', 'investigating', 'closed'] as const).map((st) => (
              <button
                key={st}
                onClick={() => handleStatusChange(st)}
                disabled={updateCaseMutation.isPending}
                className={cn(
                  'px-2 py-0.5 rounded transition-colors uppercase',
                  caseItem.status === st
                    ? 'bg-primary text-primary-foreground font-semibold shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                )}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Severity Switcher */}
          <div className="flex items-center bg-surface border border-border rounded p-0.5 font-mono text-[10px]">
            {(['low', 'medium', 'high', 'critical'] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => handleSeverityChange(sev)}
                disabled={updateCaseMutation.isPending}
                className={cn(
                  'px-2 py-0.5 rounded transition-colors uppercase',
                  caseItem.severity === sev
                    ? 'bg-surface-2 text-foreground font-bold shadow-sm border border-border'
                    : 'text-muted-foreground hover:text-foreground'
                )}
              >
                {sev}
              </button>
            ))}
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsDeleteConfirmOpen(true)}
            className="h-7 text-xs text-critical hover:bg-critical/10 hover:text-critical border-critical/30"
          >
            <Trash2 className="size-3.5" />
          </Button>
        </div>
      </div>

      {actionError && (
        <div className="flex items-center gap-1.5 text-xs text-critical bg-critical/10 border border-critical/20 rounded p-2.5 font-mono">
          <AlertCircle className="size-4 shrink-0" />
          <span>{actionError}</span>
        </div>
      )}

      {/* Tabs Navigation */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-surface-2 p-1 border border-border">
          <TabsTrigger value="overview" className="text-xs font-mono gap-1.5">
            <FolderOpen className="size-3.5" />
            OVERVIEW
          </TabsTrigger>
          <TabsTrigger value="evidence" className="text-xs font-mono gap-1.5">
            <Mail className="size-3.5" />
            LINKED EVIDENCE ({linkedEmails?.length || 0})
          </TabsTrigger>
          <TabsTrigger value="notes" className="text-xs font-mono gap-1.5">
            <MessageSquare className="size-3.5" />
            ANALYST NOTES
          </TabsTrigger>
          <TabsTrigger value="timeline" className="text-xs font-mono gap-1.5">
            <History className="size-3.5" />
            TIMELINE & AUDIT
          </TabsTrigger>
        </TabsList>

        {/* Tab 1: Overview */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="panel p-3.5 flex items-center gap-3">
              <div className="size-9 rounded bg-primary/10 flex items-center justify-center text-primary border border-primary/20">
                <User className="size-4" />
              </div>
              <div>
                <p className="label-mono text-[9px]">ASSIGNEE</p>
                <p className="text-xs font-semibold text-foreground">{caseItem.assigned_to || 'Lead Analyst'}</p>
              </div>
            </div>

            <div className="panel p-3.5 flex items-center gap-3">
              <div className="size-9 rounded bg-primary/10 flex items-center justify-center text-primary border border-primary/20">
                <Mail className="size-4" />
              </div>
              <div>
                <p className="label-mono text-[9px]">LINKED EVIDENCE</p>
                <p className="text-xs font-semibold text-foreground font-mono">{linkedEmails?.length || 0} Records</p>
              </div>
            </div>

            <div className="panel p-3.5 flex items-center gap-3">
              <div className="size-9 rounded bg-clean/10 flex items-center justify-center text-clean border border-clean/20">
                <Calendar className="size-4" />
              </div>
              <div>
                <p className="label-mono text-[9px]">CREATED</p>
                <p className="text-xs font-semibold text-foreground font-mono">
                  {caseItem.created_at
                    ? formatDistanceToNow(new Date(caseItem.created_at), { addSuffix: true })
                    : 'recent'}
                </p>
              </div>
            </div>

            <div className="panel p-3.5 flex items-center gap-3">
              <div className="size-9 rounded bg-purple-500/10 flex items-center justify-center text-purple-400 border border-purple-500/20">
                <Clock className="size-4" />
              </div>
              <div>
                <p className="label-mono text-[9px]">LAST MODIFIED</p>
                <p className="text-xs font-semibold text-foreground font-mono">
                  {caseItem.updated_at
                    ? formatDistanceToNow(new Date(caseItem.updated_at), { addSuffix: true })
                    : 'recent'}
                </p>
              </div>
            </div>
          </div>

          <div className="panel p-5 space-y-2">
            <h3 className="label-mono font-bold flex items-center gap-2 text-foreground">
              <FileText className="size-3.5 text-primary" />
              CASE HYPOTHESIS & THREAT CONTEXT
            </h3>
            <p className="text-xs text-foreground/90 leading-relaxed whitespace-pre-wrap font-mono bg-surface/50 p-3 rounded border border-border/50">
              {caseItem.description || 'No description provided for this investigation case.'}
            </p>
          </div>
        </TabsContent>

        {/* Tab 2: Linked Evidence */}
        <TabsContent value="evidence" className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="label-mono font-bold text-foreground flex items-center gap-2">
              <Mail className="size-3.5 text-primary" />
              ASSOCIATED EVIDENCE ({linkedEmails?.length || 0})
            </h3>
            <Button
              size="sm"
              onClick={() => setIsLinkModalOpen(true)}
              className="h-7 text-xs font-mono font-bold gap-1.5"
            >
              <Plus className="size-3.5" />
              LINK EVIDENCE
            </Button>
          </div>

          {isEmailsLoading && (
            <div className="panel flex flex-col items-center justify-center p-8 text-muted-foreground gap-2">
              <Loader2 className="size-6 animate-spin text-primary" />
              <span className="label-mono text-[10px]">FETCHING LINKED ARTIFACTS...</span>
            </div>
          )}

          {!isEmailsLoading && (!linkedEmails || linkedEmails.length === 0) && (
            <div className="panel p-8 text-center text-muted-foreground border-dashed">
              <Mail className="size-8 opacity-40 mx-auto mb-2 text-muted-foreground" />
              <p className="text-xs font-medium text-foreground">No email evidence attached to this case</p>
              <p className="text-[11px] text-muted-foreground mt-0.5 mb-3">
                Link analyzed phishing lures or BEC emails to correlate IOCs and campaign signals.
              </p>
              <Button size="sm" variant="outline" onClick={() => setIsLinkModalOpen(true)} className="text-xs font-mono border-border">
                LINK EMAIL EVIDENCE
              </Button>
            </div>
          )}

          {!isEmailsLoading && linkedEmails && linkedEmails.length > 0 && (
            <div className="space-y-2">
              {linkedEmails.map((email: any) => (
                <div key={email.id} className="panel p-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h4 className="text-xs font-semibold text-foreground truncate max-w-[320px]">
                        {email.subject || 'No Subject'}
                      </h4>
                      <span className="label-mono text-[9px] uppercase px-1.5 py-0.5 rounded bg-surface border border-border">
                        {email.status || 'analyzed'}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-[11px] text-muted-foreground font-mono">
                      <span className="truncate max-w-[200px]">From: {email.sender}</span>
                      {email.raw_hash_sha256 && (
                        <span className="hidden sm:inline">SHA-256: {email.raw_hash_sha256.slice(0, 16)}...</span>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => navigate(`/emails/${email.id}`)}
                      className="h-7 text-xs font-mono px-2 gap-1 border-border"
                      title="View detailed threat analysis"
                    >
                      <ExternalLink className="size-3" />
                      ANALYSIS
                    </Button>

                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => navigate(`/reports?emailId=${email.id}`)}
                      className="h-7 text-xs font-mono px-2 gap-1 border-border"
                      title="View forensic report"
                    >
                      <FileCheck2 className="size-3 text-primary" />
                      REPORT
                    </Button>

                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleUnlinkEmail(email.id)}
                      disabled={unlinkEmailMutation.isPending}
                      className="size-7 p-0 text-muted-foreground hover:text-critical"
                      title="Unlink from case"
                    >
                      <Unlink className="size-3.5" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </TabsContent>

        {/* Tab 3: Notes */}
        <TabsContent value="notes">
          <CaseNotes caseId={caseId} />
        </TabsContent>

        {/* Tab 4: Timeline */}
        <TabsContent value="timeline">
          <CaseTimeline caseId={caseId} onEmailClick={(id) => navigate(`/emails/${id}`)} />
        </TabsContent>
      </Tabs>

      {/* Link Email Evidence Modal */}
      <Dialog open={isLinkModalOpen} onOpenChange={setIsLinkModalOpen}>
        <DialogContent className="max-w-md panel p-6">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-sm font-bold text-foreground">
              <Link2 className="size-4 text-primary" />
              Link Email Evidence
            </DialogTitle>
            <DialogDescription className="text-xs text-muted-foreground">
              Select an analyzed email evidence file to attach to this investigation case.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3 py-2">
            {unlinkedEmails.length === 0 ? (
              <p className="text-xs text-muted-foreground text-center py-4">
                No unlinked email records available.
              </p>
            ) : (
              <div className="max-h-60 overflow-y-auto space-y-1.5 pr-1">
                {unlinkedEmails.map((email) => (
                  <div
                    key={email.id}
                    onClick={() => setSelectedEmailToLink(email.id)}
                    className={cn(
                      'p-2.5 rounded border text-xs cursor-pointer transition-all',
                      selectedEmailToLink === email.id
                        ? 'border-primary bg-primary/10 shadow-glow'
                        : 'border-border/50 bg-surface/50 hover:bg-surface'
                    )}
                  >
                    <p className="font-semibold text-foreground truncate">{email.subject || 'No Subject'}</p>
                    <div className="flex items-center justify-between text-[10px] text-muted-foreground mt-1 font-mono">
                      <span className="truncate max-w-[180px]">{email.sender}</span>
                      <span className="uppercase">{email.status}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <DialogFooter className="gap-2 border-t border-border/50 pt-2">
            <Button variant="outline" size="sm" onClick={() => setIsLinkModalOpen(false)} className="text-xs font-mono border-border">
              CANCEL
            </Button>
            <Button
              size="sm"
              onClick={handleLinkEmail}
              disabled={!selectedEmailToLink || linkEmailMutation.isPending}
              className="text-xs font-mono font-bold gap-1.5"
            >
              {linkEmailMutation.isPending ? <Loader2 className="size-3.5 animate-spin" /> : <Link2 className="size-3.5" />}
              <span>LINK SELECTED EMAIL</span>
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Modal */}
      <Dialog open={isDeleteConfirmOpen} onOpenChange={setIsDeleteConfirmOpen}>
        <DialogContent className="max-w-sm panel p-6">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-critical text-sm font-bold">
              <ShieldAlert className="size-4" />
              Delete Investigation Case
            </DialogTitle>
            <DialogDescription className="text-xs text-muted-foreground">
              Are you sure you want to delete <strong className="text-foreground">{caseItem.title}</strong>? This action will cascade delete attached notes and log a permanent audit record.
            </DialogDescription>
          </DialogHeader>

          <DialogFooter className="gap-2 border-t border-border/50 pt-2">
            <Button variant="outline" size="sm" onClick={() => setIsDeleteConfirmOpen(false)} className="text-xs font-mono border-border">
              CANCEL
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleDeleteCase}
              disabled={deleteCaseMutation.isPending}
              className="text-xs font-mono font-bold gap-1.5"
            >
              {deleteCaseMutation.isPending ? <Loader2 className="size-3.5 animate-spin" /> : <Trash2 className="size-3.5" />}
              <span>CONFIRM DELETE</span>
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

