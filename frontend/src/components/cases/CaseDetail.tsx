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

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
      <div className="flex flex-col items-center justify-center p-16 text-muted-foreground gap-3">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
        <p className="text-sm font-medium">Loading case details...</p>
      </div>
    );
  }

  if (isError || !caseItem) {
    return (
      <Card className="p-8 text-center bg-card/40 border-destructive/30">
        <AlertCircle className="w-10 h-10 text-destructive mx-auto mb-3" />
        <h3 className="text-base font-semibold text-foreground">Failed to load case</h3>
        <p className="text-xs text-muted-foreground mt-1 mb-4">
          The requested case could not be found or failed to load.
        </p>
        <div className="flex justify-center gap-2">
          <Button variant="outline" size="sm" onClick={onBack}>
            Back to Cases
          </Button>
          <Button size="sm" onClick={() => refetch()}>
            Retry
          </Button>
        </div>
      </Card>
    );
  }

  const getSeverityBadge = (sev?: string) => {
    switch (sev) {
      case 'critical':
        return <Badge variant="destructive" className="uppercase font-bold text-[10px] bg-red-500/20 text-red-400 border-red-500/40">Critical</Badge>;
      case 'high':
        return <Badge variant="secondary" className="uppercase font-bold text-[10px] bg-amber-500/20 text-amber-400 border-amber-500/40">High</Badge>;
      case 'medium':
        return <Badge variant="outline" className="uppercase font-bold text-[10px] bg-yellow-500/20 text-yellow-400 border-yellow-500/40">Medium</Badge>;
      default:
        return <Badge variant="outline" className="uppercase font-bold text-[10px] bg-emerald-500/20 text-emerald-400 border-emerald-500/40">Low</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Actions Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-border/40 pb-4">
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={onBack}
            className="h-8 w-8 p-0 shrink-0"
            title="Back to Cases list"
          >
            <ArrowLeft className="w-4 h-4" />
          </Button>

          <div>
            <div className="flex items-center gap-2.5">
              <h2 className="text-xl font-bold tracking-tight text-foreground">{caseItem.title}</h2>
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
        <div className="flex items-center gap-2">
          {/* Status Switcher */}
          <div className="flex items-center bg-background/60 border border-border/60 rounded-md p-0.5">
            {(['open', 'investigating', 'closed'] as const).map((st) => (
              <button
                key={st}
                onClick={() => handleStatusChange(st)}
                disabled={updateCaseMutation.isPending}
                className={`text-[11px] font-medium px-2.5 py-1 rounded transition-colors capitalize ${
                  caseItem.status === st
                    ? 'bg-primary text-primary-foreground font-semibold shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Severity Switcher */}
          <div className="flex items-center bg-background/60 border border-border/60 rounded-md p-0.5">
            {(['low', 'medium', 'high', 'critical'] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => handleSeverityChange(sev)}
                disabled={updateCaseMutation.isPending}
                className={`text-[11px] font-medium px-2 py-1 rounded transition-colors uppercase text-[10px] ${
                  caseItem.severity === sev
                    ? 'bg-muted text-foreground font-bold shadow-sm border border-border/80'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsDeleteConfirmOpen(true)}
            className="h-8 text-xs text-destructive hover:bg-destructive/10 hover:text-destructive border-destructive/30"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {actionError && (
        <div className="flex items-center gap-1.5 text-xs text-destructive bg-destructive/10 border border-destructive/20 rounded-md p-2.5">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{actionError}</span>
        </div>
      )}

      {/* Tabs Navigation */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-muted/40 p-1 border border-border/60">
          <TabsTrigger value="overview" className="text-xs gap-1.5">
            <FolderOpen className="w-3.5 h-3.5" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="evidence" className="text-xs gap-1.5">
            <Mail className="w-3.5 h-3.5" />
            Linked Evidence ({linkedEmails?.length || 0})
          </TabsTrigger>
          <TabsTrigger value="notes" className="text-xs gap-1.5">
            <MessageSquare className="w-3.5 h-3.5" />
            Analyst Notes
          </TabsTrigger>
          <TabsTrigger value="timeline" className="text-xs gap-1.5">
            <History className="w-3.5 h-3.5" />
            Timeline & Audit
          </TabsTrigger>
        </TabsList>

        {/* Tab 1: Overview */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="bg-card/50 border-border/60">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                  <User className="w-5 h-5" />
                </div>
                <div>
                  <p className="text-[11px] text-muted-foreground uppercase font-bold tracking-wider">Assignee</p>
                  <p className="text-sm font-semibold text-foreground">{caseItem.assigned_to || 'Lead Analyst'}</p>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-border/60">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-sky-500/10 flex items-center justify-center text-sky-400">
                  <Mail className="w-5 h-5" />
                </div>
                <div>
                  <p className="text-[11px] text-muted-foreground uppercase font-bold tracking-wider">Linked Emails</p>
                  <p className="text-sm font-semibold text-foreground">{linkedEmails?.length || 0} Records</p>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-border/60">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400">
                  <Calendar className="w-5 h-5" />
                </div>
                <div>
                  <p className="text-[11px] text-muted-foreground uppercase font-bold tracking-wider">Created</p>
                  <p className="text-sm font-semibold text-foreground">
                    {caseItem.created_at
                      ? formatDistanceToNow(new Date(caseItem.created_at), { addSuffix: true })
                      : 'recently'}
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-border/60">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center text-purple-400">
                  <Clock className="w-5 h-5" />
                </div>
                <div>
                  <p className="text-[11px] text-muted-foreground uppercase font-bold tracking-wider">Last Modified</p>
                  <p className="text-sm font-semibold text-foreground">
                    {caseItem.updated_at
                      ? formatDistanceToNow(new Date(caseItem.updated_at), { addSuffix: true })
                      : 'recently'}
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card className="bg-card/60 border-border/60">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <FileText className="w-4 h-4 text-primary" />
                Case Description & Hypothesis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-foreground/90 leading-relaxed whitespace-pre-wrap font-sans">
                {caseItem.description || 'No description provided for this investigation case.'}
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tab 2: Linked Evidence */}
        <TabsContent value="evidence" className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Mail className="w-4 h-4 text-primary" />
              Associated Email Evidence ({linkedEmails?.length || 0})
            </h3>
            <Button
              size="sm"
              onClick={() => setIsLinkModalOpen(true)}
              className="h-8 text-xs gap-1.5 font-medium"
            >
              <Plus className="w-3.5 h-3.5" />
              Link Evidence
            </Button>
          </div>

          {isEmailsLoading && (
            <div className="flex flex-col items-center justify-center p-8 text-muted-foreground gap-2">
              <Loader2 className="w-6 h-6 animate-spin text-primary" />
              <span className="text-xs">Loading linked evidence...</span>
            </div>
          )}

          {!isEmailsLoading && (!linkedEmails || linkedEmails.length === 0) && (
            <Card className="p-8 text-center text-muted-foreground border-dashed bg-card/30">
              <Mail className="w-8 h-8 opacity-40 mx-auto mb-2 text-muted-foreground" />
              <p className="text-xs font-medium text-foreground">No email evidence attached to this case</p>
              <p className="text-[11px] text-muted-foreground mt-0.5 mb-3">
                Link analyzed phishing lures or BEC emails to correlate IOCs and campaign signals.
              </p>
              <Button size="sm" variant="outline" onClick={() => setIsLinkModalOpen(true)} className="text-xs">
                Link Email Evidence
              </Button>
            </Card>
          )}

          {!isEmailsLoading && linkedEmails && linkedEmails.length > 0 && (
            <div className="space-y-2.5">
              {linkedEmails.map((email: any) => (
                <Card key={email.id} className="bg-card/50 border-border/60 hover:border-border/80 transition-colors">
                  <CardContent className="p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <h4 className="text-xs font-semibold text-foreground truncate max-w-[320px]">
                          {email.subject || 'No Subject'}
                        </h4>
                        <Badge variant="outline" className="text-[10px] uppercase font-mono">
                          {email.status || 'analyzed'}
                        </Badge>
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
                        className="h-7 text-xs px-2 gap-1"
                        title="View detailed threat analysis"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                        Analysis
                      </Button>

                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => navigate(`/reports?emailId=${email.id}`)}
                        className="h-7 text-xs px-2 gap-1"
                        title="View forensic report"
                      >
                        <FileCheck2 className="w-3.5 h-3.5 text-primary" />
                        Report
                      </Button>

                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleUnlinkEmail(email.id)}
                        disabled={unlinkEmailMutation.isPending}
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                        title="Unlink from case"
                      >
                        <Unlink className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
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
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-sm">
              <Link2 className="w-4 h-4 text-primary" />
              Link Email Evidence
            </DialogTitle>
            <DialogDescription className="text-xs">
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
                    className={`p-2.5 rounded-lg border text-xs cursor-pointer transition-all ${
                      selectedEmailToLink === email.id
                        ? 'border-primary bg-primary/10 ring-1 ring-primary'
                        : 'border-border/50 bg-background/50 hover:bg-muted/40'
                    }`}
                  >
                    <p className="font-semibold text-foreground truncate">{email.subject || 'No Subject'}</p>
                    <div className="flex items-center justify-between text-[10px] text-muted-foreground mt-1">
                      <span className="truncate max-w-[180px]">{email.sender}</span>
                      <span className="uppercase font-mono">{email.status}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <DialogFooter className="gap-2">
            <Button variant="outline" size="sm" onClick={() => setIsLinkModalOpen(false)} className="text-xs">
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleLinkEmail}
              disabled={!selectedEmailToLink || linkEmailMutation.isPending}
              className="text-xs gap-1.5"
            >
              {linkEmailMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Link2 className="w-3.5 h-3.5" />}
              <span>Link Selected Email</span>
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Modal */}
      <Dialog open={isDeleteConfirmOpen} onOpenChange={setIsDeleteConfirmOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive text-sm">
              <ShieldAlert className="w-4 h-4" />
              Delete Investigation Case
            </DialogTitle>
            <DialogDescription className="text-xs">
              Are you sure you want to delete <strong className="text-foreground">{caseItem.title}</strong>? This action will cascade delete attached notes and log a permanent audit record.
            </DialogDescription>
          </DialogHeader>

          <DialogFooter className="gap-2">
            <Button variant="outline" size="sm" onClick={() => setIsDeleteConfirmOpen(false)} className="text-xs">
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleDeleteCase}
              disabled={deleteCaseMutation.isPending}
              className="text-xs gap-1.5"
            >
              {deleteCaseMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
              <span>Confirm Delete</span>
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
