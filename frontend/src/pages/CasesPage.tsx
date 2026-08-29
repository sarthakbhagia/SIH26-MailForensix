import { useState, useEffect } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import {
  FolderPlus,
  Loader2,
  Plus,
  User,
  Briefcase,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useCases, useCreateCase, useLinkCaseEmail } from '@/hooks/useCases';
import { CaseSeverity } from '@/types/case';
import CaseList from '@/components/cases/CaseList';
import CaseDetail from '@/components/cases/CaseDetail';
import { cn } from '@/lib/utils';

export default function CasesPage() {
  const { caseId } = useParams<{ caseId?: string }>();
  const [searchParams, setSearchParams] = useSearchParams();

  const urlCaseId = caseId || searchParams.get('caseId');
  const urlNew = searchParams.get('new') === 'true';
  const urlPreTitle = searchParams.get('title') || '';
  const urlPreEmailId = searchParams.get('emailId') || '';

  const { data: cases, isLoading: isCasesLoading, isError: isCasesError, refetch: refetchCases } = useCases();
  const createCaseMutation = useCreateCase();
  const linkEmailMutation = useLinkCaseEmail();

  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(urlCaseId || null);
  const [isNewCaseModalOpen, setIsNewCaseModalOpen] = useState(urlNew);

  // New Case form state
  const [title, setTitle] = useState(urlPreTitle);
  const [description, setDescription] = useState(
    urlPreEmailId ? `Investigation initiated from email envelope ID: ${urlPreEmailId}` : ''
  );
  const [severity, setSeverity] = useState<CaseSeverity>('medium');
  const [assignedTo, setAssignedTo] = useState('Lead Analyst');
  const [formError, setFormError] = useState<string | null>(null);

  // Auto-select first case if none selected
  useEffect(() => {
    if (cases && cases.length > 0 && !selectedCaseId) {
      setSelectedCaseId(cases[0].id);
    }
  }, [cases, selectedCaseId]);

  useEffect(() => {
    if (caseId) {
      setSelectedCaseId(caseId);
    }
  }, [caseId]);

  const handleSelectCase = (id: string) => {
    setSelectedCaseId(id);
    setSearchParams({ caseId: id }, { replace: true });
  };

  const handleCreateCaseSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) {
      setFormError('Case title is required.');
      return;
    }

    try {
      setFormError(null);
      const newCase = await createCaseMutation.mutateAsync({
        title: title.trim(),
        description: description.trim(),
        severity,
        assigned_to: assignedTo.trim() || 'Lead Analyst',
      });

      // If created with pre-linked email, automatically associate it
      if (urlPreEmailId) {
        try {
          await linkEmailMutation.mutateAsync({
            caseId: newCase.id,
            emailId: urlPreEmailId,
          });
        } catch (linkErr) {
          console.error('Auto link email failed:', linkErr);
        }
      }

      // Reset form and close modal
      setTitle('');
      setDescription('');
      setSeverity('medium');
      setAssignedTo('Lead Analyst');
      setIsNewCaseModalOpen(false);

      // Select newly created case
      handleSelectCase(newCase.id);
    } catch (err: any) {
      console.error('Failed to create case:', err);
      setFormError('Failed to create investigation case. Please check inputs.');
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-4.5rem)] space-y-3 max-w-full pb-4">
      {/* Top Header */}
      <div className="panel p-4 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div>
          <h1 className="text-lg sm:text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <Briefcase className="size-4 text-primary" />
            Case Investigation Center
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Master-detail threat investigation ledger correlating suspicious email artifacts, IOCs, and analyst audits.
          </p>
        </div>

        <Button
          size="sm"
          onClick={() => setIsNewCaseModalOpen(true)}
          className="h-8 px-3 text-xs font-mono gap-1.5 font-bold bg-primary text-primary-foreground"
        >
          <Plus className="size-3.5" />
          <span>INITIALIZE NEW CASE</span>
        </Button>
      </div>

      {/* Main 2-Column Master-Detail Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 flex-1 min-h-0">
        {/* Left Column: Master Case Queue (4 cols on large, 3 cols on xl) */}
        <div className="panel lg:col-span-4 xl:col-span-3 p-3.5 flex flex-col h-full min-h-0">
          <CaseList
            cases={cases || []}
            selectedCaseId={selectedCaseId}
            onSelectCase={handleSelectCase}
            onNewCase={() => setIsNewCaseModalOpen(true)}
            isLoading={isCasesLoading}
            isError={isCasesError}
            onRefresh={() => refetchCases()}
          />
        </div>

        {/* Right Column: Case Detail Workspace (8 cols on large, 9 cols on xl) */}
        <div className="panel lg:col-span-8 xl:col-span-9 p-3.5 flex flex-col h-full min-h-0 overflow-hidden">
          {selectedCaseId ? (
            <CaseDetail
              caseId={selectedCaseId}
              onBack={() => setSelectedCaseId(null)}
            />
          ) : (
            <div className="flex flex-col items-center justify-center h-full p-12 text-center text-muted-foreground">
              <Briefcase className="size-10 opacity-30 mb-2 text-primary" />
              <h3 className="text-sm font-semibold text-foreground">No Case Selected</h3>
              <p className="text-xs text-muted-foreground mt-0.5 max-w-sm">
                Select an investigation case from the queue on the left or create a new case to review forensic evidence.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* New Case Creation Modal */}
      <Dialog open={isNewCaseModalOpen} onOpenChange={setIsNewCaseModalOpen}>
        <DialogContent className="max-w-lg panel p-6">
          <form onSubmit={handleCreateCaseSubmit} className="space-y-4">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2 text-base font-bold text-foreground">
                <FolderPlus className="size-4 text-primary" />
                Initialize Investigation Case
              </DialogTitle>
              <DialogDescription className="text-xs text-muted-foreground">
                Create a new cybersecurity threat investigation ledger to correlate emails, IOCs, and analyst remarks.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3 py-2 text-xs font-mono">
              <div className="space-y-1.5">
                <label className="label-mono text-[9px] block">
                  CASE TITLE <span className="text-critical">*</span>
                </label>
                <Input
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. SpearPhish Campaign: Executive Credential Harvesting"
                  className="text-xs h-8 font-mono bg-background border-border"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="label-mono text-[9px] block">
                  THREAT CONTEXT & SUMMARY
                </label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Summarize initial trigger, affected targets, observed tactics, or suspect infrastructure..."
                  rows={3}
                  className="w-full text-xs rounded bg-background border border-border p-2.5 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary resize-y font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="label-mono text-[9px] block">
                    SEVERITY TIER
                  </label>
                  <div className="flex items-center bg-surface-2 border border-border rounded p-0.5">
                    {(['low', 'medium', 'high', 'critical'] as const).map((sev) => (
                      <button
                        type="button"
                        key={sev}
                        onClick={() => setSeverity(sev)}
                        className={cn(
                          'flex-1 font-mono text-[9px] font-bold py-1 rounded uppercase transition-colors',
                          severity === sev
                            ? sev === 'critical'
                              ? 'bg-critical text-critical-foreground font-bold shadow-sm'
                              : sev === 'high'
                              ? 'bg-high text-high-foreground font-bold shadow-sm'
                              : sev === 'medium'
                              ? 'bg-medium text-medium-foreground font-bold shadow-sm'
                              : 'bg-clean text-clean-foreground font-bold shadow-sm'
                            : 'text-muted-foreground hover:text-foreground'
                        )}
                      >
                        {sev}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="label-mono text-[9px] block">
                    ASSIGNED INVESTIGATOR
                  </label>
                  <div className="relative">
                    <User className="absolute left-2.5 top-2 size-3.5 text-muted-foreground" />
                    <Input
                      value={assignedTo}
                      onChange={(e) => setAssignedTo(e.target.value)}
                      placeholder="Lead Analyst"
                      className="text-xs h-8 pl-8 font-mono bg-background border-border"
                    />
                  </div>
                </div>
              </div>

              {formError && (
                <div className="text-xs font-mono text-critical bg-critical/10 border border-critical/20 rounded p-2">
                  {formError}
                </div>
              )}
            </div>

            <DialogFooter className="gap-2 pt-2 border-t border-border/50">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setIsNewCaseModalOpen(false)}
                className="text-xs font-mono border-border"
              >
                CANCEL
              </Button>
              <Button
                type="submit"
                size="sm"
                disabled={!title.trim() || createCaseMutation.isPending}
                className="text-xs font-mono font-bold gap-1.5 bg-primary text-primary-foreground"
              >
                {createCaseMutation.isPending ? (
                  <Loader2 className="size-3.5 animate-spin" />
                ) : (
                  <Plus className="size-3.5" />
                )}
                <span>INITIALIZE CASE</span>
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
