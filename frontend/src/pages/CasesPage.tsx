import { useState, useEffect } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { FolderPlus, Loader2, Plus, User } from 'lucide-react';

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
import { useCreateCase } from '@/hooks/useCases';
import { CaseSeverity } from '@/types/case';
import CaseList from '@/components/cases/CaseList';
import CaseDetail from '@/components/cases/CaseDetail';

export default function CasesPage() {
  const { caseId } = useParams<{ caseId?: string }>();
  const [searchParams] = useSearchParams();
  const initialSearch = searchParams.get('search') || '';
  const navigate = useNavigate();

  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(caseId || null);
  const [isNewCaseModalOpen, setIsNewCaseModalOpen] = useState(false);

  // New Case form state
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<CaseSeverity>('medium');
  const [assignedTo, setAssignedTo] = useState('Lead Analyst');
  const [formError, setFormError] = useState<string | null>(null);

  const createCaseMutation = useCreateCase();

  useEffect(() => {
    if (caseId) {
      setSelectedCaseId(caseId);
    }
  }, [caseId]);

  const handleSelectCase = (id: string) => {
    setSelectedCaseId(id);
    navigate(`/cases/${id}`);
  };

  const handleBackToList = () => {
    setSelectedCaseId(null);
    navigate('/cases');
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
      setFormError('Failed to create investigation case. Please check your inputs.');
    }
  };

  return (
    <div className="space-y-6">
      {/* If a case is selected, render CaseDetail; otherwise render CaseList */}
      {selectedCaseId ? (
        <CaseDetail caseId={selectedCaseId} onBack={handleBackToList} />
      ) : (
        <CaseList
          onSelectCase={handleSelectCase}
          onNewCase={() => setIsNewCaseModalOpen(true)}
          initialSearch={initialSearch}
        />
      )}

      {/* New Case Creation Modal */}
      <Dialog open={isNewCaseModalOpen} onOpenChange={setIsNewCaseModalOpen}>
        <DialogContent className="max-w-lg">
          <form onSubmit={handleCreateCaseSubmit} className="space-y-4">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2 text-base">
                <FolderPlus className="w-5 h-5 text-primary" />
                Create Investigation Case
              </DialogTitle>
              <DialogDescription className="text-xs">
                Initialize a new cybersecurity threat investigation ledger to correlate emails, IOCs, and analyst notes.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3 py-2">
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-foreground">
                  Case Title <span className="text-destructive">*</span>
                </label>
                <Input
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. Operation SpearPhish: CFO Credential Harvesting Campaign"
                  className="text-xs h-9 bg-background/60"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-foreground">
                  Case Description & Threat Context
                </label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Summarize initial trigger, affected targets, observed tactics, or suspect infrastructure..."
                  rows={3}
                  className="w-full text-xs rounded-md bg-background/60 border border-border/60 p-2.5 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary transition-all resize-y"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-foreground">
                    Initial Severity
                  </label>
                  <div className="flex items-center bg-background/60 border border-border/60 rounded-md p-0.5">
                    {(['low', 'medium', 'high', 'critical'] as const).map((sev) => (
                      <button
                        type="button"
                        key={sev}
                        onClick={() => setSeverity(sev)}
                        className={`flex-1 text-[11px] font-medium py-1 rounded uppercase text-[10px] transition-colors ${
                          severity === sev
                            ? 'bg-primary text-primary-foreground font-bold shadow-sm'
                            : 'text-muted-foreground hover:text-foreground'
                        }`}
                      >
                        {sev}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-foreground">
                    Assigned Analyst
                  </label>
                  <div className="relative">
                    <User className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                    <Input
                      value={assignedTo}
                      onChange={(e) => setAssignedTo(e.target.value)}
                      placeholder="Lead Analyst"
                      className="text-xs h-9 pl-8 bg-background/60"
                    />
                  </div>
                </div>
              </div>

              {formError && (
                <div className="text-xs text-destructive bg-destructive/10 border border-destructive/20 rounded-md p-2">
                  {formError}
                </div>
              )}
            </div>

            <DialogFooter className="gap-2 pt-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setIsNewCaseModalOpen(false)}
                className="text-xs"
              >
                Cancel
              </Button>
              <Button
                type="submit"
                size="sm"
                disabled={!title.trim() || createCaseMutation.isPending}
                className="text-xs gap-1.5"
              >
                {createCaseMutation.isPending ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Plus className="w-3.5 h-3.5" />
                )}
                <span>Initialize Case</span>
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}

