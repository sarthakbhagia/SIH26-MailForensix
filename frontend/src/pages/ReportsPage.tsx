import { useState, useMemo, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  FileCheck2,
  FileSearch,
  Loader2,
  Mail,
  RefreshCw,
  Search,
  ArrowLeft,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from '@/lib/api';
import { EmailSummary } from '@/types/email';
import ReportPreview from '@/components/reports/ReportPreview';
import ReportDownload from '@/components/reports/ReportDownload';
import { cn, safeFormatDistanceToNow } from '@/lib/utils';
import { getSeverityTokens } from '@/lib/severity';

export default function ReportsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const initialEmailId = searchParams.get('emailId');

  const [selectedEmailId, setSelectedEmailId] = useState<string | null>(initialEmailId);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'critical' | 'high' | 'analyzed'>('all');

  // Query emails list
  const {
    data: emailsData,
    isLoading: isEmailsLoading,
    isError: isEmailsError,
    refetch: refetchEmails,
  } = useQuery({
    queryKey: ['emails', { page: 1, pageSize: 50 }],
    queryFn: () => api.getEmails(1, 50),
    staleTime: 30000,
  });

  const emails: EmailSummary[] = emailsData?.data?.items || [];

  // Filter emails based on search query and risk status
  const filteredEmails = useMemo(() => {
    return emails.filter((email) => {
      const matchesSearch =
        searchQuery === '' ||
        (email.subject || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        (email.sender || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        email.id.toLowerCase().includes(searchQuery.toLowerCase());

      if (!matchesSearch) return false;

      if (statusFilter === 'critical') return (email.risk_score || 0) >= 75;
      if (statusFilter === 'high') return (email.risk_score || 0) >= 50 && (email.risk_score || 0) < 75;
      if (statusFilter === 'analyzed') return email.status === 'analyzed';
      return true;
    });
  }, [emails, searchQuery, statusFilter]);

  // Auto-select first analyzed email if none selected
  useEffect(() => {
    if (!selectedEmailId && filteredEmails.length > 0) {
      const firstAnalyzed = filteredEmails.find((e) => e.status === 'analyzed') || filteredEmails[0];
      setSelectedEmailId(firstAnalyzed.id);
      setSearchParams({ emailId: firstAnalyzed.id }, { replace: true });
    }
  }, [filteredEmails, selectedEmailId, setSearchParams]);

  const selectedEmail = emails.find((e) => e.id === selectedEmailId);

  const handleSelectEmail = (id: string) => {
    setSelectedEmailId(id);
    setSearchParams({ emailId: id });
  };

  const renderRiskBadge = (score?: number) => {
    if (score === undefined || score === null) {
      return (
        <span className="font-mono text-[9px] px-1.5 py-0.2 rounded bg-surface border border-border text-muted-foreground">
          Pending
        </span>
      );
    }
    const tokens = getSeverityTokens(score);
    return (
      <span className={cn('font-mono text-[9px] font-bold px-1.5 py-0.2 rounded border tabular-nums', tokens.badgeClass)}>
        Risk {score.toFixed(0)}
      </span>
    );
  };

  return (
    <div className="flex flex-col h-[calc(100vh-4.5rem)] space-y-3 max-w-full pb-4">
      {/* 1. Header Toolbar */}
      <div className="panel p-4 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div>
          <h1 className="text-lg sm:text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <FileCheck2 className="size-4 text-primary" />
            Digital Forensics Dossier Generator
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Compile, inspect, and export court-ready cryptographic email evidence dossiers in PDF and JSON formats.
          </p>
        </div>

        {selectedEmailId && (
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate(`/emails/${selectedEmailId}`)}
              className="h-8 text-xs font-mono gap-1.5 border-border bg-surface hover:bg-surface-2 text-foreground"
              title="Return to Email Analysis Workstation"
            >
              <ArrowLeft className="size-3.5" />
              <span>Back to Analysis</span>
            </Button>

            <ReportDownload
              emailId={selectedEmailId}
              emailSubject={selectedEmail?.subject}
            />
          </div>
        )}
      </div>

      {/* 2. Main 2-Column Split: Evidence Selector (Left) | Document Preview (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 flex-1 min-h-0">
        {/* Left Column: Email Evidence Selector (4 cols on lg, 3.5 cols on xl) */}
        <div className="panel lg:col-span-4 xl:col-span-3 p-3.5 flex flex-col h-full min-h-0 space-y-2.5 select-none">
          <div className="flex items-center justify-between border-b border-border/50 pb-2 shrink-0">
            <div className="flex items-center gap-2">
              <Mail className="size-4 text-primary" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                Select Evidence ({filteredEmails.length})
              </h3>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => refetchEmails()}
              className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
              title="Refresh ledger"
            >
              <RefreshCw className={`size-3 ${isEmailsLoading ? 'animate-spin' : ''}`} />
            </Button>
          </div>

          {/* Search Input */}
          <div className="relative shrink-0">
            <Search className="absolute left-2.5 top-2 size-3.5 text-muted-foreground" />
            <Input
              placeholder="Search sender, subject, ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 h-7 text-xs font-mono bg-background border-border"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1 shrink-0 font-mono text-[10px]">
            {(['all', 'critical', 'high', 'analyzed'] as const).map((filter) => (
              <button
                key={filter}
                onClick={() => setStatusFilter(filter)}
                className={cn(
                  'px-2 py-0.5 rounded uppercase transition-colors border',
                  statusFilter === filter
                    ? 'bg-primary/20 text-primary border-primary/40 font-bold'
                    : 'bg-surface text-muted-foreground border-border/50 hover:bg-surface-2 hover:text-foreground'
                )}
              >
                {filter}
              </button>
            ))}
          </div>

          {/* Evidence List */}
          <div className="flex-1 overflow-y-auto space-y-2 pr-1 min-h-0">
            {isEmailsLoading ? (
              <div className="py-12 flex flex-col items-center justify-center gap-2 text-muted-foreground">
                <Loader2 className="size-6 animate-spin text-primary" />
                <span className="label-mono text-[10px]">LOADING EVIDENCE LEDGER...</span>
              </div>
            ) : isEmailsError ? (
              <div className="py-8 text-center text-xs text-critical bg-critical/10 border border-critical/30 rounded font-mono">
                Failed to load evidence records.
              </div>
            ) : filteredEmails.length === 0 ? (
              <div className="py-12 text-center text-muted-foreground flex flex-col items-center justify-center rounded border border-border bg-surface-2/30">
                <FileSearch className="size-8 opacity-30 mb-1 text-primary" />
                <p className="text-xs font-semibold text-foreground">No matching evidence</p>
                <p className="text-[11px] text-muted-foreground mt-0.5 font-mono">Adjust search query or filters.</p>
              </div>
            ) : (
              filteredEmails.map((email) => {
                const isSelected = email.id === selectedEmailId;
                return (
                  <div
                    key={email.id}
                    onClick={() => handleSelectEmail(email.id)}
                    className={cn(
                      'p-2.5 rounded border transition-all duration-150 cursor-pointer space-y-1',
                      isSelected
                        ? 'border-primary ring-1 ring-primary bg-primary/10 shadow-sm'
                        : 'border-border/60 bg-surface hover:bg-surface-2 hover:border-border'
                    )}
                  >
                    <div className="flex items-center justify-between gap-1.5">
                      {renderRiskBadge(email.risk_score)}
                      <span className="label-mono text-[9px]">
                        {safeFormatDistanceToNow(email.ingested_at, { addSuffix: true })}
                      </span>
                    </div>

                    <p className="text-xs font-bold text-foreground truncate" title={email.subject}>
                      {email.subject || '(No Subject)'}
                    </p>

                    <p className="text-[10px] font-mono text-muted-foreground truncate">
                      {email.sender || 'Unknown Sender'}
                    </p>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: PDF / Dossier Preview Canvas (8 cols on lg, 8.5 cols on xl) */}
        <div className="lg:col-span-8 xl:col-span-9 flex flex-col h-full min-h-0 overflow-hidden">
          {selectedEmailId ? (
            <ReportPreview
              emailId={selectedEmailId}
              emailSubject={selectedEmail?.subject}
            />
          ) : (
            <div className="panel h-full flex flex-col items-center justify-center p-12 text-center text-muted-foreground">
              <FileCheck2 className="size-12 opacity-20 mb-3 text-primary" />
              <h3 className="text-sm font-semibold text-foreground">No Evidence Envelope Selected</h3>
              <p className="text-xs text-muted-foreground mt-1 max-w-sm">
                Choose an email from the left ledger to inspect, render, and download its cryptographic forensic dossier.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
