import { useState, useMemo, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { formatDistanceToNow } from 'date-fns';
import {
  FileCheck2,
  FileSearch,
  Loader2,
  Mail,
  RefreshCw,
  Search,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from '@/lib/api';
import { EmailSummary } from '@/types/email';
import ReportPreview from '@/components/reports/ReportPreview';
import ReportDownload from '@/components/reports/ReportDownload';
import { cn } from '@/lib/utils';

export default function ReportsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
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

      if (statusFilter === 'critical') return (email.risk_score || 0) >= 90;
      if (statusFilter === 'high') return (email.risk_score || 0) >= 75 && (email.risk_score || 0) < 90;
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

  const selectedEmail = useMemo(() => {
    return emails.find((e) => e.id === selectedEmailId);
  }, [emails, selectedEmailId]);

  const handleSelectEmail = (id: string) => {
    setSelectedEmailId(id);
    setSearchParams({ emailId: id });
  };

  const renderRiskBadge = (score?: number) => {
    if (score === undefined || score === null) {
      return (
        <span className="font-mono text-[9px] px-1.5 py-0.5 rounded bg-surface border border-border text-muted-foreground">
          Pending
        </span>
      );
    }
    if (score >= 75) {
      return (
        <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-critical/15 text-critical border border-critical/30 uppercase">
          Risk {score.toFixed(0)}
        </span>
      );
    }
    if (score >= 50) {
      return (
        <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-high/15 text-high border border-high/30 uppercase">
          Risk {score.toFixed(0)}
        </span>
      );
    }
    return (
      <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-clean/15 text-clean border border-clean/30 uppercase">
        Risk {score.toFixed(0)}
      </span>
    );
  };

  return (
    <div className="space-y-5 max-w-7xl mx-auto pb-10">
      {/* Page Header */}
      <div className="panel p-5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
              <FileCheck2 className="size-5 text-primary" />
              Forensic Reports & Dossier Export
            </h1>
            <p className="text-xs text-muted-foreground mt-0.5">
              Generate, preview, and download cryptographically-sealed forensic investigation reports.
            </p>
          </div>

          {selectedEmail && (
            <div className="shrink-0">
              <ReportDownload
                emailId={selectedEmail.id}
                emailSubject={selectedEmail.subject}
              />
            </div>
          )}
        </div>
      </div>

      {/* Main 2-Column Content */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left Sidebar: Email Evidence Selector */}
        <div className="panel lg:col-span-4 flex flex-col h-[calc(100vh-210px)] min-h-[580px] p-3 space-y-2.5">
          <div className="flex items-center justify-between border-b border-border/50 pb-2">
            <span className="label-mono font-semibold flex items-center gap-1.5">
              <Mail className="size-3.5 text-primary" />
              Evidence Ledger ({filteredEmails.length})
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => refetchEmails()}
              className="size-6 p-0 text-muted-foreground hover:text-foreground"
              title="Refresh email list"
            >
              <RefreshCw className={`size-3 ${isEmailsLoading ? 'animate-spin' : ''}`} />
            </Button>
          </div>

          {/* Search Bar */}
          <div className="relative">
            <Search className="absolute left-2.5 top-2 size-3 text-muted-foreground" />
            <Input
              placeholder="Search sender, subject..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-7 pl-7 text-xs font-mono bg-background/50 border-border/60"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1 overflow-x-auto pb-0.5 scrollbar-none">
            {(['all', 'critical', 'high', 'analyzed'] as const).map((filter) => (
              <button
                key={filter}
                onClick={() => setStatusFilter(filter)}
                className={cn(
                  'text-[10px] font-mono font-semibold px-2 py-0.5 rounded capitalize transition-colors whitespace-nowrap border',
                  statusFilter === filter
                    ? 'bg-primary text-primary-foreground border-primary'
                    : 'bg-surface text-muted-foreground border-border/50 hover:bg-muted'
                )}
              >
                {filter}
              </button>
            ))}
          </div>

          {/* Email List */}
          <div className="flex-1 overflow-y-auto space-y-1.5 pr-1">
            {isEmailsLoading && (
              <div className="flex flex-col items-center justify-center p-8 text-center text-muted-foreground">
                <Loader2 className="size-5 animate-spin text-primary mb-2" />
                <span className="label-mono text-[10px]">LOADING EVIDENCE ARTIFACTS...</span>
              </div>
            )}

            {!isEmailsLoading && isEmailsError && (
              <div className="p-4 text-center text-xs text-medium">
                Failed to load email records.
              </div>
            )}

            {!isEmailsLoading && !isEmailsError && filteredEmails.length === 0 && (
              <div className="flex flex-col items-center justify-center p-8 text-center text-muted-foreground">
                <FileSearch className="size-8 opacity-40 mb-2" />
                <p className="text-xs font-medium text-foreground">No matching emails found</p>
                <p className="text-[11px] text-muted-foreground mt-1">
                  Try adjusting your search query or filter.
                </p>
              </div>
            )}

            {!isEmailsLoading &&
              !isEmailsError &&
              filteredEmails.map((email) => {
                const isSelected = email.id === selectedEmailId;
                return (
                  <div
                    key={email.id}
                    onClick={() => handleSelectEmail(email.id)}
                    className={cn(
                      'p-2.5 rounded border transition-all cursor-pointer text-xs space-y-1',
                      isSelected
                        ? 'border-primary/80 bg-primary/10 shadow-glow'
                        : 'border-border/50 bg-surface/40 hover:bg-surface hover:border-border'
                    )}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <p className="font-semibold text-foreground truncate max-w-[200px]">
                        {email.subject || 'No Subject'}
                      </p>
                      {renderRiskBadge(email.risk_score)}
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-muted-foreground font-mono mt-1">
                      <span className="truncate max-w-[140px]">{email.sender}</span>
                      <span className="shrink-0">
                        {email.ingested_at
                          ? formatDistanceToNow(new Date(email.ingested_at), { addSuffix: true })
                          : 'recent'}
                      </span>
                    </div>
                  </div>
                );
              })}
          </div>
        </div>

        {/* Right Area: Interactive Report Preview */}
        <div className="lg:col-span-8 h-[calc(100vh-210px)] min-h-[580px]">
          <ReportPreview
            emailId={selectedEmailId}
            emailSubject={selectedEmail?.subject}
          />
        </div>
      </div>
    </div>
  );
}


