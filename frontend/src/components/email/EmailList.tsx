import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Inbox,
  Search,
  RefreshCw,
  ExternalLink,
  MapPin,
  Share2,
  FolderPlus,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { EmailSummary } from '@/types/email';
import { useEmails } from '@/hooks/useEmails';
import { cn, safeFormatDistanceToNow } from '@/lib/utils';
import { getSeverityTokens } from '@/lib/severity';

export interface EmailListProps {
  className?: string;
}

export function EmailList({ className }: EmailListProps) {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const pageSize = 15;
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const { data: emailResponse, isLoading, isError, refetch } = useEmails(page);

  const rawItems: EmailSummary[] = emailResponse?.items ?? (emailResponse as any)?.data ?? [];
  const totalCount = emailResponse?.total ?? rawItems.length;

  // Filter items based on local search and filter criteria
  const filteredEmails = useMemo(() => {
    return rawItems.filter((email: EmailSummary) => {
      // Substring search
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchSubj = (email.subject || '').toLowerCase().includes(q);
        const matchSender = (email.sender || '').toLowerCase().includes(q);
        const matchId = email.id.toLowerCase().includes(q);
        if (!matchSubj && !matchSender && !matchId) return false;
      }

      // Status filter
      if (statusFilter !== 'all') {
        if (email.status !== statusFilter) return false;
      }

      // Severity filter
      if (severityFilter !== 'all') {
        const score = email.risk_score || 0;
        const tokens = getSeverityTokens(score);
        if (tokens.level.toLowerCase() !== severityFilter.toLowerCase()) {
          return false;
        }
      }

      return true;
    });
  }, [rawItems, searchQuery, statusFilter, severityFilter]);

  const handleResetFilters = () => {
    setSearchQuery('');
    setStatusFilter('all');
    setSeverityFilter('all');
  };

  return (
    <div className={cn('panel p-4 sm:p-5 flex flex-col h-full space-y-3.5 min-w-0', className)}>
      {/* 1. Forensic Ledger Header & Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 border-b border-border/50 pb-3 shrink-0">
        <div className="flex items-center gap-2">
          <Inbox className="size-4 text-primary" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
            Ingested Evidence Ledger
          </h3>
          <span className="label-mono text-[9px] bg-surface-2 px-2 py-0.5 rounded border border-border">
            {filteredEmails.length} OF {totalCount} ARTIFACTS
          </span>
        </div>

        <Button
          variant="ghost"
          size="sm"
          onClick={() => refetch()}
          className="h-7 px-2 text-xs font-mono gap-1 text-muted-foreground hover:text-foreground self-end sm:self-auto"
          title="Refresh Evidence Ledger"
        >
          <RefreshCw className={`size-3 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </Button>
      </div>

      {/* 2. Filter Controls Strip */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 shrink-0 text-xs font-mono">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-2.5 top-2 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search by subject, sender, artifact ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-7 text-xs font-mono bg-background border-border"
          />
        </div>

        <div className="flex items-center gap-2">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="h-7 rounded border border-border bg-surface px-2 text-[10px] font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="all">Status: All</option>
            <option value="analyzed">Analyzed</option>
            <option value="processing">Processing</option>
            <option value="pending">Pending</option>
            <option value="error">Error</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="h-7 rounded border border-border bg-surface px-2 text-[10px] font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="all">Severity: All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* 3. Evidence Ledger Records List / Table */}
      <div className="flex-1 overflow-y-auto space-y-2 min-h-0 pr-1">
        {isLoading ? (
          <div className="py-16 flex flex-col items-center justify-center gap-2 text-muted-foreground">
            <div className="size-7 rounded-full border-2 border-muted border-t-primary animate-spin" />
            <span className="label-mono text-[10px] mt-1">QUERYING EVIDENCE LEDGER...</span>
          </div>
        ) : isError ? (
          <div className="p-8 text-center text-xs text-critical bg-critical/10 border border-critical/30 rounded font-mono">
            <p className="font-bold">Failed to load evidence ledger records.</p>
            <Button size="sm" onClick={() => refetch()} className="mt-3 text-xs font-mono">
              Retry Connection
            </Button>
          </div>
        ) : filteredEmails.length === 0 ? (
          <div className="py-16 flex flex-col items-center justify-center gap-2 text-muted-foreground text-center rounded border border-border bg-surface-2/30">
            <Inbox className="size-9 opacity-30 mb-1" />
            <p className="text-xs font-semibold text-foreground">
              {searchQuery || statusFilter !== 'all' || severityFilter !== 'all'
                ? 'No evidence records match active filters'
                : 'No evidence artifacts ingested'}
            </p>
            <p className="text-[11px] text-muted-foreground max-w-xs font-mono">
              {searchQuery || statusFilter !== 'all' || severityFilter !== 'all' ? (
                <button onClick={handleResetFilters} className="text-primary hover:underline mt-1 block">
                  Reset filters & search
                </button>
              ) : (
                'Ingest raw .eml or .msg artifacts using the ingestion dock to begin forensic triage.'
              )}
            </p>
          </div>
        ) : (
          <div className="space-y-2 font-mono">
            {filteredEmails.map((email: EmailSummary) => {
              const score = email.risk_score ?? 0;
              const tokens = getSeverityTokens(score);
              const isAnalyzing = email.status === 'processing' || email.status === 'pending';

              return (
                <div
                  key={email.id}
                  className="p-3 rounded border border-border bg-surface hover:bg-surface-2 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 group"
                >
                  <div className="min-w-0 flex-1 space-y-1">
                    {/* Header Row: ID + Ingested Timestamp + Status + Risk Badge */}
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="label-mono text-[9px] font-bold text-foreground">
                        ID: {email.id.substring(0, 8)}
                      </span>

                      <span
                        className={cn(
                          'inline-flex items-center gap-1 font-mono text-[9px] font-bold uppercase px-1.5 py-0.2 rounded border',
                          isAnalyzing
                            ? 'bg-primary/10 text-primary border-primary/30'
                            : email.status === 'error'
                            ? 'bg-critical/10 text-critical border-critical/30'
                            : 'bg-surface-2 text-muted-foreground border-border'
                        )}
                      >
                        {isAnalyzing && <span className="size-1 rounded-full bg-primary animate-pulse" />}
                        {email.status || 'analyzed'}
                      </span>

                      <span
                        className={cn(
                          'font-mono text-[10px] font-bold px-1.5 py-0.2 rounded border tabular-nums',
                          email.risk_score !== undefined && email.risk_score !== null
                            ? tokens.badgeClass
                            : 'bg-surface-2 text-muted-foreground border-border'
                        )}
                      >
                        {email.risk_score !== undefined && email.risk_score !== null
                          ? `RISK ${score.toFixed(0)} / 100`
                          : 'RISK -- / 100'}
                      </span>

                      <span className="text-[10px] text-muted-foreground">
                        {safeFormatDistanceToNow(email.ingested_at, { addSuffix: true })}
                      </span>
                    </div>

                    {/* Subject Line */}
                    <h4
                      onClick={() => navigate(`/emails/${email.id}`)}
                      className="text-xs font-bold text-foreground group-hover:text-primary transition-colors cursor-pointer truncate font-sans"
                      title={email.subject}
                    >
                      {email.subject || '(No Subject)'}
                    </h4>

                    {/* Sender Line */}
                    <p className="text-[11px] text-muted-foreground truncate">
                      From: <span className="text-foreground/90">{email.sender || 'Unknown'}</span>
                    </p>
                  </div>

                  {/* Tactical Actions & Pivots */}
                  <div className="flex flex-wrap items-center gap-1.5 shrink-0 pt-2 sm:pt-0 border-t sm:border-t-0 border-border/40">
                    <Button
                      size="sm"
                      onClick={() => navigate(`/emails/${email.id}`)}
                      className="h-7 px-2 text-xs font-mono gap-1 bg-primary text-primary-foreground font-semibold"
                    >
                      <span>Analyze</span>
                      <ExternalLink className="size-3" />
                    </Button>

                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => navigate(`/map?emailId=${email.id}`)}
                      className="h-7 px-2 text-xs font-mono border-border gap-1"
                      title="Inspect MTA Relay Path"
                    >
                      <MapPin className="size-3 text-accent" />
                      <span>Map</span>
                    </Button>

                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => navigate(`/graph?emailId=${email.id}`)}
                      className="h-7 px-2 text-xs font-mono border-border gap-1"
                      title="Correlate in Attribution Graph"
                    >
                      <Share2 className="size-3 text-primary" />
                      <span>Graph</span>
                    </Button>

                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        navigate(
                          `/cases?new=true&title=${encodeURIComponent(
                            `Threat Analysis: ${email.subject || email.id.substring(0, 8)}`
                          )}&emailId=${email.id}`
                        )
                      }
                      className="h-7 px-2 text-xs font-mono border-border gap-1"
                      title="Promote to Investigation Case"
                    >
                      <FolderPlus className="size-3 text-muted-foreground" />
                      <span>Case</span>
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 4. Ledger Footer & Pagination */}
      {totalCount > pageSize && (
        <div className="flex items-center justify-between border-t border-border/50 pt-2.5 shrink-0 text-xs font-mono">
          <span className="text-muted-foreground text-[10px]">
            PAGE {page} · SHOWING {filteredEmails.length} ITEMS
          </span>

          <div className="flex items-center gap-1.5">
            <Button
              variant="outline"
              size="sm"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="h-7 px-2 text-xs font-mono border-border"
            >
              <ChevronLeft className="size-3.5" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={filteredEmails.length < pageSize}
              onClick={() => setPage((p) => p + 1)}
              className="h-7 px-2 text-xs font-mono border-border"
            >
              <ChevronRight className="size-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

export default EmailList;
