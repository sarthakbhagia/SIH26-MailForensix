import { useState, useMemo } from 'react';
import { formatDistanceToNow } from 'date-fns';
import {
  Briefcase,
  ChevronRight,
  FolderPlus,
  Loader2,
  Mail,
  Plus,
  RefreshCw,
  Search,
  User,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useCases } from '@/hooks/useCases';
import { Case, CaseSeverity, CaseStatus } from '@/types/case';
import { cn } from '@/lib/utils';

interface CaseListProps {
  onSelectCase: (caseId: string) => void;
  onNewCase: () => void;
  initialSearch?: string;
}

export default function CaseList({ onSelectCase, onNewCase, initialSearch = '' }: CaseListProps) {
  const [searchQuery, setSearchQuery] = useState(initialSearch);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const { data: cases, isLoading, isError, refetch } = useCases();

  const filteredCases = useMemo(() => {
    if (!cases) return [];
    return cases.filter((c: Case) => {
      const matchesSearch =
        searchQuery === '' ||
        c.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (c.description || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        (c.assigned_to || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.id.toLowerCase().includes(searchQuery.toLowerCase());

      if (!matchesSearch) return false;

      if (statusFilter !== 'all' && c.status !== statusFilter) return false;
      if (severityFilter !== 'all' && c.severity !== severityFilter) return false;

      return true;
    });
  }, [cases, searchQuery, statusFilter, severityFilter]);

  const renderStatusBadge = (status: CaseStatus) => {
    switch (status) {
      case 'open':
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/30 uppercase">
            Open
          </span>
        );
      case 'investigating':
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-medium/15 text-medium border border-medium/30 uppercase">
            Investigating
          </span>
        );
      case 'closed':
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-clean/15 text-clean border border-clean/30 uppercase">
            Closed
          </span>
        );
      default:
        return (
          <span className="font-mono text-[9px] px-1.5 py-0.5 rounded bg-surface text-muted-foreground border border-border uppercase">
            {status}
          </span>
        );
    }
  };

  const renderSeverityBadge = (severity: CaseSeverity) => {
    switch (severity) {
      case 'critical':
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-critical/15 text-critical border border-critical/30 uppercase">
            Critical
          </span>
        );
      case 'high':
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-high/15 text-high border border-high/30 uppercase">
            High
          </span>
        );
      case 'medium':
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-medium/15 text-medium border border-medium/30 uppercase">
            Medium
          </span>
        );
      default:
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-clean/15 text-clean border border-clean/30 uppercase">
            Low
          </span>
        );
    }
  };

  return (
    <div className="panel p-5 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border/50 pb-3">
        <div>
          <h2 className="text-base sm:text-lg font-bold text-foreground flex items-center gap-2">
            <Briefcase className="size-4 text-primary" />
            Active Investigation Cases ({filteredCases.length})
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Manage threat campaigns, linked evidence, and incident notes.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            className="h-8 w-8 p-0 text-muted-foreground hover:text-foreground border-border"
            title="Refresh cases"
          >
            <RefreshCw className={`size-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>

          <Button
            size="sm"
            onClick={onNewCase}
            className="h-8 text-xs font-mono font-bold gap-1.5"
          >
            <Plus className="size-3.5" />
            NEW CASE
          </Button>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col md:flex-row md:items-center gap-3 pt-1">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search case title, description, assignee, ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-8 pl-8 text-xs font-mono bg-background/50 border-border/60"
          />
        </div>

        {/* Status Filters */}
        <div className="flex items-center gap-1 overflow-x-auto pb-1 scrollbar-none">
          <span className="label-mono mr-1">STATUS:</span>
          {['all', 'open', 'investigating', 'closed'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={cn(
                'text-[10px] font-mono font-semibold px-2 py-0.5 rounded capitalize transition-colors border',
                statusFilter === st
                  ? 'bg-primary text-primary-foreground border-primary'
                  : 'bg-surface text-muted-foreground border-border/50 hover:bg-muted'
              )}
            >
              {st}
            </button>
          ))}
        </div>

        {/* Severity Filters */}
        <div className="flex items-center gap-1 overflow-x-auto pb-1 scrollbar-none">
          <span className="label-mono mr-1">SEVERITY:</span>
          {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={cn(
                'text-[10px] font-mono font-semibold px-2 py-0.5 rounded uppercase transition-colors border',
                severityFilter === sev
                  ? 'bg-surface-2 text-foreground border-border font-bold'
                  : 'bg-surface text-muted-foreground border-border/50 hover:bg-muted'
              )}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Cases List Content */}
      <div className="pt-2">
        {isLoading && (
          <div className="flex flex-col items-center justify-center p-16 text-muted-foreground gap-3">
            <Loader2 className="size-8 animate-spin text-primary" />
            <p className="label-mono text-[10px]">LOADING CASES LEDGER...</p>
          </div>
        )}

        {!isLoading && isError && (
          <div className="p-8 text-center text-xs text-medium">
            Failed to load cases.{' '}
            <button onClick={() => refetch()} className="underline font-semibold ml-1">
              Retry
            </button>
          </div>
        )}

        {!isLoading && !isError && filteredCases.length === 0 && (
          <div className="flex flex-col items-center justify-center p-12 text-center text-muted-foreground">
            <FolderPlus className="size-10 opacity-40 mb-3 text-muted-foreground" />
            <h4 className="text-sm font-semibold text-foreground">No investigation cases found</h4>
            <p className="text-xs text-muted-foreground mt-1 max-w-sm">
              {searchQuery || statusFilter !== 'all' || severityFilter !== 'all'
                ? 'Try adjusting your search query or filters.'
                : 'Create your first case to organize threat intelligence findings.'}
            </p>
            <Button size="sm" onClick={onNewCase} className="mt-4 text-xs font-mono font-bold gap-1.5">
              <Plus className="size-3.5" />
              CREATE NEW CASE
            </Button>
          </div>
        )}

        {!isLoading && !isError && filteredCases.length > 0 && (
          <div className="divide-y divide-border/40 border border-border/60 rounded bg-surface/30">
            {filteredCases.map((c: Case) => (
              <div
                key={c.id}
                onClick={() => onSelectCase(c.id)}
                className="p-4 hover:bg-surface-2/60 transition-colors cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-3 group"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-xs sm:text-sm font-semibold text-foreground group-hover:text-primary transition-colors truncate max-w-[380px]">
                      {c.title}
                    </h3>
                    {renderStatusBadge(c.status)}
                    {renderSeverityBadge(c.severity)}
                  </div>

                  {c.description && (
                    <p className="text-xs text-muted-foreground line-clamp-1 max-w-2xl">
                      {c.description}
                    </p>
                  )}

                  <div className="flex items-center gap-4 text-[11px] text-muted-foreground font-mono">
                    <span className="flex items-center gap-1">
                      <User className="size-3 text-muted-foreground" />
                      {c.assigned_to || 'Lead Analyst'}
                    </span>

                    <span className="flex items-center gap-1 text-primary">
                      <Mail className="size-3" />
                      {c.email_ids?.length || 0} Evidence Files
                    </span>

                    <span>
                      Created{' '}
                      {c.created_at
                        ? formatDistanceToNow(new Date(c.created_at), { addSuffix: true })
                        : 'recent'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end md:self-center shrink-0">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 text-xs font-mono text-muted-foreground group-hover:text-primary gap-1"
                  >
                    <span>VIEW CASE</span>
                    <ChevronRight className="size-3.5" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

