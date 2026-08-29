import { useState, useMemo } from 'react';
import { formatDistanceToNow } from 'date-fns';
import {
  Briefcase,
  Search,
  RefreshCw,
  Loader2,
  Mail,
  User,
  Plus,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { SeverityBadge } from '@/components/forensics/SeverityBadge';
import { Case, CaseStatus } from '@/types/case';
import { cn } from '@/lib/utils';


export interface CaseListProps {
  cases: Case[];
  selectedCaseId?: string | null;
  onSelectCase: (caseId: string) => void;
  onNewCase: () => void;
  isLoading?: boolean;
  isError?: boolean;
  onRefresh?: () => void;
  initialSearch?: string;
  className?: string;
}

export function CaseList({
  cases = [],
  selectedCaseId,
  onSelectCase,
  onNewCase,
  isLoading = false,
  isError = false,
  onRefresh,
  initialSearch = '',
  className,
}: CaseListProps) {
  const [searchQuery, setSearchQuery] = useState(initialSearch);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const filteredCases = useMemo(() => {
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
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.2 rounded bg-primary/15 text-primary border border-primary/30 uppercase">
            Open
          </span>
        );
      case 'investigating':
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.2 rounded bg-high/15 text-high border border-high/30 uppercase">
            Investigating
          </span>
        );
      case 'closed':
        return (
          <span className="font-mono text-[9px] font-bold px-1.5 py-0.2 rounded bg-clean/15 text-clean border border-clean/30 uppercase">
            Closed
          </span>
        );
      default:
        return (
          <span className="font-mono text-[9px] px-1.5 py-0.2 rounded bg-surface-2 text-muted-foreground border border-border uppercase">
            {status}
          </span>
        );
    }
  };

  const formatTimestamp = (dateStr: string) => {
    try {
      return formatDistanceToNow(new Date(dateStr), { addSuffix: true });
    } catch {
      return 'recently';
    }
  };

  return (
    <div className={cn('flex flex-col h-full space-y-2.5 min-w-0 select-none', className)}>
      {/* Queue Toolbar */}
      <div className="flex items-center justify-between gap-2 border-b border-border/50 pb-2.5 shrink-0">
        <div className="flex items-center gap-2">
          <Briefcase className="size-4 text-primary" />
          <span className="text-xs font-semibold uppercase tracking-wider text-foreground">
            Case Queue ({filteredCases.length})
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          {onRefresh && (
            <Button
              variant="ghost"
              size="sm"
              onClick={onRefresh}
              className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
              title="Refresh case queue"
            >
              <RefreshCw className={`size-3 ${isLoading ? 'animate-spin' : ''}`} />
            </Button>
          )}
          <Button
            size="sm"
            onClick={onNewCase}
            className="h-7 px-2.5 text-xs font-mono gap-1 font-semibold bg-primary text-primary-foreground"
          >
            <Plus className="size-3" />
            <span>New Case</span>
          </Button>
        </div>
      </div>

      {/* Search Input */}
      <div className="relative shrink-0">
        <Search className="absolute left-2.5 top-2 size-3.5 text-muted-foreground" />
        <Input
          placeholder="Filter cases by title, ID, investigator..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-8 h-7 text-xs font-mono bg-background border-border"
        />
      </div>

      {/* Filter Chips */}
      <div className="flex items-center gap-1.5 shrink-0 text-xs font-mono">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="flex-1 h-7 rounded border border-border bg-surface px-2 text-[10px] font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
        >
          <option value="all">Status: All</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="closed">Closed</option>
        </select>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="flex-1 h-7 rounded border border-border bg-surface px-2 text-[10px] font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
        >
          <option value="all">Severity: All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Scrollable Case Queue List */}
      <div className="flex-1 overflow-y-auto space-y-2 pr-1 min-h-0">
        {isLoading ? (
          <div className="p-8 flex flex-col items-center justify-center gap-2 text-muted-foreground">
            <Loader2 className="size-6 animate-spin text-primary" />
            <span className="label-mono text-[10px]">SYNCING INVESTIGATION QUEUE...</span>
          </div>
        ) : isError ? (
          <div className="p-4 text-center text-xs text-critical bg-critical/10 border border-critical/30 rounded">
            Failed to load cases queue.
          </div>
        ) : filteredCases.length === 0 ? (
          <div className="p-8 text-center text-muted-foreground flex flex-col items-center justify-center rounded border border-border bg-surface-2/40">
            <Briefcase className="size-8 opacity-30 mb-2" />
            <p className="text-xs font-semibold text-foreground">No matching cases</p>
            <p className="text-[11px] text-muted-foreground mt-0.5 max-w-xs">
              {searchQuery ? `No cases match filter "${searchQuery}".` : 'No cases recorded in datastore.'}
            </p>
          </div>
        ) : (
          filteredCases.map((caseItem: Case) => {
            const isSelected = caseItem.id === selectedCaseId;
            return (
              <div
                key={caseItem.id}
                onClick={() => onSelectCase(caseItem.id)}
                className={cn(
                  'panel p-3 transition-all duration-150 cursor-pointer space-y-1.5 relative border',
                  isSelected
                    ? 'border-primary ring-1 ring-primary bg-primary/10 shadow-sm'
                    : 'border-border/60 bg-surface hover:bg-surface-2 hover:border-border'
                )}
              >
                <div className="flex items-center justify-between gap-1.5">
                  <span className="label-mono text-[9px] font-bold text-foreground/80">
                    CASE #{caseItem.id.substring(0, 8)}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {renderStatusBadge(caseItem.status)}
                    <SeverityBadge severity={caseItem.severity} />
                  </div>
                </div>

                <h3 className="text-xs font-bold text-foreground truncate" title={caseItem.title}>
                  {caseItem.title}
                </h3>

                {caseItem.description && (
                  <p className="text-[11px] text-muted-foreground line-clamp-1">
                    {caseItem.description}
                  </p>
                )}

                <div className="flex items-center justify-between text-[10px] font-mono text-muted-foreground pt-1 border-t border-border/30">
                  <div className="flex items-center gap-1 truncate max-w-[120px]">
                    <User className="size-3 shrink-0" />
                    <span className="truncate">{caseItem.assigned_to || 'Unassigned'}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Mail className="size-3" />
                    <span>{caseItem.email_ids?.length || 0}</span>
                    <span>·</span>
                    <span>{formatTimestamp(caseItem.updated_at || caseItem.created_at)}</span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

export default CaseList;
