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

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { useCases } from '@/hooks/useCases';
import { Case, CaseSeverity, CaseStatus } from '@/types/case';

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
          <Badge variant="outline" className="text-[10px] bg-sky-500/10 text-sky-400 border-sky-500/30 uppercase font-semibold">
            Open
          </Badge>
        );
      case 'investigating':
        return (
          <Badge variant="outline" className="text-[10px] bg-amber-500/10 text-amber-400 border-amber-500/30 uppercase font-semibold">
            Investigating
          </Badge>
        );
      case 'closed':
        return (
          <Badge variant="outline" className="text-[10px] bg-emerald-500/10 text-emerald-400 border-emerald-500/30 uppercase font-semibold">
            Closed
          </Badge>
        );
      default:
        return (
          <Badge variant="outline" className="text-[10px] uppercase font-semibold">
            {status}
          </Badge>
        );
    }
  };

  const renderSeverityBadge = (severity: CaseSeverity) => {
    switch (severity) {
      case 'critical':
        return (
          <Badge variant="destructive" className="text-[10px] uppercase font-bold bg-red-500/20 text-red-400 border-red-500/40">
            Critical
          </Badge>
        );
      case 'high':
        return (
          <Badge variant="secondary" className="text-[10px] uppercase font-bold bg-amber-500/20 text-amber-400 border-amber-500/40">
            High
          </Badge>
        );
      case 'medium':
        return (
          <Badge variant="outline" className="text-[10px] uppercase font-bold bg-yellow-500/20 text-yellow-400 border-yellow-500/40">
            Medium
          </Badge>
        );
      default:
        return (
          <Badge variant="outline" className="text-[10px] uppercase font-bold bg-emerald-500/20 text-emerald-400 border-emerald-500/40">
            Low
          </Badge>
        );
    }
  };

  return (
    <Card className="bg-card/60 backdrop-blur-md border border-border/60 shadow-sm">
      <CardHeader className="p-4 pb-3 border-b border-border/40 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <CardTitle className="text-base font-bold text-foreground flex items-center gap-2">
              <Briefcase className="w-5 h-5 text-primary" />
              Investigation Cases ({filteredCases.length})
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              Manage threat campaigns, linked evidence, and incident notes.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              className="h-8 w-8 p-0 text-muted-foreground hover:text-foreground"
              title="Refresh cases"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            </Button>

            <Button
              size="sm"
              onClick={onNewCase}
              className="h-8 text-xs gap-1.5 font-medium bg-primary text-primary-foreground hover:bg-primary/90"
            >
              <Plus className="w-3.5 h-3.5" />
              New Case
            </Button>
          </div>
        </div>

        {/* Filter & Search Bar */}
        <div className="flex flex-col md:flex-row md:items-center gap-3 pt-1">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder="Search case title, description, assignee, ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-8 pl-8 text-xs bg-background/50 border-border/60"
            />
          </div>

          {/* Status Filters */}
          <div className="flex items-center gap-1 overflow-x-auto pb-1 scrollbar-none">
            <span className="text-[10px] uppercase font-bold text-muted-foreground mr-1">Status:</span>
            {['all', 'open', 'investigating', 'closed'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`text-[11px] font-medium px-2 py-0.5 rounded capitalize transition-colors ${
                  statusFilter === st
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-background/40 text-muted-foreground border border-border/50 hover:bg-muted'
                }`}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Severity Filters */}
          <div className="flex items-center gap-1 overflow-x-auto pb-1 scrollbar-none">
            <span className="text-[10px] uppercase font-bold text-muted-foreground mr-1">Severity:</span>
            {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`text-[11px] font-medium px-2 py-0.5 rounded uppercase text-[10px] transition-colors ${
                  severityFilter === sev
                    ? 'bg-muted text-foreground border border-border/80 font-bold'
                    : 'bg-background/40 text-muted-foreground border border-border/50 hover:bg-muted'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-0">
        {isLoading && (
          <div className="flex flex-col items-center justify-center p-16 text-muted-foreground gap-3">
            <Loader2 className="w-8 h-8 animate-spin text-primary" />
            <p className="text-xs font-medium">Loading cases...</p>
          </div>
        )}

        {!isLoading && isError && (
          <div className="p-8 text-center text-xs text-amber-400">
            Failed to load cases.{' '}
            <button onClick={() => refetch()} className="underline font-semibold ml-1">
              Retry
            </button>
          </div>
        )}

        {!isLoading && !isError && filteredCases.length === 0 && (
          <div className="flex flex-col items-center justify-center p-12 text-center text-muted-foreground">
            <FolderPlus className="w-10 h-10 opacity-40 mb-3 text-muted-foreground" />
            <h4 className="text-sm font-semibold text-foreground">No investigation cases found</h4>
            <p className="text-xs text-muted-foreground mt-1 max-w-sm">
              {searchQuery || statusFilter !== 'all' || severityFilter !== 'all'
                ? 'Try adjusting your search query or filters.'
                : 'Create your first case to organize threat intelligence findings.'}
            </p>
            <Button size="sm" onClick={onNewCase} className="mt-4 text-xs gap-1.5">
              <Plus className="w-3.5 h-3.5" />
              Create New Case
            </Button>
          </div>
        )}

        {!isLoading && !isError && filteredCases.length > 0 && (
          <div className="divide-y divide-border/40">
            {filteredCases.map((c: Case) => (
              <div
                key={c.id}
                onClick={() => onSelectCase(c.id)}
                className="p-4 hover:bg-muted/30 transition-colors cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-3 group"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors truncate max-w-[380px]">
                      {c.title}
                    </h3>
                    {renderStatusBadge(c.status)}
                    {renderSeverityBadge(c.severity)}
                  </div>

                  {c.description && (
                    <p className="text-xs text-muted-foreground line-clamp-1 max-w-2xl font-sans">
                      {c.description}
                    </p>
                  )}

                  <div className="flex items-center gap-4 text-[11px] text-muted-foreground font-mono">
                    <span className="flex items-center gap-1">
                      <User className="w-3.5 h-3.5" />
                      {c.assigned_to || 'Lead Analyst'}
                    </span>

                    <span className="flex items-center gap-1 text-sky-400">
                      <Mail className="w-3.5 h-3.5" />
                      {c.email_ids?.length || 0} Evidence Files
                    </span>

                    <span>
                      Created{' '}
                      {c.created_at
                        ? formatDistanceToNow(new Date(c.created_at), { addSuffix: true })
                        : 'recently'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end md:self-center shrink-0">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 text-xs text-muted-foreground group-hover:text-primary gap-1"
                  >
                    <span>View Case</span>
                    <ChevronRight className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
