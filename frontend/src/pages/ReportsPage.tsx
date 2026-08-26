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

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { api } from '@/lib/api';
import { EmailSummary } from '@/types/email';
import ReportPreview from '@/components/reports/ReportPreview';
import ReportDownload from '@/components/reports/ReportDownload';

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
      // Must be analyzed or have a risk score for report generation
      const matchesSearch =
        searchQuery === '' ||
        (email.subject || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        (email.sender || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        email.id.toLowerCase().includes(searchQuery.toLowerCase());

      if (!matchesSearch) return false;

      if (statusFilter === 'critical') {
        return (email.risk_score || 0) >= 90;
      }
      if (statusFilter === 'high') {
        return (email.risk_score || 0) >= 75 && (email.risk_score || 0) < 90;
      }
      if (statusFilter === 'analyzed') {
        return email.status === 'analyzed';
      }
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
        <Badge variant="outline" className="text-[10px] px-1.5 py-0">
          Pending
        </Badge>
      );
    }
    if (score >= 90) {
      return (
        <Badge
          variant="destructive"
          className="text-[10px] font-bold px-1.5 py-0 bg-red-500/20 text-red-400 border-red-500/40 uppercase"
        >
          Critical ({score.toFixed(0)})
        </Badge>
      );
    }
    if (score >= 75) {
      return (
        <Badge
          variant="secondary"
          className="text-[10px] font-bold px-1.5 py-0 bg-amber-500/20 text-amber-400 border-amber-500/40 uppercase"
        >
          High ({score.toFixed(0)})
        </Badge>
      );
    }
    if (score >= 50) {
      return (
        <Badge
          variant="outline"
          className="text-[10px] font-bold px-1.5 py-0 bg-yellow-500/20 text-yellow-400 border-yellow-500/40 uppercase"
        >
          Medium ({score.toFixed(0)})
        </Badge>
      );
    }
    return (
      <Badge
        variant="outline"
        className="text-[10px] font-bold px-1.5 py-0 bg-emerald-500/20 text-emerald-400 border-emerald-500/40 uppercase"
      >
        Low ({score.toFixed(0)})
      </Badge>
    );
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
            <FileCheck2 className="w-7 h-7 text-primary" />
            Forensic Reports & Export
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
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

      {/* Main 2-Column Content */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Sidebar: Email Evidence Selector */}
        <Card className="lg:col-span-4 flex flex-col bg-card/60 backdrop-blur-md border border-border/60 shadow-sm h-[calc(100vh-210px)] min-h-[580px]">
          <CardHeader className="p-4 pb-3 border-b border-border/40 shrink-0 space-y-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Mail className="w-4 h-4 text-primary" />
                Analyzed Evidence ({filteredEmails.length})
              </CardTitle>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => refetchEmails()}
                className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground"
                title="Refresh email list"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isEmailsLoading ? 'animate-spin' : ''}`} />
              </Button>
            </div>

            {/* Search Bar */}
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                placeholder="Search sender, subject..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-8 pl-8 text-xs bg-background/50 border-border/60"
              />
            </div>

            {/* Filter Pills */}
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none">
              {(['all', 'critical', 'high', 'analyzed'] as const).map((filter) => (
                <button
                  key={filter}
                  onClick={() => setStatusFilter(filter)}
                  className={`text-[11px] font-medium px-2.5 py-1 rounded-full border transition-colors capitalize whitespace-nowrap ${
                    statusFilter === filter
                      ? 'bg-primary text-primary-foreground border-primary'
                      : 'bg-background/40 text-muted-foreground border-border/50 hover:bg-muted'
                  }`}
                >
                  {filter}
                </button>
              ))}
            </div>
          </CardHeader>

          {/* Email List */}
          <CardContent className="p-2 flex-1 overflow-y-auto space-y-1.5 scrollbar-thin scrollbar-thumb-border scrollbar-track-transparent">
            {isEmailsLoading && (
              <div className="flex flex-col items-center justify-center p-8 text-center text-muted-foreground">
                <Loader2 className="w-6 h-6 animate-spin text-primary mb-2" />
                <span className="text-xs">Loading email records...</span>
              </div>
            )}

            {!isEmailsLoading && isEmailsError && (
              <div className="p-4 text-center text-xs text-amber-400">
                Failed to load email records.
              </div>
            )}

            {!isEmailsLoading && !isEmailsError && filteredEmails.length === 0 && (
              <div className="flex flex-col items-center justify-center p-8 text-center text-muted-foreground">
                <FileSearch className="w-8 h-8 opacity-50 mb-2" />
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
                    className={`p-3 rounded-lg border transition-all cursor-pointer ${
                      isSelected
                        ? 'border-primary/80 bg-primary/10 shadow-sm ring-1 ring-primary/40'
                        : 'border-border/40 bg-background/30 hover:bg-muted/40 hover:border-border/80'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <p className="text-xs font-semibold text-foreground truncate max-w-[200px]">
                        {email.subject || 'No Subject'}
                      </p>
                      {renderRiskBadge(email.risk_score)}
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-muted-foreground mt-1.5">
                      <span className="truncate max-w-[150px]">{email.sender}</span>
                      <span className="shrink-0 text-[10px]">
                        {email.ingested_at
                          ? formatDistanceToNow(new Date(email.ingested_at), { addSuffix: true })
                          : 'recent'}
                      </span>
                    </div>
                  </div>
                );
              })}
          </CardContent>
        </Card>

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

