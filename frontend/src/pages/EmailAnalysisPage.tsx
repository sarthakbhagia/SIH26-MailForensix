import { useNavigate, useParams } from 'react-router-dom';
import { useEmail } from '@/hooks/useEmails';
import { useAnalysis as useAnalysisHook } from '@/hooks/useAnalysis';
import ThreatScoreBadge from '@/components/email/ThreatScoreBadge';
import EmailDetail from '@/components/email/EmailDetail';
import HeaderInspector from '@/components/email/HeaderInspector';
import { AuthenticationPanel } from '@/components/analysis/AuthenticationPanel';
import { RelayPathViewer } from '@/components/analysis/RelayPathViewer';
import { IOCTable } from '@/components/analysis/IOCTable';
import { RiskBreakdown } from '@/components/analysis/RiskBreakdown';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ArrowLeft, FileCheck2, FolderPlus, Share2, ShieldAlert } from 'lucide-react';

export default function EmailAnalysisPage() {
  const navigate = useNavigate();
  const { emailId } = useParams<{ emailId: string }>();
  const { data: email, isLoading: emailLoading } = useEmail(emailId!);
  const { data: analysis, isLoading: analysisLoading } = useAnalysisHook(emailId!);

  if (emailLoading || analysisLoading) {
    return (
      <div className="space-y-6 max-w-6xl mx-auto p-4">
        <div className="h-32 bg-muted/40 animate-pulse rounded-xl border border-border/50" />
        <div className="h-[600px] bg-muted/40 animate-pulse rounded-xl border border-border/50" />
      </div>
    );
  }

  // Fallback if data absent
  const mEmail = email || { 
    id: emailId, subject: 'Urgent: Invoice Overdue', status: 'analyzed', risk_score: 92, ingested_at: new Date().toISOString(), headers: {} 
  };
  const mAnalysis = analysis || { 
    composite_risk_score: 92, 
    attribution_category: 'Phishing',
    risk_breakdown: {},
  };

  const senderDomain = (mEmail as any)?.sender?.includes('@')
    ? (mEmail as any).sender.split('@').pop()
    : '';

  const authStatus = (mAnalysis as any)?.auth_status || {};
  const authResult = (mAnalysis as any)?.auth_result || {};

  const spf = {
    status: (authResult.spf_status || authStatus.spf_status || authStatus.spf || 'unavailable') as any,
    domain: authResult.spf_domain || authStatus.spf_domain || senderDomain || '',
    ip: authResult.spf_ip || authStatus.spf_ip || (mAnalysis as any)?.geo_data?.[0]?.ip || '',
    record: authResult.spf_record || authStatus.spf_record || '',
    details: authResult.spf_details || authStatus.spf_details || '',
  };

  const dkim = {
    status: (authResult.dkim_status || authStatus.dkim_status || authStatus.dkim || 'unavailable') as any,
    domain: authResult.dkim_domain || authStatus.dkim_domain || senderDomain || '',
    selector: authResult.dkim_selector || authStatus.dkim_selector || 'default',
    details: authResult.dkim_details || authStatus.dkim_details || '',
  };

  const dmarc = {
    status: (authResult.dmarc_status || authStatus.dmarc_status || authStatus.dmarc || 'unavailable') as any,
    policy: (authResult.dmarc_policy || authStatus.dmarc_policy || authStatus.policy || 'none') as any,
    domain: authResult.dmarc_domain || authStatus.dmarc_domain || senderDomain || '',
    alignment_spf: Boolean(authResult.alignment_spf ?? authStatus.alignment_spf ?? (authResult.spf_status === 'pass' || authStatus.spf === 'pass')),
    alignment_dkim: Boolean(authResult.alignment_dkim ?? authStatus.alignment_dkim ?? (authResult.dkim_status === 'pass' || authStatus.dkim === 'pass')),
    record: authResult.dmarc_record || authStatus.dmarc_record || '',
    details: authResult.dmarc_details || authStatus.dmarc_details || '',
  };

  const hops = ((mAnalysis as any)?.relay_path || []).map((hop: any, idx: number) => ({
    hop_number: hop.hop_number ?? (idx + 1),
    from_host: hop.from_host || hop.hostname || 'unknown',
    by_host: hop.by_host || hop.hostname || 'unknown',
    ip: hop.ip || '',
    timestamp: hop.timestamp || '',
    protocol: hop.protocol || 'ESMTP',
    delay_seconds: hop.delay_seconds ?? 0,
    is_private: hop.is_private ?? false,
    infrastructure_type: hop.infrastructure_type || (hop.is_private ? 'private' : 'unknown'),
    anomalies: hop.anomalies || [],
  }));

  const rawIocs = (mAnalysis as any)?.iocs || [];
  const formattedIocs = rawIocs.map((ioc: any) => {
    const rawType = String(ioc.type || '').toUpperCase();
    let type: 'URL' | 'IP' | 'Domain' | 'Hash' = 'URL';
    if (rawType === 'IP') type = 'IP';
    else if (rawType === 'DOMAIN') type = 'Domain';
    else if (rawType === 'HASH') type = 'Hash';

    return {
      type,
      value: ioc.value || '',
      risk_score: ioc.risk_score ?? 0,
      reason: ioc.reason || '',
      source: ioc.source || 'Pipeline',
    };
  });

  const riskFactors = mAnalysis.risk_breakdown
    ? Object.entries(mAnalysis.risk_breakdown).map(([name, score]) => ({
        name: name.toUpperCase(),
        score: typeof score === 'number' ? score : (score as any)?.raw_score ?? 0,
        percentage: 20,
        color: '#3b82f6',
      }))
    : undefined;

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-10">
      <div className="flex flex-col gap-4 p-6 bg-card/60 rounded-xl border border-border/60 shadow-sm backdrop-blur-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate('/ingest')}
              className="h-8 w-8 p-0 shrink-0"
              title="Back to Email List"
            >
              <ArrowLeft className="w-4 h-4" />
            </Button>
            <ThreatScoreBadge score={mAnalysis.composite_risk_score || (mEmail as any).risk_score || 0} />
            <div>
              <h1 className="text-xl md:text-2xl font-bold tracking-tight text-foreground line-clamp-1">
                {mEmail.subject}
              </h1>
              <div className="flex flex-wrap gap-2 items-center text-xs text-muted-foreground mt-1">
                <Badge variant="outline" className="uppercase tracking-wider text-[10px]">
                  {(mEmail as any).status || 'analyzed'}
                </Badge>
                {mAnalysis.attribution_category && (
                  <Badge variant="destructive" className="uppercase font-semibold tracking-wider text-[10px] flex items-center gap-1">
                    <ShieldAlert className="h-3 w-3" />
                    {mAnalysis.attribution_category}
                  </Badge>
                )}
                <span className="opacity-50">•</span>
                <span>Analyzed: {new Date((mEmail as any).ingested_at || Date.now()).toLocaleDateString()}</span>
                <span className="opacity-50">•</span>
                <span className="font-mono text-[10px] opacity-75">ID: {String(mEmail.id).slice(0, 8)}...</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 self-end md:self-center shrink-0">
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate(`/graph?emailId=${emailId}`)}
              className="h-8 text-xs gap-1.5 font-medium border-border/60"
            >
              <Share2 className="w-3.5 h-3.5" />
              <span>Threat Graph</span>
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate('/cases')}
              className="h-8 text-xs gap-1.5 font-medium border-border/60"
            >
              <FolderPlus className="w-3.5 h-3.5" />
              <span>Add to Case</span>
            </Button>
            <Button
              size="sm"
              onClick={() => navigate(`/reports?emailId=${emailId}`)}
              className="h-8 text-xs gap-1.5 font-medium bg-primary text-primary-foreground hover:bg-primary/90"
            >
              <FileCheck2 className="w-3.5 h-3.5" />
              <span>Forensic Report</span>
            </Button>
          </div>
        </div>
      </div>

      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="grid w-full grid-cols-4 max-w-2xl mb-8 bg-muted/50 p-1">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="headers">Headers & Auth</TabsTrigger>
          <TabsTrigger value="iocs">Extracted IOCs</TabsTrigger>
          <TabsTrigger value="raw">Raw Content</TabsTrigger>
        </TabsList>
        
        <TabsContent value="overview" className="space-y-6 mt-0 animate-in fade-in-50">
          <EmailDetail email={mEmail as any} />
          <RiskBreakdown overallScore={mAnalysis.composite_risk_score || (mEmail as any).risk_score || 0} factors={riskFactors} />
        </TabsContent>
        
        <TabsContent value="headers" className="space-y-6 mt-0 animate-in fade-in-50">
          <AuthenticationPanel spf={spf} dkim={dkim} dmarc={dmarc} />
          <RelayPathViewer hops={hops} />
        </TabsContent>

        <TabsContent value="iocs" className="mt-0 animate-in fade-in-50">
          <Card className="bg-card/50">
            <CardHeader>
              <CardTitle>Indicators of Compromise</CardTitle>
            </CardHeader>
            <CardContent>
              {formattedIocs.length > 0 ? (
                <div className="rounded-lg border border-border/60 overflow-hidden">
                  <IOCTable iocs={formattedIocs} />
                </div>
              ) : (
                <p className="text-sm text-muted-foreground py-4 text-center">No indicators of compromise detected in this email.</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="raw" className="space-y-6 mt-0 animate-in fade-in-50">
          <HeaderInspector headers={(mEmail as any).headers || {}} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
