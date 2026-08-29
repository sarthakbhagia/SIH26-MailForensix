import { useState, useMemo, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Map as MapIcon,
  Mail,
  Search,
  RefreshCw,
  Loader2,
  FileSearch,
  Server,
  Globe,
  Radio,
  Clock,
  ArrowLeft,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from '@/lib/api';
import { EmailSummary } from '@/types/email';
import { TraceMap, HopGeoItem } from '@/components/map/TraceMap';
import { cn, safeFormatDistanceToNow } from '@/lib/utils';
import { getSeverityTokens, getInfrastructureTokens } from '@/lib/severity';

interface TraceMapPageProps {
  analysis?: any;
  emailId?: string;
}

export function TraceMapPage({ analysis: propAnalysis, emailId: propEmailId }: TraceMapPageProps) {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const urlEmailId = searchParams.get('emailId') || propEmailId;
  const urlHop = searchParams.get('hop');

  const [selectedEmailId, setSelectedEmailId] = useState<string | null>(urlEmailId || null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'critical' | 'high' | 'analyzed'>('all');
  const [selectedHopIndex, setSelectedHopIndex] = useState<number | null>(
    urlHop ? parseInt(urlHop, 10) : null
  );

  // 1. Fetch email list for sidebar
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

  // Filter emails for left sidebar
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

  // Auto-select first email if none currently selected
  useEffect(() => {
    if (!selectedEmailId && filteredEmails.length > 0) {
      const first = filteredEmails.find((e) => e.status === 'analyzed') || filteredEmails[0];
      setSelectedEmailId(first.id);
      setSearchParams({ emailId: first.id }, { replace: true });
    }
  }, [filteredEmails, selectedEmailId, setSearchParams]);

  // 2. Fetch analysis for selected email
  const { data: analysisData, isLoading: isAnalysisLoading } = useQuery({
    queryKey: ['analysis', selectedEmailId],
    queryFn: () => api.getAnalysis(selectedEmailId!).then((res) => res.data),
    enabled: !!selectedEmailId && !propAnalysis,
  });

  const currentAnalysis = propAnalysis || analysisData;
  const currentEmail = useMemo(() => emails.find((e) => e.id === selectedEmailId), [emails, selectedEmailId]);

  // 3. Extract and normalize Geo Hops for Canonical Map
  const hops: HopGeoItem[] = useMemo(() => {
    if (!currentAnalysis) return [];

    const geoDataList = currentAnalysis.geo_data || [];
    const relayPath = currentAnalysis.relay_path || [];

    const list: HopGeoItem[] = [];
    const seenCoords: Record<string, number> = {};

    geoDataList.forEach((geo: any, idx: number) => {
      const relayHop = relayPath[idx] || {};
      let lat = typeof geo.latitude === 'number' ? geo.latitude : 0;
      let lon = typeof geo.longitude === 'number' ? geo.longitude : 0;

      if (lat !== 0 || lon !== 0 || geo.country !== 'Unknown' || geo.city !== 'Unknown') {
        const coordKey = `${lat.toFixed(2)},${lon.toFixed(2)}`;
        if (seenCoords[coordKey] !== undefined) {
          seenCoords[coordKey] += 1;
          const count = seenCoords[coordKey];
          lat = lat + (count % 2 === 1 ? 0.35 : -0.35) * Math.ceil(count / 2);
          lon = lon + (count % 2 === 0 ? 0.5 : -0.5) * Math.ceil(count / 2);
        } else {
          seenCoords[coordKey] = 0;
        }

        const infraType = geo.infrastructure_type || (geo.is_private ? 'private' : 'residential');
        const isTor = geo.tor || infraType === 'tor_exit_node';
        const isVpn = geo.vpn || infraType === 'known_vpn' || geo.proxy || infraType === 'proxy';
        const isHosting = geo.hosting || infraType === 'hosting' || ['aws_cloud', 'gcp', 'azure', 'cloud'].includes(infraType);

        list.push({
          index: idx,
          hop_number: relayHop.hop_number ?? (idx + 1),
          latitude: lat,
          longitude: lon,
          ip: geo.ip || relayHop.ip || 'Unknown IP',
          country: geo.country || 'Unknown',
          country_code: geo.country_code || '?',
          city: geo.city || 'Unknown',
          region: geo.region || 'Unknown',
          isp: geo.isp || 'Unknown',
          asn: geo.asn || '?',
          org: geo.org || 'Unknown',
          infrastructureType: infraType,
          riskScore: isTor ? 95 : isVpn ? 70 : isHosting ? 45 : 15,
          delay: relayHop.delay_seconds,
          timestamp: relayHop.timestamp,
          from_host: relayHop.from_host,
          by_host: relayHop.by_host,
        });
      }
    });

    if (list.length === 0 && relayPath.length > 0) {
      relayPath.forEach((r: any, idx: number) => {
        list.push({
          index: idx,
          hop_number: r.hop_number ?? (idx + 1),
          latitude: 30 + idx * 10,
          longitude: -20 + idx * 25,
          ip: r.ip || 'Relay MTA',
          country: 'Transmission Relay',
          country_code: 'MTA',
          city: r.from_host || 'Relay Node',
          region: '',
          isp: r.by_host || 'SMTP Gateway',
          asn: 'AS-RELAY',
          org: 'Intermediate Hop',
          infrastructureType: r.is_private ? 'private' : 'residential',
          riskScore: 25,
          delay: r.delay_seconds,
          timestamp: r.timestamp,
          from_host: r.from_host,
          by_host: r.by_host,
        });
      });
    }

    return list;
  }, [currentAnalysis]);

  const handleSelectEmail = (id: string) => {
    setSelectedEmailId(id);
    setSelectedHopIndex(null);
    setSearchParams({ emailId: id });
  };

  return (
    <div className="space-y-4 max-w-full pb-8">
      {/* Top Header */}
      <div className="panel p-4 sm:p-5 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <MapIcon className="size-4 text-primary" />
            <h1 className="text-lg sm:text-xl font-bold tracking-tight text-foreground">
              MTA Relay Geolocation & Trace Map
            </h1>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            Geographic transmission routing, MTA server hop triangulation, and infrastructure anomaly telemetry.
          </p>
        </div>

        {currentEmail && (
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate(`/emails/${currentEmail.id}`)}
              className="h-8 text-xs font-mono gap-1.5 border-border bg-surface hover:bg-surface-2"
            >
              <ArrowLeft className="size-3.5" />
              <span>Back to Analysis</span>
            </Button>
          </div>
        )}
      </div>

      {/* Main 3-Column Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
        {/* Left Column: Email Evidence Selector (3 cols) */}
        <div className="panel lg:col-span-3 flex flex-col h-[650px] p-3 space-y-2.5">
          <div className="flex items-center justify-between border-b border-border/50 pb-2">
            <span className="label-mono font-semibold flex items-center gap-1.5 text-xs">
              <Mail className="size-3.5 text-primary" />
              Evidence ({filteredEmails.length})
            </span>
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
          <div className="relative">
            <Search className="absolute left-2.5 top-2 size-3 text-muted-foreground" />
            <Input
              placeholder="Search sender, subject..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-7 pl-7 text-xs font-mono"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1 overflow-x-auto pb-0.5">
            {(['all', 'critical', 'high', 'analyzed'] as const).map((filter) => (
              <button
                key={filter}
                onClick={() => setStatusFilter(filter)}
                className={cn(
                  'font-mono text-[9px] uppercase px-2 py-0.5 rounded transition-colors whitespace-nowrap border',
                  statusFilter === filter
                    ? 'bg-primary text-primary-foreground border-primary font-semibold'
                    : 'bg-surface text-muted-foreground border-border/50 hover:bg-surface-2'
                )}
              >
                {filter}
              </button>
            ))}
          </div>

          {/* Email List Items */}
          <div className="flex-1 overflow-y-auto space-y-1.5 pr-1">
            {isEmailsLoading && (
              <div className="flex flex-col items-center justify-center p-8 text-center text-muted-foreground">
                <Loader2 className="size-5 animate-spin text-primary mb-2" />
                <span className="label-mono text-[10px]">LOADING EVIDENCE...</span>
              </div>
            )}

            {!isEmailsLoading && isEmailsError && (
              <div className="p-3 text-center text-xs text-critical">Failed to load email records.</div>
            )}

            {!isEmailsLoading && !isEmailsError && filteredEmails.length === 0 && (
              <div className="flex flex-col items-center justify-center p-6 text-center text-muted-foreground">
                <FileSearch className="size-6 opacity-40 mb-1.5" />
                <p className="text-xs font-medium text-foreground">No evidence matched</p>
              </div>
            )}

            {!isEmailsLoading &&
              !isEmailsError &&
              filteredEmails.map((email) => {
                const isSelected = email.id === selectedEmailId;
                const tokens = getSeverityTokens(email.risk_score || 0);

                return (
                  <div
                    key={email.id}
                    onClick={() => handleSelectEmail(email.id)}
                    className={cn(
                      'p-2.5 rounded border transition-all cursor-pointer text-xs space-y-1',
                      isSelected
                        ? 'border-primary/80 bg-primary/10 shadow-sm'
                        : 'border-border/60 bg-surface hover:bg-surface-2 hover:border-border'
                    )}
                  >
                    <div className="flex items-start justify-between gap-1">
                      <p className="font-semibold text-foreground truncate max-w-[160px]" title={email.subject}>
                        {email.subject || '(No Subject)'}
                      </p>
                      <span className={cn('px-1.5 py-0.2 rounded font-mono text-[9px] font-bold border tabular-nums', tokens.badgeClass)}>
                        {email.risk_score ? email.risk_score.toFixed(0) : '0'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-muted-foreground font-mono">
                      <span className="truncate max-w-[120px]">{email.sender}</span>
                      <span>
                        {safeFormatDistanceToNow(email.ingested_at, { addSuffix: true }, 'recent')}
                      </span>
                    </div>
                  </div>
                );
              })}
          </div>
        </div>

        {/* Center Column: Canonical MapLibre Trace Map (6 cols) */}
        <div className="panel lg:col-span-6 flex flex-col h-[650px] overflow-hidden relative p-0">
          {/* Active Email Banner */}
          {currentEmail && (
            <div className="p-2.5 border-b border-border/50 bg-surface-2/60 flex items-center justify-between gap-2 shrink-0 z-10">
              <div className="flex items-center gap-2 truncate">
                <Radio className="size-3 text-primary animate-pulse shrink-0" />
                <span className="text-xs font-semibold truncate text-foreground">{currentEmail.subject}</span>
              </div>
              <span className="label-mono text-[9px] bg-surface px-2 py-0.5 rounded border border-border shrink-0">
                {hops.length} GEO HOPS
              </span>
            </div>
          )}

          {/* Interactive Map */}
          <div className="flex-1 w-full h-full relative">
            {isAnalysisLoading ? (
              <div className="absolute inset-0 flex flex-col items-center justify-center bg-background/80 z-20">
                <Loader2 className="size-7 animate-spin text-primary mb-2" />
                <span className="label-mono text-[10px]">RESOLVING RELAY COORDINATES...</span>
              </div>
            ) : (
              <TraceMap
                hops={hops}
                selectedHopIndex={selectedHopIndex}
                onHopSelect={(idx) => {
                  setSelectedHopIndex(idx);
                  setSearchParams({ emailId: selectedEmailId!, hop: String(idx) });
                }}
              />
            )}
          </div>
        </div>

        {/* Right Column: Hop Routing Sequence & Telemetry (3 cols) */}
        <div className="panel lg:col-span-3 flex flex-col h-[650px] p-3 space-y-2.5">
          <div className="flex items-center justify-between border-b border-border/50 pb-2">
            <span className="label-mono font-semibold flex items-center gap-1.5 text-xs">
              <Server className="size-3.5 text-primary" />
              Routing Sequence ({hops.length})
            </span>
          </div>

          <div className="flex-1 overflow-y-auto space-y-2 pr-1">
            {hops.length === 0 ? (
              <p className="text-xs text-muted-foreground text-center py-8 font-mono">
                No relay route hops available.
              </p>
            ) : (
              hops.map((hop, idx) => {
                const isSelected = selectedHopIndex === idx;
                const isOrigin = idx === 0;
                const isDestination = idx === hops.length - 1;
                const infra = getInfrastructureTokens(hop.infrastructureType);
                const isAnonymized = infra.category === 'tor' || infra.category === 'vpn';
                const isCloud = infra.category === 'hosting';

                return (
                  <div
                    key={idx}
                    onClick={() => {
                      setSelectedHopIndex(idx);
                      setSearchParams({ emailId: selectedEmailId!, hop: String(idx) });
                    }}
                    className={cn(
                      'p-2.5 rounded border transition-all cursor-pointer text-xs space-y-1',
                      isSelected
                        ? 'border-primary ring-1 ring-primary bg-primary/10'
                        : 'border-border/60 bg-surface hover:bg-surface-2 hover:border-border'
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={cn(
                            'size-2 rounded-full shrink-0',
                            isAnonymized ? 'bg-critical' : isCloud ? 'bg-high' : 'bg-primary'
                          )}
                        />
                        <span className="font-bold font-mono text-[11px]">Hop #{idx + 1}</span>
                      </div>
                      <span className="label-mono text-[9px] uppercase px-1.5 py-0.2 rounded bg-surface border border-border">
                        {isOrigin ? 'Origin' : isDestination ? 'Destination' : 'Relay'}
                      </span>
                    </div>

                    <div className="font-mono text-xs text-primary font-semibold truncate select-all">{hop.ip}</div>

                    <div className="text-[11px] text-muted-foreground flex items-center gap-1 truncate">
                      <Globe className="size-3 shrink-0" />
                      <span className="truncate">
                        {hop.city !== 'Unknown' ? `${hop.city}, ` : ''}{hop.country}
                      </span>
                    </div>

                    <div className="text-[10px] text-muted-foreground flex items-center justify-between font-mono pt-0.5 border-t border-border/30">
                      <span className="truncate max-w-[130px]">{hop.isp || hop.org}</span>
                      {hop.delay !== undefined && (
                        <span className="flex items-center gap-0.5 text-foreground font-semibold">
                          <Clock className="size-2.5" />
                          +{hop.delay.toFixed(1)}s
                        </span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default TraceMapPage;
