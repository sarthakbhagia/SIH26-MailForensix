import { useState, useMemo, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Map, Marker, Source, Layer, Popup, NavigationControl } from 'react-map-gl/maplibre';
import 'maplibre-gl/dist/maplibre-gl.css';
import { formatDistanceToNow } from 'date-fns';
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
  ExternalLink,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from '@/lib/api';
import { EmailSummary } from '@/types/email';
import { cn } from '@/lib/utils';

const MAP_STYLE = 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json';

interface HopGeo {
  index: number;
  hop_number?: number;
  latitude: number;
  longitude: number;
  ip: string;
  country: string;
  country_code: string;
  city: string;
  region: string;
  isp: string;
  asn: string;
  org: string;
  infrastructureType: string;
  riskScore: number;
  delay?: number;
  timestamp?: string;
  from_host?: string;
  by_host?: string;
}

interface TraceMapPageProps {
  analysis?: any;
  emailId?: string;
}

export function TraceMapPage({ analysis: propAnalysis, emailId: propEmailId }: TraceMapPageProps) {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const urlEmailId = searchParams.get('emailId') || propEmailId;

  const [selectedEmailId, setSelectedEmailId] = useState<string | null>(urlEmailId || null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'critical' | 'high' | 'analyzed'>('all');
  const [selectedHop, setSelectedHop] = useState<HopGeo | null>(null);

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

      if (statusFilter === 'critical') return (email.risk_score || 0) >= 90;
      if (statusFilter === 'high') return (email.risk_score || 0) >= 75 && (email.risk_score || 0) < 90;
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

  // 2. Fetch analysis for selected email (if not provided as prop)
  const { data: analysisData, isLoading: isAnalysisLoading } = useQuery({
    queryKey: ['analysis', selectedEmailId],
    queryFn: () => api.getAnalysis(selectedEmailId!).then((res) => res.data),
    enabled: !!selectedEmailId && !propAnalysis,
  });

  const currentAnalysis = propAnalysis || analysisData;
  const currentEmail = useMemo(() => emails.find((e) => e.id === selectedEmailId), [emails, selectedEmailId]);

  // 3. Extract and normalize Geo Hops for Map
  const hops: HopGeo[] = useMemo(() => {
    if (!currentAnalysis) return [];

    const geoDataList = currentAnalysis.geo_data || [];
    const relayPath = currentAnalysis.relay_path || [];

    const list: HopGeo[] = [];

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

  const geojsonLine = useMemo(() => {
    return {
      type: 'FeatureCollection' as const,
      features: [
        {
          type: 'Feature' as const,
          geometry: {
            type: 'LineString' as const,
            coordinates: hops.map((h) => [h.longitude, h.latitude]),
          },
          properties: {},
        },
      ],
    };
  }, [hops]);

  const handleSelectEmail = (id: string) => {
    setSelectedEmailId(id);
    setSelectedHop(null);
    setSearchParams({ emailId: id });
  };

  const getMarkerColor = (type: string) => {
    if (type === 'tor_exit_node' || type === 'known_vpn') return '#ff3366';
    if (type === 'hosting' || type === 'aws_cloud' || type === 'cloud') return '#ffb020';
    if (type === 'private') return '#64748b';
    return '#00e5ff';
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
    <div className="space-y-4 max-w-7xl mx-auto pb-10">
      {/* Top Header */}
      <div className="panel p-5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
              <MapIcon className="size-5 text-primary" />
              MTA Relay Trace Map
            </h1>
            <p className="text-xs text-muted-foreground mt-0.5">
              Geographic transmission routing, MTA server hop triangulation, and infrastructure inspection.
            </p>
          </div>

          {currentEmail && (
            <div className="flex items-center gap-2.5">
              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate(`/emails/${currentEmail.id}`)}
                className="h-8 text-xs font-mono gap-1.5 border-border bg-surface hover:bg-muted"
              >
                <span>Email Workstation</span>
                <ExternalLink className="size-3.5" />
              </Button>
            </div>
          )}
        </div>
      </div>

      {/* Main 3-Column Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
        {/* Left Column: Email Selector */}
        <div className="panel lg:col-span-3 flex flex-col h-[calc(100vh-210px)] min-h-[580px] p-3 space-y-2.5">
          <div className="flex items-center justify-between border-b border-border/50 pb-2">
            <span className="label-mono font-semibold flex items-center gap-1.5">
              <Mail className="size-3.5 text-primary" />
              Emails ({filteredEmails.length})
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => refetchEmails()}
              className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
              title="Refresh email list"
            >
              <RefreshCw className={`size-3 ${isEmailsLoading ? 'animate-spin' : ''}`} />
            </Button>
          </div>

          {/* Search Input */}
          <div className="relative">
            <Search className="absolute left-2.5 top-2 size-3 text-muted-foreground" />
            <Input
              placeholder="Search subject, sender..."
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
                  'font-mono text-[9px] uppercase px-2 py-0.5 rounded transition-colors whitespace-nowrap border',
                  statusFilter === filter
                    ? 'bg-primary text-primary-foreground border-primary font-semibold'
                    : 'bg-surface text-muted-foreground border-border/50 hover:bg-muted'
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
              <div className="p-3 text-center text-xs text-medium">Failed to load email records.</div>
            )}

            {!isEmailsLoading && !isEmailsError && filteredEmails.length === 0 && (
              <div className="flex flex-col items-center justify-center p-6 text-center text-muted-foreground">
                <FileSearch className="size-6 opacity-40 mb-1.5" />
                <p className="text-xs font-medium text-foreground">No emails found</p>
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
                      'p-2.5 rounded border transition-all cursor-pointer text-xs',
                      isSelected
                        ? 'border-primary/80 bg-primary/10 shadow-glow'
                        : 'border-border/50 bg-surface/40 hover:bg-surface hover:border-border'
                    )}
                  >
                    <div className="flex items-start justify-between gap-1 mb-1">
                      <p className="font-semibold text-foreground truncate max-w-[170px]">
                        {email.subject || 'No Subject'}
                      </p>
                      {renderRiskBadge(email.risk_score)}
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-muted-foreground font-mono mt-1">
                      <span className="truncate max-w-[120px]">{email.sender}</span>
                      <span>
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

        {/* Center Column: Interactive Map */}
        <div className="panel lg:col-span-6 flex flex-col h-[calc(100vh-210px)] min-h-[580px] overflow-hidden relative p-0">
          {/* Active Email Banner */}
          {currentEmail && (
            <div className="p-2.5 border-b border-border/50 bg-surface/60 flex items-center justify-between gap-2 shrink-0 z-10">
              <div className="flex items-center gap-2 truncate">
                <Radio className="size-3 text-primary animate-pulse shrink-0" />
                <span className="text-xs font-semibold truncate text-foreground">{currentEmail.subject}</span>
              </div>
              <span className="label-mono text-[9px] bg-surface px-2 py-0.5 rounded border border-border shrink-0">
                {hops.length} GEO HOPS
              </span>
            </div>
          )}

          {/* Map Canvas */}
          <div className="flex-1 w-full h-full relative">
            {isAnalysisLoading ? (
              <div className="absolute inset-0 flex flex-col items-center justify-center bg-background/80 z-20">
                <Loader2 className="size-8 animate-spin text-primary mb-2" />
                <span className="label-mono text-[10px]">RESOLVING RELAY COORDINATES...</span>
              </div>
            ) : hops.length === 0 ? (
              <div className="absolute inset-0 flex flex-col items-center justify-center p-8 text-center text-muted-foreground">
                <Globe className="size-10 opacity-30 mb-3 text-primary" />
                <h3 className="text-sm font-semibold text-foreground">No Geo Hops Detected</h3>
                <p className="text-xs text-muted-foreground max-w-xs mt-1">
                  Select an email on the left or upload an email file with public received headers to plot its geographic path.
                </p>
              </div>
            ) : (
              <Map
                mapStyle={MAP_STYLE}
                initialViewState={{
                  longitude: hops.length > 0 ? hops[0].longitude : 0,
                  latitude: hops.length > 0 ? hops[0].latitude : 20,
                  zoom: 1.8,
                }}
                style={{ width: '100%', height: '100%' }}
              >
                <NavigationControl position="top-right" />

                {/* Trajectory Flight Path */}
                <Source type="geojson" data={geojsonLine} id="trace-path-source">
                  <Layer
                    type="line"
                    id="trace-path-layer"
                    paint={{
                      'line-color': '#00e5ff',
                      'line-width': 2.5,
                      'line-opacity': 0.8,
                      'line-dasharray': [2, 1],
                    }}
                    layout={{
                      'line-join': 'round',
                      'line-cap': 'round',
                    }}
                  />
                </Source>

                {/* Interactive Markers */}
                {hops.map((hop, idx) => {
                  const color = getMarkerColor(hop.infrastructureType);
                  const isSelected = selectedHop?.index === hop.index;

                  return (
                    <Marker
                      key={idx}
                      latitude={hop.latitude}
                      longitude={hop.longitude}
                      anchor="center"
                      onClick={(e) => {
                        e.originalEvent.stopPropagation();
                        setSelectedHop(hop);
                      }}
                    >
                      <div
                        className="group relative flex items-center justify-center cursor-pointer transition-transform hover:scale-125"
                        style={{ width: '28px', height: '28px' }}
                      >
                        <div
                          className={cn(
                            'size-6 rounded-full flex items-center justify-center font-mono text-[10px] font-bold text-black shadow-lg border-2 border-background',
                            isSelected ? 'ring-4 ring-primary/60 scale-110' : ''
                          )}
                          style={{
                            backgroundColor: color,
                          }}
                        >
                          #{idx + 1}
                        </div>
                      </div>
                    </Marker>
                  );
                })}

                {/* Hop Detail Popup */}
                {selectedHop && (
                  <Popup
                    latitude={selectedHop.latitude}
                    longitude={selectedHop.longitude}
                    anchor="bottom"
                    onClose={() => setSelectedHop(null)}
                    closeButton={true}
                    className="z-50"
                  >
                    <div className="min-w-[200px] p-2.5 text-foreground space-y-1.5 panel shadow-2xl">
                      <div className="flex items-center justify-between border-b border-border/60 pb-1">
                        <span className="label-mono font-bold">Hop #{selectedHop.index + 1}</span>
                        <span
                          className="font-mono text-[9px] px-1 py-0.5 rounded border uppercase"
                          style={{ borderColor: getMarkerColor(selectedHop.infrastructureType), color: getMarkerColor(selectedHop.infrastructureType) }}
                        >
                          {selectedHop.infrastructureType}
                        </span>
                      </div>
                      <div className="font-mono text-xs">
                        <span className="text-muted-foreground">IP: </span>
                        <span className="font-semibold text-primary">{selectedHop.ip}</span>
                      </div>
                      <div className="text-[11px]">
                        <span className="text-muted-foreground">Location: </span>
                        <span>
                          {selectedHop.city}, {selectedHop.country} ({selectedHop.country_code})
                        </span>
                      </div>
                      <div className="text-[11px] truncate">
                        <span className="text-muted-foreground">Org: </span>
                        <span>{selectedHop.org || selectedHop.isp}</span>
                      </div>
                      {selectedHop.delay !== undefined && (
                        <div className="text-[11px] font-mono">
                          <span className="text-muted-foreground">Delay: </span>
                          <span>{selectedHop.delay.toFixed(1)}s</span>
                        </div>
                      )}
                    </div>
                  </Popup>
                )}
              </Map>
            )}
          </div>
        </div>

        {/* Right Column: Hop Path Breakdown */}
        <div className="panel lg:col-span-3 flex flex-col h-[calc(100vh-210px)] min-h-[580px] p-3 space-y-2.5">
          <div className="flex items-center justify-between border-b border-border/50 pb-2">
            <span className="label-mono font-semibold flex items-center gap-1.5">
              <Server className="size-3.5 text-primary" />
              Routing Chain ({hops.length})
            </span>
          </div>

          <div className="flex-1 overflow-y-auto space-y-2 pr-1">
            {hops.length === 0 ? (
              <p className="text-xs text-muted-foreground text-center py-8">No relay route hops available.</p>
            ) : (
              hops.map((hop, idx) => {
                const isSelected = selectedHop?.index === hop.index;
                const isOrigin = idx === 0;
                const isDestination = idx === hops.length - 1;

                return (
                  <div
                    key={idx}
                    onClick={() => setSelectedHop(hop)}
                    className={cn(
                      'p-2.5 rounded border transition-all cursor-pointer text-xs space-y-1',
                      isSelected
                        ? 'border-primary/80 bg-primary/10 shadow-glow'
                        : 'border-border/50 bg-surface/40 hover:bg-surface hover:border-border'
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <span
                          className="size-2 rounded-full shrink-0"
                          style={{ backgroundColor: getMarkerColor(hop.infrastructureType) }}
                        />
                        <span className="font-bold font-mono text-[11px]">Hop #{idx + 1}</span>
                      </div>
                      <span className="label-mono text-[9px] uppercase px-1.5 py-0.5 rounded bg-surface border border-border">
                        {isOrigin ? 'Origin' : isDestination ? 'Destination' : 'Relay'}
                      </span>
                    </div>

                    <div className="font-mono text-xs text-primary font-semibold truncate">{hop.ip}</div>

                    <div className="text-[11px] text-muted-foreground flex items-center gap-1 truncate">
                      <Globe className="size-3 shrink-0" />
                      <span className="truncate">
                        {hop.city !== 'Unknown' ? `${hop.city}, ` : ''}
                        {hop.country}
                      </span>
                    </div>

                    <div className="text-[10px] text-muted-foreground flex items-center justify-between font-mono pt-0.5">
                      <span className="truncate max-w-[130px]">{hop.isp || hop.org}</span>
                      {hop.delay !== undefined && (
                        <span className="flex items-center gap-0.5">
                          <Clock className="size-2.5" />
                          {hop.delay.toFixed(1)}s
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