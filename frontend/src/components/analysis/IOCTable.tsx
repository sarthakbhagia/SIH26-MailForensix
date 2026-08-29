import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Globe,
  Server,
  Hash,
  Link as LinkIcon,
  ShieldAlert,
  ShieldCheck,
  Check,
  Copy,
  Search,
  ExternalLink,
  Share2,
  FolderPlus,
  Shield,
  CheckSquare,
  Square,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { getSeverityTokens, defangUrl, defangIp } from '@/lib/severity';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

export interface IOCItem {
  type: 'URL' | 'IP' | 'Domain' | 'Hash' | 'url' | 'ip' | 'domain' | 'hash' | string;
  value: string;
  risk_score: number;
  reason?: string;
  source?: string;
  timestamp?: string;
  emailId?: string;
}

export interface IOCTableProps {
  iocs: IOCItem[];
  emailId?: string;
  onRowClick?: (value: string, type: string) => void;
}

export function IOCTable({ iocs = [], emailId, onRowClick }: IOCTableProps) {
  const navigate = useNavigate();

  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('ALL');
  const [filterSeverity, setFilterSeverity] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM_LOW'>('ALL');
  const [defangEnabled, setDefangEnabled] = useState<boolean>(true);
  const [copiedValue, setCopiedValue] = useState<string | null>(null);
  const [copiedBulk, setCopiedBulk] = useState(false);
  const [selectedValues, setSelectedValues] = useState<Set<string>>(new Set());
  const [expandedIoc, setExpandedIoc] = useState<string | null>(null);

  // Normalize IOC types
  const normalizedIocs: IOCItem[] = useMemo(() => {
    return iocs.map((ioc) => {
      const rawType = String(ioc.type || '').toUpperCase().trim();
      let type = 'URL';
      if (rawType === 'IP' || rawType.includes('IP')) type = 'IP';
      else if (rawType === 'DOMAIN' || rawType.includes('DOMAIN')) type = 'DOMAIN';
      else if (rawType === 'HASH' || rawType.includes('SHA') || rawType.includes('MD5')) type = 'HASH';

      return {
        ...ioc,
        type,
        emailId: ioc.emailId || emailId,
      };
    });
  }, [iocs, emailId]);

  // Counts by type
  const countByType = useMemo(() => {
    return {
      ALL: normalizedIocs.length,
      URL: normalizedIocs.filter((i) => i.type === 'URL').length,
      IP: normalizedIocs.filter((i) => i.type === 'IP').length,
      DOMAIN: normalizedIocs.filter((i) => i.type === 'DOMAIN').length,
      HASH: normalizedIocs.filter((i) => i.type === 'HASH').length,
    };
  }, [normalizedIocs]);

  // Filtered IOCs
  const filteredIocs = useMemo(() => {
    return normalizedIocs.filter((ioc) => {
      // Type match
      if (filterType !== 'ALL' && ioc.type !== filterType) return false;

      // Severity match
      if (filterSeverity === 'CRITICAL' && ioc.risk_score < 75) return false;
      if (filterSeverity === 'HIGH' && (ioc.risk_score < 50 || ioc.risk_score >= 75)) return false;
      if (filterSeverity === 'MEDIUM_LOW' && ioc.risk_score >= 50) return false;

      // Search match
      if (searchTerm.trim()) {
        const query = searchTerm.toLowerCase();
        const valMatch = ioc.value.toLowerCase().includes(query);
        const reasonMatch = ioc.reason?.toLowerCase().includes(query);
        const sourceMatch = ioc.source?.toLowerCase().includes(query);
        const typeMatch = ioc.type.toLowerCase().includes(query);
        return valMatch || reasonMatch || sourceMatch || typeMatch;
      }

      return true;
    });
  }, [normalizedIocs, filterType, filterSeverity, searchTerm]);

  // Defanging formatter
  const formatIndicator = (val: string, type: string) => {
    if (!defangEnabled) return val;
    if (type === 'URL') return defangUrl(val);
    if (type === 'IP') return defangIp(val);
    if (type === 'DOMAIN') return val.replace(/\./g, '[.]');
    return val;
  };

  const handleCopy = (value: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    navigator.clipboard.writeText(value);
    setCopiedValue(value);
    setTimeout(() => setCopiedValue(null), 1800);
  };

  const handleCopyBulk = () => {
    const targets = selectedValues.size > 0
      ? filteredIocs.filter((i) => selectedValues.has(i.value))
      : filteredIocs;
    const text = targets.map((i) => formatIndicator(i.value, i.type)).join('\n');
    navigator.clipboard.writeText(text);
    setCopiedBulk(true);
    setTimeout(() => setCopiedBulk(false), 2000);
  };

  const toggleSelectAll = () => {
    if (selectedValues.size === filteredIocs.length && filteredIocs.length > 0) {
      setSelectedValues(new Set());
    } else {
      setSelectedValues(new Set(filteredIocs.map((i) => i.value)));
    }
  };

  const toggleSelectRow = (val: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const next = new Set(selectedValues);
    if (next.has(val)) next.delete(val);
    else next.add(val);
    setSelectedValues(next);
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'IP':
        return <Server className="size-3.5 text-primary" />;
      case 'DOMAIN':
        return <Globe className="size-3.5 text-accent" />;
      case 'HASH':
        return <Hash className="size-3.5 text-foreground/70" />;
      case 'URL':
      default:
        return <LinkIcon className="size-3.5 text-sky-400" />;
    }
  };

  const getExternalLookupUrl = (ioc: IOCItem) => {
    const rawVal = encodeURIComponent(ioc.value.trim());
    if (ioc.type === 'IP') {
      return `https://www.virustotal.com/gui/ip-address/${rawVal}`;
    }
    if (ioc.type === 'DOMAIN') {
      return `https://www.virustotal.com/gui/domain/${rawVal}`;
    }
    if (ioc.type === 'HASH') {
      return `https://www.virustotal.com/gui/file/${rawVal}`;
    }
    return `https://www.virustotal.com/gui/search/${rawVal}`;
  };

  return (
    <div className="panel p-4 sm:p-5 space-y-4">
      {/* 1. Header Toolbar & Threat Triage Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-border/50 pb-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="size-4 text-critical" />
          <h3 className="text-sm font-semibold tracking-tight text-foreground">
            Extracted Indicators of Compromise ({normalizedIocs.length})
          </h3>
        </div>

        {/* Safety & Bulk Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Defang Toggle Switch */}
          <button
            onClick={() => setDefangEnabled(!defangEnabled)}
            className={cn(
              'flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-mono transition-colors select-none',
              defangEnabled
                ? 'bg-clean/10 border-clean/30 text-clean font-semibold'
                : 'bg-critical/10 border-critical/30 text-critical font-semibold'
            )}
            title="Toggle defanging for active copy protection"
          >
            <Shield className="size-3" />
            <span>{defangEnabled ? 'DEFANGED (SAFE)' : 'RAW (ACTIVE)'}</span>
          </button>

          {/* Copy Filtered / Selected Action */}
          {filteredIocs.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleCopyBulk}
              className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border hover:bg-surface-2"
              title="Copy all visible defanged indicators to clipboard"
            >
              {copiedBulk ? <Check className="size-3 text-clean" /> : <Copy className="size-3" />}
              <span>{copiedBulk ? 'Copied' : selectedValues.size > 0 ? `Copy Selected (${selectedValues.size})` : `Copy All (${filteredIocs.length})`}</span>
            </Button>
          )}

          {/* Pivot to Attribution Threat Graph */}
          {emailId && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate(`/graph?emailId=${emailId}`)}
              className="h-7 px-2.5 text-xs font-mono gap-1.5 border-border hover:bg-surface-2"
              title="Inspect IOC correlations in Attribution Threat Graph"
            >
              <Share2 className="size-3 text-primary" />
              <span>Threat Graph</span>
            </Button>
          )}
        </div>
      </div>

      {/* 2. Compact Search & Filter Matrix */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-2.5 pt-0.5">
        {/* Search Input */}
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-2.5 top-2 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search indicator, hash, detection reason, or source..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="h-8 pl-8 text-xs font-mono bg-background border-border"
          />
        </div>

        {/* Type Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
          {(['ALL', 'URL', 'IP', 'DOMAIN', 'HASH'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={cn(
                'px-2.5 py-1 rounded text-[10px] uppercase font-semibold transition-all border',
                filterType === t
                  ? 'bg-primary text-primary-foreground font-bold shadow-sm'
                  : 'bg-surface-2 text-muted-foreground border-border hover:bg-surface-3 hover:text-foreground'
              )}
            >
              {t} <span className="opacity-70 text-[9px]">({countByType[t]})</span>
            </button>
          ))}

          {/* Severity Filter Dropdown */}
          <div className="flex items-center rounded border border-border bg-surface-2 p-0.5 ml-1">
            <button
              onClick={() => setFilterSeverity('ALL')}
              className={cn(
                'px-2 py-0.5 rounded text-[10px] font-bold uppercase transition-colors',
                filterSeverity === 'ALL' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'
              )}
            >
              All Sev
            </button>
            <button
              onClick={() => setFilterSeverity('CRITICAL')}
              className={cn(
                'px-2 py-0.5 rounded text-[10px] font-bold uppercase transition-colors',
                filterSeverity === 'CRITICAL' ? 'bg-critical text-critical-foreground' : 'text-critical hover:bg-critical/10'
              )}
            >
              Crit
            </button>
            <button
              onClick={() => setFilterSeverity('HIGH')}
              className={cn(
                'px-2 py-0.5 rounded text-[10px] font-bold uppercase transition-colors',
                filterSeverity === 'HIGH' ? 'bg-high text-high-foreground' : 'text-high hover:bg-high/10'
              )}
            >
              High
            </button>
          </div>
        </div>
      </div>

      {/* 3. Forensic Evidence Ledger Table */}
      {filteredIocs.length === 0 ? (
        <div className="p-12 text-center text-muted-foreground flex flex-col items-center justify-center rounded border border-border bg-surface-2/40">
          <ShieldCheck className="size-8 text-clean mb-2 opacity-60" />
          <p className="text-xs font-semibold text-foreground">No Indicators Match Filter Criteria</p>
          <p className="text-[11px] text-muted-foreground mt-0.5 max-w-sm">
            {searchTerm ? `No IOC records matched "${searchTerm}".` : 'No indicators extracted under current category and severity settings.'}
          </p>
          {(searchTerm || filterType !== 'ALL' || filterSeverity !== 'ALL') && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setSearchTerm('');
                setFilterType('ALL');
                setFilterSeverity('ALL');
              }}
              className="mt-3 h-7 text-xs font-mono border-border"
            >
              Reset Filters
            </Button>
          )}
        </div>
      ) : (
        <div className="overflow-hidden rounded border border-border bg-background">
          {/* Desktop Table Header */}
          <div className="hidden md:grid md:grid-cols-12 gap-3 px-4 py-2.5 border-b border-border bg-surface-2/80 text-[10px] font-mono text-muted-foreground font-bold uppercase select-none">
            <div className="col-span-1 flex items-center gap-2">
              <button
                onClick={toggleSelectAll}
                className="text-muted-foreground hover:text-foreground transition-colors"
                title="Select / Deselect all"
              >
                {selectedValues.size === filteredIocs.length && filteredIocs.length > 0 ? (
                  <CheckSquare className="size-3.5 text-primary" />
                ) : (
                  <Square className="size-3.5" />
                )}
              </button>
              <span>#</span>
            </div>
            <div className="col-span-1">Type</div>
            <div className="col-span-5">Indicator ({defangEnabled ? 'Defanged' : 'Raw'})</div>
            <div className="col-span-2">Severity / Risk</div>
            <div className="col-span-3 text-right">Actions</div>
          </div>

          {/* Table Rows / Mobile Stacked Cards */}
          <div className="divide-y divide-border/60">
            {filteredIocs.map((ioc, idx) => {
              const tokens = getSeverityTokens(ioc.risk_score);
              const formattedVal = formatIndicator(ioc.value, ioc.type);
              const isSelected = selectedValues.has(ioc.value);
              const isExpanded = expandedIoc === ioc.value;

              return (
                <div
                  key={`${ioc.type}-${ioc.value}-${idx}`}
                  className={cn(
                    'transition-colors text-xs font-mono',
                    isSelected ? 'bg-primary/5' : 'hover:bg-surface-2/50'
                  )}
                >
                  {/* Desktop Grid Layout */}
                  <div
                    onClick={() => {
                      if (onRowClick) onRowClick(ioc.value, ioc.type);
                    }}
                    className={cn(
                      'hidden md:grid md:grid-cols-12 gap-3 px-4 py-3 items-center',
                      onRowClick && 'cursor-pointer'
                    )}
                  >
                    {/* Checkbox & Index */}
                    <div className="col-span-1 flex items-center gap-2">
                      <button
                        onClick={(e) => toggleSelectRow(ioc.value, e)}
                        className="text-muted-foreground hover:text-foreground transition-colors shrink-0"
                      >
                        {isSelected ? (
                          <CheckSquare className="size-3.5 text-primary" />
                        ) : (
                          <Square className="size-3.5" />
                        )}
                      </button>
                      <span className="text-muted-foreground text-[10px] tabular-nums">{idx + 1}</span>
                    </div>

                    {/* Type Badge */}
                    <div className="col-span-1 flex items-center gap-1.5">
                      {getTypeIcon(ioc.type)}
                      <span className="label-mono text-[9px] font-bold">{ioc.type}</span>
                    </div>

                    {/* Indicator Value & Reason */}
                    <div className="col-span-5 min-w-0">
                      <div className="flex items-center gap-2">
                        <span
                          className="font-bold text-foreground truncate select-all block text-xs"
                          title={ioc.value}
                        >
                          {formattedVal}
                        </span>
                      </div>
                      {ioc.reason && (
                        <p className="text-[11px] text-muted-foreground/80 truncate mt-0.5" title={ioc.reason}>
                          {ioc.reason}
                        </p>
                      )}
                    </div>

                    {/* Risk & Severity Pill */}
                    <div className="col-span-2 flex items-center gap-2">
                      <span className={cn('px-2 py-0.5 rounded font-mono text-[10px] font-bold border tabular-nums', tokens.badgeClass)}>
                        RISK {ioc.risk_score}
                      </span>
                      {ioc.source && (
                        <span className="text-[9px] text-muted-foreground truncate hidden lg:inline">
                          via {ioc.source}
                        </span>
                      )}
                    </div>

                    {/* Actions Toolbar */}
                    <div className="col-span-3 flex items-center justify-end gap-1.5">
                      <button
                        onClick={(e) => handleCopy(ioc.value, e)}
                        className="p-1 rounded border border-border bg-surface hover:bg-surface-2 hover:text-foreground text-muted-foreground transition-colors"
                        title="Copy raw value"
                      >
                        {copiedValue === ioc.value ? (
                          <Check className="size-3 text-clean" />
                        ) : (
                          <Copy className="size-3" />
                        )}
                      </button>

                      <a
                        href={getExternalLookupUrl(ioc)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-1 rounded border border-border bg-surface hover:bg-surface-2 hover:text-foreground text-muted-foreground transition-colors"
                        title="External VirusTotal threat lookup"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <ExternalLink className="size-3" />
                      </a>

                      <button
                        onClick={() => navigate(`/cases?new=true&title=${encodeURIComponent(`Investigate IOC: ${ioc.value}`)}`)}
                        className="p-1 rounded border border-border bg-surface hover:bg-surface-2 hover:text-foreground text-muted-foreground transition-colors"
                        title="Create case from IOC"
                      >
                        <FolderPlus className="size-3" />
                      </button>

                      <button
                        onClick={() => setExpandedIoc(isExpanded ? null : ioc.value)}
                        className="p-1 rounded border border-border bg-surface hover:bg-surface-2 hover:text-foreground text-muted-foreground transition-colors"
                        title="Expand details"
                      >
                        {isExpanded ? <ChevronDown className="size-3" /> : <ChevronRight className="size-3" />}
                      </button>
                    </div>
                  </div>

                  {/* Mobile Stacked Card Layout */}
                  <div className="md:hidden p-3.5 space-y-2.5">
                    <div className="flex items-center justify-between gap-2 border-b border-border/40 pb-2">
                      <div className="flex items-center gap-2">
                        {getTypeIcon(ioc.type)}
                        <span className="label-mono text-[9px] font-bold">{ioc.type}</span>
                      </div>
                      <span className={cn('px-2 py-0.5 rounded font-mono text-[10px] font-bold border tabular-nums', tokens.badgeClass)}>
                        RISK {ioc.risk_score}
                      </span>
                    </div>

                    <p className="font-bold text-foreground break-all select-all text-xs">
                      {formattedVal}
                    </p>

                    {ioc.reason && (
                      <p className="text-[11px] text-muted-foreground">{ioc.reason}</p>
                    )}

                    <div className="flex items-center justify-between pt-2 border-t border-border/30">
                      <span className="text-[10px] text-muted-foreground font-mono">
                        {ioc.source ? `Source: ${ioc.source}` : 'Pipeline Forensics'}
                      </span>

                      <div className="flex items-center gap-1.5">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={(e) => handleCopy(ioc.value, e)}
                          className="h-6 px-2 text-[10px] font-mono border-border"
                        >
                          {copiedValue === ioc.value ? <Check className="size-3 text-clean" /> : <Copy className="size-3" />}
                          <span className="ml-1">{copiedValue === ioc.value ? 'Copied' : 'Copy'}</span>
                        </Button>

                        <a
                          href={getExternalLookupUrl(ioc)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="p-1 rounded border border-border bg-surface hover:bg-surface-2 text-muted-foreground"
                          title="VirusTotal"
                        >
                          <ExternalLink className="size-3" />
                        </a>
                      </div>
                    </div>
                  </div>

                  {/* Expanded Detail Drawer */}
                  {isExpanded && (
                    <div className="p-4 bg-surface-2/80 border-t border-border/60 space-y-3">
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                        <div className="p-2.5 rounded bg-surface border border-border space-y-1">
                          <span className="label-mono text-[9px]">RAW VALUE</span>
                          <p className="font-bold text-foreground break-all select-all">{ioc.value}</p>
                        </div>
                        <div className="p-2.5 rounded bg-surface border border-border space-y-1">
                          <span className="label-mono text-[9px]">DETECTION CONTEXT</span>
                          <p className="text-muted-foreground">{ioc.reason || 'Detected via heuristic pipeline analysis'}</p>
                        </div>
                        <div className="p-2.5 rounded bg-surface border border-border space-y-1">
                          <span className="label-mono text-[9px]">THREAT SOURCE</span>
                          <p className="text-primary font-semibold">{ioc.source || 'Automated Threat Intelligence'}</p>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-2 pt-1">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => navigate(`/cases?new=true&title=${encodeURIComponent(`Investigate IOC: ${ioc.value}`)}`)}
                          className="h-7 text-xs font-mono gap-1.5 border-border"
                        >
                          <FolderPlus className="size-3 text-muted-foreground" />
                          <span>Attach to Case</span>
                        </Button>

                        <a
                          href={getExternalLookupUrl(ioc)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-border bg-surface hover:bg-surface-2 text-xs font-mono text-foreground"
                        >
                          <span>VirusTotal Dossier</span>
                          <ExternalLink className="size-3 text-primary" />
                        </a>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

export default IOCTable;
