import React from 'react';
import { Search, RotateCcw, Download, Filter, ShieldAlert, Layers } from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { GraphFilters, GraphNodeType, Campaign } from '../../types/graph';
import { cn } from '../../lib/utils';

interface GraphControlsProps {
  filters: GraphFilters;
  onFilterChange: (filters: GraphFilters) => void;
  campaigns: Campaign[];
  onExportJson?: () => void;
  onReset?: () => void;
}

const TYPE_CONFIG: Array<{ type: GraphNodeType; label: string; activeClass: string }> = [
  { type: 'email', label: 'EMAILS', activeClass: 'bg-primary/20 text-primary border-primary/40' },
  { type: 'domain', label: 'DOMAINS', activeClass: 'bg-purple-500/20 text-purple-400 border-purple-500/40' },
  { type: 'ip', label: 'IPS', activeClass: 'bg-critical/20 text-critical border-critical/40' },
  { type: 'asn', label: 'ASNS', activeClass: 'bg-clean/20 text-clean border-clean/40' },
  { type: 'registrar', label: 'REGISTRARS', activeClass: 'bg-amber-500/20 text-amber-400 border-amber-500/40' },
  { type: 'campaign', label: 'CAMPAIGNS', activeClass: 'bg-pink-500/20 text-pink-400 border-pink-500/40' },
];

export default function GraphControls({
  filters,
  onFilterChange,
  campaigns,
  onExportJson,
  onReset,
}: GraphControlsProps) {
  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    onFilterChange({ ...filters, searchQuery: e.target.value });
  };

  const toggleType = (type: GraphNodeType) => {
    onFilterChange({
      ...filters,
      nodeTypes: {
        ...filters.nodeTypes,
        [type]: !filters.nodeTypes[type],
      },
    });
  };

  const handleRiskChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onFilterChange({ ...filters, minRiskScore: Number(e.target.value) });
  };

  const handleCampaignChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value === 'ALL' ? null : e.target.value;
    onFilterChange({ ...filters, selectedCampaignId: val });
  };

  return (
    <div className="panel p-3.5 space-y-3 mb-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Search Bar */}
        <div className="relative flex-1 min-w-[240px] max-w-md">
          <Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search nodes by IP, domain, subject..."
            value={filters.searchQuery}
            onChange={handleSearch}
            className="pl-8 h-8 text-xs font-mono bg-background/50 border-border/60"
          />
        </div>

        {/* Campaign Filter Dropdown */}
        <div className="flex items-center gap-2">
          <Layers className="size-3.5 text-muted-foreground" />
          <select
            value={filters.selectedCampaignId || 'ALL'}
            onChange={handleCampaignChange}
            className="h-8 px-2.5 rounded bg-surface border border-border text-xs font-mono focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="ALL">ALL CAMPAIGNS ({campaigns.length})</option>
            {campaigns.map((camp) => (
              <option key={camp.campaign_id} value={camp.campaign_id}>
                {camp.attribution} ({camp.email_ids.length} emails)
              </option>
            ))}
          </select>
        </div>

        {/* Export & Reset Actions */}
        <div className="flex items-center gap-2">
          {onExportJson && (
            <Button variant="outline" size="sm" onClick={onExportJson} className="h-8 gap-1.5 text-xs font-mono border-border bg-surface hover:bg-muted">
              <Download className="size-3.5" />
              EXPORT JSON
            </Button>
          )}
          {onReset && (
            <Button variant="ghost" size="sm" onClick={onReset} className="h-8 gap-1.5 text-xs font-mono text-muted-foreground hover:text-foreground">
              <RotateCcw className="size-3.5" />
              RESET
            </Button>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 pt-2.5 border-t border-border/50 text-xs">
        {/* Node Type Filters */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="label-mono mr-1 flex items-center gap-1">
            <Filter className="size-3" /> TYPES:
          </span>
          {TYPE_CONFIG.map(({ type, label, activeClass }) => {
            const active = filters.nodeTypes[type];
            return (
              <button
                key={type}
                type="button"
                onClick={() => toggleType(type)}
                className={cn(
                  'px-2 py-0.5 rounded border font-mono text-[10px] font-semibold transition-all',
                  active ? activeClass : 'bg-surface/40 text-muted-foreground border-border/40 opacity-60'
                )}
              >
                {label}
              </button>
            );
          })}
        </div>

        {/* Risk Threshold Slider */}
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="size-3.5 text-medium" />
          <span className="label-mono text-[10px]">MIN RISK:</span>
          <input
            type="range"
            min="0"
            max="100"
            step="5"
            value={filters.minRiskScore}
            onChange={handleRiskChange}
            className="w-24 h-1.5 bg-surface-2 rounded appearance-none cursor-pointer accent-primary"
          />
          <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-surface border border-border">
            {filters.minRiskScore}+
          </span>
        </div>
      </div>
    </div>
  );
}

