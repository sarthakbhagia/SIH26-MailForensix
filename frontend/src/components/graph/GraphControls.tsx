import React from 'react';
import { Search, RotateCcw, Download, Filter, ShieldAlert, Layers } from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Badge } from '../ui/badge';
import { GraphFilters, GraphNodeType, Campaign } from '../../types/graph';

interface GraphControlsProps {
  filters: GraphFilters;
  onFilterChange: (filters: GraphFilters) => void;
  campaigns: Campaign[];
  onExportJson?: () => void;
  onReset?: () => void;
}

const TYPE_CONFIG: Array<{ type: GraphNodeType; label: string; color: string }> = [
  { type: 'email', label: 'Emails', color: 'bg-blue-500/20 text-blue-400 border-blue-500/40' },
  { type: 'domain', label: 'Domains', color: 'bg-purple-500/20 text-purple-400 border-purple-500/40' },
  { type: 'ip', label: 'IPs', color: 'bg-red-500/20 text-red-400 border-red-500/40' },
  { type: 'asn', label: 'ASNs', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40' },
  { type: 'registrar', label: 'Registrars', color: 'bg-amber-500/20 text-amber-400 border-amber-500/40' },
  { type: 'campaign', label: 'Campaigns', color: 'bg-pink-500/20 text-pink-400 border-pink-500/40' },
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
    <div className="bg-card border border-border rounded-lg p-3 shadow-sm space-y-3 mb-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Search Bar */}
        <div className="relative flex-1 min-w-[240px] max-w-md">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search nodes by IP, domain, subject..."
            value={filters.searchQuery}
            onChange={handleSearch}
            className="pl-9 h-9 text-sm"
          />
        </div>

        {/* Campaign Filter Dropdown */}
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-muted-foreground" />
          <select
            value={filters.selectedCampaignId || 'ALL'}
            onChange={handleCampaignChange}
            className="h-9 px-3 rounded-md bg-background border border-input text-xs font-medium focus:outline-none focus:ring-1 focus:ring-ring"
          >
            <option value="ALL">All Campaigns ({campaigns.length})</option>
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
            <Button variant="outline" size="sm" onClick={onExportJson} className="h-9 gap-1.5 text-xs">
              <Download className="h-3.5 w-3.5" />
              Export JSON
            </Button>
          )}
          {onReset && (
            <Button variant="ghost" size="sm" onClick={onReset} className="h-9 gap-1.5 text-xs text-muted-foreground hover:text-foreground">
              <RotateCcw className="h-3.5 w-3.5" />
              Reset
            </Button>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-border/50 text-xs">
        {/* Node Type Filters */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-muted-foreground mr-1 flex items-center gap-1 font-medium">
            <Filter className="h-3.5 w-3.5" /> Types:
          </span>
          {TYPE_CONFIG.map(({ type, label, color }) => {
            const active = filters.nodeTypes[type];
            return (
              <button
                key={type}
                type="button"
                onClick={() => toggleType(type)}
                className={`px-2.5 py-1 rounded-md border text-xs font-medium transition-all ${
                  active ? color : 'bg-muted/30 text-muted-foreground border-transparent opacity-60'
                }`}
              >
                {label}
              </button>
            );
          })}
        </div>

        {/* Risk Threshold Slider */}
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="h-3.5 w-3.5 text-amber-500" />
          <span className="text-muted-foreground">Min Risk:</span>
          <input
            type="range"
            min="0"
            max="100"
            step="5"
            value={filters.minRiskScore}
            onChange={handleRiskChange}
            className="w-24 h-1.5 bg-secondary rounded-lg appearance-none cursor-pointer accent-primary"
          />
          <Badge variant={filters.minRiskScore > 70 ? 'destructive' : filters.minRiskScore > 40 ? 'outline' : 'secondary'} className="px-1.5 py-0 text-[10px]">
            {filters.minRiskScore}+
          </Badge>
        </div>
      </div>
    </div>
  );
}
