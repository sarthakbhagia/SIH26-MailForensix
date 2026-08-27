import React, { useState } from 'react';
import { cn } from '@/lib/utils';
import { Globe, Server, Hash, Link as LinkIcon, ShieldAlert, Check, Copy } from 'lucide-react';

export interface IOCItem {
  type: 'URL' | 'IP' | 'Domain' | 'Hash' | 'url' | 'ip' | 'domain' | 'hash' | string;
  value: string;
  risk_score: number;
  reason?: string;
  source?: string;
}

export interface IOCTableProps {
  iocs: IOCItem[];
  onRowClick?: (value: string, type: string) => void;
}

export function IOCTable({ iocs, onRowClick }: IOCTableProps) {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  const handleCopy = (value: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(value);
    setCopiedValue(value);
    setTimeout(() => setCopiedValue(null), 1800);
  };

  const normalizedIocs = iocs.map((ioc) => {
    const rawType = String(ioc.type || '').toUpperCase();
    let type: 'URL' | 'IP' | 'DOMAIN' | 'HASH' = 'URL';
    if (rawType === 'IP') type = 'IP';
    else if (rawType === 'DOMAIN') type = 'DOMAIN';
    else if (rawType === 'HASH') type = 'HASH';

    return {
      ...ioc,
      type,
    };
  });

  const filteredIocs = filterType === 'ALL'
    ? normalizedIocs
    : normalizedIocs.filter((ioc) => ioc.type === filterType);

  const getRiskStyle = (score: number) => {
    if (score >= 75) return { color: 'var(--critical)', bg: 'bg-critical/15', border: 'border-critical/40' };
    if (score >= 50) return { color: 'var(--high)', bg: 'bg-high/15', border: 'border-high/40' };
    if (score >= 25) return { color: 'var(--medium)', bg: 'bg-medium/15', border: 'border-medium/40' };
    return { color: 'var(--clean)', bg: 'bg-clean/15', border: 'border-clean/40' };
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'IP':
        return <Server className="size-3.5 text-primary" />;
      case 'DOMAIN':
        return <Globe className="size-3.5 text-accent" />;
      case 'HASH':
        return <Hash className="size-3.5 text-muted-foreground" />;
      case 'URL':
      default:
        return <LinkIcon className="size-3.5 text-sky-400" />;
    }
  };

  const countByType = {
    ALL: normalizedIocs.length,
    URL: normalizedIocs.filter((i) => i.type === 'URL').length,
    IP: normalizedIocs.filter((i) => i.type === 'IP').length,
    DOMAIN: normalizedIocs.filter((i) => i.type === 'DOMAIN').length,
    HASH: normalizedIocs.filter((i) => i.type === 'HASH').length,
  };

  return (
    <div className="space-y-3.5">
      {/* Top Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2.5">
        <div className="flex flex-wrap items-center gap-1.5">
          {(['ALL', 'URL', 'IP', 'DOMAIN', 'HASH'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={cn(
                'px-2.5 py-0.5 rounded font-mono text-[10px] font-semibold uppercase transition-all border',
                filterType === t
                  ? 'bg-primary/10 text-primary border-primary/40 font-bold shadow-sm'
                  : 'bg-surface text-muted-foreground border-border/50 hover:bg-surface-2 hover:text-foreground'
              )}
            >
              {t} <span className="opacity-70 text-[9px]">({countByType[t]})</span>
            </button>
          ))}
        </div>

        <span className="label-mono text-[10px]">
          {filteredIocs.length} {filteredIocs.length === 1 ? 'indicator' : 'indicators'} filtered
        </span>
      </div>

      {/* IOC Rows List */}
      {filteredIocs.length === 0 ? (
        <div className="p-8 text-center text-muted-foreground">
          <ShieldAlert className="size-7 mx-auto opacity-40 mb-2" />
          <p className="text-xs font-medium text-foreground">No {filterType !== 'ALL' ? filterType : ''} IOCs detected</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filteredIocs.map((ioc, idx) => {
            const risk = getRiskStyle(ioc.risk_score);
            return (
              <div
                key={idx}
                onClick={() => onRowClick?.(ioc.value, ioc.type)}
                className="panel group flex flex-col md:flex-row md:items-center justify-between gap-3 p-3.5 hover:border-border/80 transition-all cursor-pointer"
              >
                {/* Left: Type Badge & Monospace Value */}
                <div className="flex items-start md:items-center gap-3 min-w-0 flex-1">
                  <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-surface border border-border/80 font-mono text-[10px] font-semibold text-foreground shrink-0">
                    {getTypeIcon(ioc.type)}
                    <span>{ioc.type}</span>
                  </div>

                  <div className="min-w-0 flex-1">
                    <p className="font-mono text-xs text-foreground font-medium break-all group-hover:text-primary transition-colors">
                      {ioc.value}
                    </p>
                    {ioc.reason && (
                      <p className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed truncate">
                        {ioc.reason}
                        {ioc.source && <span> · Source: {ioc.source}</span>}
                      </p>
                    )}
                  </div>
                </div>

                {/* Right: Risk Badge & Copy Button */}
                <div className="flex items-center gap-2.5 shrink-0 self-end md:self-center">
                  <span
                    className={cn(
                      'px-2.5 py-0.5 rounded-full font-mono text-[10px] font-bold uppercase border',
                      risk.bg,
                      risk.border
                    )}
                    style={{ color: risk.color }}
                  >
                    Risk {ioc.risk_score}
                  </span>

                  <button
                    onClick={(e) => handleCopy(ioc.value, e)}
                    className="p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
                    title="Copy IOC value"
                  >
                    {copiedValue === ioc.value ? (
                      <Check className="size-3.5 text-clean" />
                    ) : (
                      <Copy className="size-3.5" />
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default IOCTable;