import { useState } from 'react';
import { cn } from '@/lib/utils';
import { Search, Copy, Check } from 'lucide-react';
import { Input } from '@/components/ui/input';

export interface HeaderInspectorProps {
  headers: Record<string, string | string[]>;
}

export function HeaderInspector({ headers }: HeaderInspectorProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [copiedAll, setCopiedAll] = useState(false);
  const [viewMode, setViewMode] = useState<'grid' | 'raw'>('grid');

  const headerEntries = Object.entries(headers || {}).map(([k, v]) => ({
    key: k,
    value: Array.isArray(v) ? v.join('\n') : String(v || ''),
  }));

  const filteredEntries = searchTerm.trim()
    ? headerEntries.filter(
        (h) =>
          h.key.toLowerCase().includes(searchTerm.toLowerCase()) ||
          h.value.toLowerCase().includes(searchTerm.toLowerCase())
      )
    : headerEntries;

  const rawHeadersText = headerEntries.map((h) => `${h.key}: ${h.value}`).join('\n');

  const handleCopyValue = (key: string, val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const handleCopyAll = () => {
    navigator.clipboard.writeText(rawHeadersText);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 1800);
  };

  return (
    <div className="space-y-4">
      {/* Inspector Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/50 pb-3">
        <div className="flex items-center gap-2 flex-1 max-w-md">
          <div className="relative w-full">
            <Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
            <Input
              placeholder="Search RFC-822 header keys or values..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 h-8 text-xs font-mono bg-background/60 border-border"
            />
          </div>
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="text-xs text-muted-foreground hover:text-foreground px-2 py-1"
            >
              Clear
            </button>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <div className="flex items-center rounded border border-border bg-surface p-0.5">
            <button
              onClick={() => setViewMode('grid')}
              className={cn(
                'px-2.5 py-0.5 text-[10px] font-mono uppercase rounded transition-colors',
                viewMode === 'grid'
                  ? 'bg-primary text-primary-foreground font-bold shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              Inspector
            </button>
            <button
              onClick={() => setViewMode('raw')}
              className={cn(
                'px-2.5 py-0.5 text-[10px] font-mono uppercase rounded transition-colors',
                viewMode === 'raw'
                  ? 'bg-primary text-primary-foreground font-bold shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              Raw RFC-822
            </button>
          </div>

          <button
            onClick={handleCopyAll}
            className="flex items-center gap-1.5 px-3 py-1 text-xs font-mono rounded border border-border hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
            title="Copy all raw headers"
          >
            {copiedAll ? <Check className="size-3 text-clean" /> : <Copy className="size-3" />}
            <span>{copiedAll ? 'Copied' : 'Copy All'}</span>
          </button>
        </div>
      </div>

      {/* Main View */}
      {viewMode === 'grid' ? (
        <div className="panel divide-y divide-border/60 overflow-hidden">
          {filteredEntries.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground text-xs">
              No headers match filter query "{searchTerm}"
            </div>
          ) : (
            filteredEntries.map((h, idx) => (
              <div
                key={idx}
                className="grid md:grid-cols-[220px_1fr] gap-2 md:gap-4 p-3.5 hover:bg-surface-2/40 transition-colors group"
              >
                {/* Header Key */}
                <div className="flex items-start justify-between gap-1">
                  <span className="label-mono font-bold text-muted-foreground break-all select-all">
                    {h.key}
                  </span>
                </div>

                {/* Header Value & Quick Copy */}
                <div className="flex items-start justify-between gap-2 min-w-0">
                  <span className="font-mono text-xs text-foreground/90 break-all leading-relaxed whitespace-pre-wrap select-all">
                    {h.value || '—'}
                  </span>

                  <button
                    onClick={() => handleCopyValue(h.key, h.value)}
                    className="opacity-0 group-hover:opacity-100 p-1 rounded text-muted-foreground hover:text-foreground hover:bg-muted transition-opacity shrink-0"
                    title={`Copy ${h.key} value`}
                  >
                    {copiedKey === h.key ? (
                      <Check className="size-3 text-clean" />
                    ) : (
                      <Copy className="size-3" />
                    )}
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      ) : (
        <div className="panel relative p-4">
          <pre className="font-mono text-xs text-foreground leading-relaxed whitespace-pre-wrap max-h-[500px] overflow-y-auto overflow-x-auto select-all">
            {rawHeadersText || 'No headers available.'}
          </pre>
        </div>
      )}
    </div>
  );
}

export default HeaderInspector;

