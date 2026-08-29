import { useState } from 'react';
import { FileText, Copy, Check, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { defangUrl } from '@/lib/severity';

export interface EmailBodyViewerProps {
  bodyText?: string;
  bodyHtml?: string;
  urls?: string[];
}

export function EmailBodyViewer({ bodyText, bodyHtml, urls = [] }: EmailBodyViewerProps) {
  const [viewMode, setViewMode] = useState<'text' | 'html' | 'urls'>('text');
  const [copiedText, setCopiedText] = useState(false);
  const [searchFilter, setSearchFilter] = useState('');
  const [defangUrls, setDefangUrls] = useState(true);

  const handleCopy = () => {
    navigator.clipboard.writeText(viewMode === 'html' ? bodyHtml || '' : bodyText || '');
    setCopiedText(true);
    setTimeout(() => setCopiedText(false), 1800);
  };

  const filteredUrls = searchFilter.trim()
    ? urls.filter((u) => u.toLowerCase().includes(searchFilter.toLowerCase()))
    : urls;

  return (
    <div className="panel p-4 sm:p-5 space-y-4">
      {/* Header Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/50 pb-3">
        <div className="flex items-center gap-2">
          <FileText className="size-4 text-primary" />
          <h3 className="text-sm font-semibold tracking-tight text-foreground">Extracted Body & Content Payload</h3>
        </div>

        <div className="flex items-center gap-2">
          {/* Mode Switcher */}
          <div className="flex items-center rounded border border-border bg-surface-2 p-0.5 font-mono text-xs">
            <button
              onClick={() => setViewMode('text')}
              className={`px-2.5 py-0.5 rounded transition-colors ${
                viewMode === 'text' ? 'bg-primary text-primary-foreground font-semibold shadow-sm' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Plain Text
            </button>
            <button
              onClick={() => setViewMode('html')}
              className={`px-2.5 py-0.5 rounded transition-colors ${
                viewMode === 'html' ? 'bg-primary text-primary-foreground font-semibold shadow-sm' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              HTML Source
            </button>
            <button
              onClick={() => setViewMode('urls')}
              className={`px-2.5 py-0.5 rounded transition-colors ${
                viewMode === 'urls' ? 'bg-primary text-primary-foreground font-semibold shadow-sm' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Extracted URLs ({urls.length})
            </button>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={handleCopy}
            className="h-7 px-2.5 text-xs font-mono border-border"
            title="Copy content to clipboard"
          >
            {copiedText ? <Check className="size-3 text-clean" /> : <Copy className="size-3" />}
            <span className="ml-1">{copiedText ? 'Copied' : 'Copy'}</span>
          </Button>
        </div>
      </div>

      {/* Content Viewports */}
      {viewMode === 'text' && (
        <div className="rounded border border-border bg-background p-4 max-h-[500px] overflow-y-auto">
          <pre className="font-mono text-xs text-foreground/90 leading-relaxed whitespace-pre-wrap select-all">
            {bodyText || 'No plain text payload present in this message envelope.'}
          </pre>
        </div>
      )}

      {viewMode === 'html' && (
        <div className="rounded border border-border bg-background p-4 max-h-[500px] overflow-y-auto">
          <pre className="font-mono text-xs text-foreground/80 leading-relaxed whitespace-pre-wrap select-all">
            {bodyHtml || 'No raw HTML payload present in this message envelope.'}
          </pre>
        </div>
      )}

      {viewMode === 'urls' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-2.5 top-2 size-3 text-muted-foreground" />
              <input
                placeholder="Filter extracted hyperlinks..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full pl-7 h-7 text-xs font-mono bg-surface-2 rounded border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>

            <label className="flex items-center gap-1.5 cursor-pointer text-[10px] font-mono text-muted-foreground select-none">
              <input
                type="checkbox"
                checked={defangUrls}
                onChange={(e) => setDefangUrls(e.target.checked)}
                className="rounded bg-surface border-border text-primary size-3"
              />
              <span>Defang URLs</span>
            </label>
          </div>

          {filteredUrls.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-muted-foreground">
              No hyperlinks extracted from body payload.
            </div>
          ) : (
            <div className="divide-y divide-border/50 rounded border border-border bg-background max-h-[440px] overflow-y-auto">
              {filteredUrls.map((url, idx) => {
                const formatted = defangUrls ? defangUrl(url) : url;
                return (
                  <div key={idx} className="p-2.5 flex items-center justify-between gap-3 text-xs font-mono hover:bg-surface-2/50 transition-colors">
                    <span className="text-primary/90 break-all select-all font-medium" title={url}>
                      {formatted}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default EmailBodyViewer;
