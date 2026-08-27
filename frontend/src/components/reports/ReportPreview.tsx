import { useState, useRef } from 'react';
import { ExternalLink, FileText, Loader2, RefreshCw, ZoomIn, ZoomOut } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface ReportPreviewProps {
  emailId: string | null;
  emailSubject?: string;
}

export default function ReportPreview({ emailId, emailSubject }: ReportPreviewProps) {
  const [isLoading, setIsLoading] = useState(true);
  const [zoom, setZoom] = useState<number>(100);
  const [key, setKey] = useState(0);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  const previewUrl = emailId ? `/api/reports/emails/${emailId}/preview` : null;

  const handleRefresh = () => {
    setIsLoading(true);
    setKey((prev) => prev + 1);
  };

  const handleZoomIn = () => {
    setZoom((prev) => Math.min(prev + 10, 150));
  };

  const handleZoomOut = () => {
    setZoom((prev) => Math.max(prev - 10, 70));
  };

  const handleOpenNewTab = () => {
    if (previewUrl) {
      window.open(previewUrl, '_blank', 'noopener,noreferrer');
    }
  };

  if (!emailId) {
    return (
      <div className="panel h-full flex flex-col items-center justify-center p-10 text-center min-h-[500px] border-dashed">
        <div className="size-16 rounded-2xl bg-surface-2 flex items-center justify-center mb-4 text-muted-foreground border border-border">
          <FileText className="size-8 opacity-60 text-primary" />
        </div>
        <h3 className="text-base font-bold text-foreground mb-1">No Email Artifact Selected</h3>
        <p className="text-xs text-muted-foreground max-w-sm">
          Select an analyzed email evidence file from the ledger to generate and inspect its cryptographic forensic report preview.
        </p>
      </div>
    );
  }

  return (
    <div className="panel h-full flex flex-col overflow-hidden p-0 shadow-lg">
      {/* Preview Toolbar */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-surface-2/70 border-b border-border/60 shrink-0">
        <div className="flex items-center gap-2 overflow-hidden mr-2">
          <FileText className="size-4 text-primary shrink-0" />
          <span className="text-xs font-semibold text-foreground truncate max-w-[280px]">
            {emailSubject || 'Forensic Investigation Report'}
          </span>
          <span className="label-mono text-[9px] bg-surface px-1.5 py-0.5 rounded border border-border">
            A4 PREVIEW
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          {/* Zoom controls */}
          <div className="flex items-center bg-surface border border-border rounded p-0.5 font-mono text-[10px]">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleZoomOut}
              disabled={zoom <= 70}
              className="size-6 p-0 text-muted-foreground hover:text-foreground"
              title="Zoom out"
            >
              <ZoomOut className="size-3.5" />
            </Button>
            <span className="px-1.5 text-muted-foreground">{zoom}%</span>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleZoomIn}
              disabled={zoom >= 150}
              className="size-6 p-0 text-muted-foreground hover:text-foreground"
              title="Zoom in"
            >
              <ZoomIn className="size-3.5" />
            </Button>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            className="h-7 text-xs font-mono px-2 gap-1 border-border bg-surface hover:bg-muted"
            title="Reload preview"
          >
            <RefreshCw className={`size-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            RELOAD
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleOpenNewTab}
            className="h-7 text-xs font-mono px-2 gap-1 border-border bg-surface hover:bg-muted"
            title="Open in new window"
          >
            <ExternalLink className="size-3.5" />
            OPEN
          </Button>
        </div>
      </div>

      {/* Preview Container */}
      <div className="relative flex-1 bg-background/50 overflow-auto p-4 flex justify-center min-h-[550px]">
        {isLoading && (
          <div className="absolute inset-0 bg-background/80 backdrop-blur-sm z-10 flex flex-col items-center justify-center gap-2">
            <Loader2 className="size-8 animate-spin text-primary" />
            <p className="label-mono text-[10px]">RENDERING FORENSIC PREVIEW...</p>
          </div>
        )}

        <div
          style={{
            transform: `scale(${zoom / 100})`,
            transformOrigin: 'top center',
            transition: 'transform 0.15s ease-out',
            width: '100%',
            maxWidth: '820px',
          }}
          className="shadow-2xl rounded bg-white border border-border h-full min-h-[750px] overflow-hidden"
        >
          {previewUrl && (
            <iframe
              key={key}
              ref={iframeRef}
              src={previewUrl}
              title="Forensic Report Preview"
              onLoad={() => setIsLoading(false)}
              className="w-full h-full min-h-[750px] border-0"
              sandbox="allow-same-origin allow-scripts"
            />
          )}
        </div>
      </div>
    </div>
  );
}

