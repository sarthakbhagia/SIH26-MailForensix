import { useState, useRef } from 'react';
import {
  ExternalLink,
  FileText,
  Loader2,
  RefreshCw,
  ZoomIn,
  ZoomOut,
  AlertCircle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';

export interface ReportPreviewProps {
  emailId: string | null;
  emailSubject?: string;
}

export default function ReportPreview({ emailId, emailSubject }: ReportPreviewProps) {
  const [isLoading, setIsLoading] = useState(true);
  const [zoom, setZoom] = useState<number>(100);
  const [key, setKey] = useState(0);
  const [loadError, setLoadError] = useState(false);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  const previewUrl = emailId ? `/api/reports/emails/${emailId}/preview` : null;

  const handleRefresh = () => {
    setIsLoading(true);
    setLoadError(false);
    setKey((prev) => prev + 1);
  };

  const handleZoomIn = () => {
    setZoom((prev) => Math.min(prev + 10, 150));
  };

  const handleZoomOut = () => {
    setZoom((prev) => Math.max(prev - 10, 60));
  };

  const handleZoomReset = () => {
    setZoom(100);
  };

  const handleOpenNewTab = () => {
    if (previewUrl) {
      window.open(previewUrl, '_blank', 'noopener,noreferrer');
    }
  };

  if (!emailId) {
    return (
      <div className="panel h-full flex flex-col items-center justify-center p-12 text-center select-none">
        <FileText className="size-10 text-primary opacity-40 mb-2" />
        <h3 className="text-sm font-semibold text-foreground">No Evidence Artifact Selected</h3>
        <p className="text-xs text-muted-foreground max-w-sm mt-0.5">
          Select an analyzed email evidence envelope from the ledger on the left to compile and inspect its formal cryptographic dossier.
        </p>
      </div>
    );
  }

  return (
    <div className="panel h-full flex flex-col overflow-hidden p-0 border border-border">
      {/* 1. Document Control Bar */}
      <div className="flex items-center justify-between px-3.5 py-2 bg-surface-2/80 border-b border-border/60 shrink-0 select-none">
        <div className="flex items-center gap-2 min-w-0">
          <FileText className="size-4 text-primary shrink-0" />
          <span className="text-xs font-bold text-foreground truncate max-w-[260px] sm:max-w-[360px]" title={emailSubject}>
            {emailSubject || 'Forensic Threat Dossier'}
          </span>
          <span className="label-mono text-[9px] bg-surface px-1.5 py-0.5 rounded border border-border shrink-0">
            A4 DOSSIER
          </span>
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {/* Zoom Controls */}
          <div className="flex items-center bg-surface border border-border rounded p-0.5 font-mono text-[10px]">
            <button
              onClick={handleZoomOut}
              disabled={zoom <= 60}
              className="size-6 flex items-center justify-center rounded hover:bg-surface-2 text-muted-foreground hover:text-foreground disabled:opacity-30"
              title="Zoom Out"
            >
              <ZoomOut className="size-3.5" />
            </button>
            <span
              onClick={handleZoomReset}
              className="px-1.5 text-muted-foreground hover:text-foreground cursor-pointer select-none"
              title="Reset Zoom to 100%"
            >
              {zoom}%
            </span>
            <button
              onClick={handleZoomIn}
              disabled={zoom >= 150}
              className="size-6 flex items-center justify-center rounded hover:bg-surface-2 text-muted-foreground hover:text-foreground disabled:opacity-30"
              title="Zoom In"
            >
              <ZoomIn className="size-3.5" />
            </button>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            className="h-7 text-xs font-mono px-2 gap-1 border-border bg-surface hover:bg-surface-2"
            title="Reload Preview Document"
          >
            <RefreshCw className={`size-3 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Reload</span>
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleOpenNewTab}
            className="h-7 text-xs font-mono px-2 gap-1 border-border bg-surface hover:bg-surface-2"
            title="Open Document in New Tab"
          >
            <ExternalLink className="size-3" />
            <span>Inspect</span>
          </Button>
        </div>
      </div>

      {/* 2. Document Paper Viewport Canvas */}
      <div className="relative flex-1 bg-[#090b10] overflow-auto p-4 flex justify-center min-h-0">
        {isLoading && (
          <div className="absolute inset-0 bg-background/80 backdrop-blur-sm z-10 flex flex-col items-center justify-center gap-2">
            <Loader2 className="size-8 animate-spin text-primary" />
            <p className="label-mono text-[10px]">COMPILING COURT-READY FORENSIC DOSSIER...</p>
          </div>
        )}

        {loadError && (
          <div className="absolute inset-0 bg-background/90 z-10 flex flex-col items-center justify-center gap-2 text-center p-6">
            <AlertCircle className="size-8 text-critical" />
            <h4 className="text-xs font-bold text-foreground">Document Compilation Error</h4>
            <p className="text-[11px] text-muted-foreground max-w-xs font-mono">
              Unable to render HTML dossier preview. Ensure the backend server is running and the email has finished analysis.
            </p>
            <Button size="sm" onClick={handleRefresh} className="mt-2 text-xs font-mono">
              Retry Compilation
            </Button>
          </div>
        )}

        <div
          style={{
            transform: `scale(${zoom / 100})`,
            transformOrigin: 'top center',
            transition: 'transform 0.15s ease-out',
            width: '100%',
            maxWidth: '840px',
          }}
          className="shadow-2xl rounded bg-white border border-border/80 min-h-[900px] my-2 overflow-hidden flex flex-col"
        >
          {previewUrl && (
            <iframe
              key={key}
              ref={iframeRef}
              src={previewUrl}
              title="Forensic Report Preview"
              onLoad={() => setIsLoading(false)}
              onError={() => {
                setIsLoading(false);
                setLoadError(true);
              }}
              className="w-full flex-1 min-h-[900px] border-0"
              sandbox="allow-same-origin allow-scripts"
            />
          )}
        </div>
      </div>
    </div>
  );
}
