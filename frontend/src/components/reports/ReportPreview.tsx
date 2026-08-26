import { useState, useRef } from 'react';
import { ExternalLink, FileText, Loader2, RefreshCw, ZoomIn, ZoomOut } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';

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
      <Card className="h-full flex flex-col items-center justify-center p-10 bg-card/40 backdrop-blur-sm border-dashed border-border/60 text-center min-h-[500px]">
        <div className="w-16 h-16 rounded-2xl bg-muted/60 flex items-center justify-center mb-4 text-muted-foreground">
          <FileText className="w-8 h-8 opacity-70" />
        </div>
        <h3 className="text-lg font-semibold text-foreground mb-1">No Email Selected</h3>
        <p className="text-sm text-muted-foreground max-w-sm">
          Select an analyzed email evidence file to generate and review its forensic investigation report preview.
        </p>
      </Card>
    );
  }

  return (
    <Card className="h-full flex flex-col bg-card/60 backdrop-blur-md border border-border/60 overflow-hidden shadow-sm">
      {/* Preview Toolbar */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-muted/30 border-b border-border/40 shrink-0">
        <div className="flex items-center gap-2 overflow-hidden mr-2">
          <FileText className="w-4 h-4 text-primary shrink-0" />
          <span className="text-xs font-semibold text-foreground truncate max-w-[280px]">
            {emailSubject || 'Forensic Investigation Report'}
          </span>
          <span className="text-[10px] text-muted-foreground bg-muted px-2 py-0.5 rounded uppercase font-bold tracking-wider">
            A4 Preview
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          {/* Zoom controls */}
          <div className="flex items-center bg-background/60 border border-border/60 rounded-md p-0.5">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleZoomOut}
              disabled={zoom <= 70}
              className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
              title="Zoom out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </Button>
            <span className="text-[11px] font-mono px-1.5 text-muted-foreground">{zoom}%</span>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleZoomIn}
              disabled={zoom >= 150}
              className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
              title="Zoom in"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </Button>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            className="h-7 text-xs px-2 gap-1"
            title="Reload preview"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleOpenNewTab}
            className="h-7 text-xs px-2 gap-1"
            title="Open in new window"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            Open
          </Button>
        </div>
      </div>

      {/* Preview Container */}
      <div className="relative flex-1 bg-muted/20 overflow-auto p-4 flex justify-center min-h-[550px]">
        {isLoading && (
          <div className="absolute inset-0 bg-background/70 backdrop-blur-sm z-10 flex flex-col items-center justify-center gap-2">
            <Loader2 className="w-8 h-8 animate-spin text-primary" />
            <p className="text-xs font-medium text-muted-foreground">Rendering forensic preview...</p>
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
          className="shadow-xl rounded-md bg-white border border-border/80 h-full min-h-[750px] overflow-hidden"
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
    </Card>
  );
}
