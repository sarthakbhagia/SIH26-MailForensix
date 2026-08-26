import { useState } from 'react';
import { AlertCircle, Check, FileCode, FileDown, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';

interface ReportDownloadProps {
  emailId: string | null;
  emailSubject?: string;
  disabled?: boolean;
}

export default function ReportDownload({ emailId, disabled }: ReportDownloadProps) {
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [isDownloadingJson, setIsDownloadingJson] = useState(false);
  const [downloadSuccess, setDownloadSuccess] = useState<'pdf' | 'json' | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleDownloadPdf = async () => {
    if (!emailId) return;
    try {
      setIsDownloadingPdf(true);
      setErrorMsg(null);
      setDownloadSuccess(null);

      const response = await api.getReportPdf(emailId);
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `forensic_report_${emailId}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setDownloadSuccess('pdf');
      setTimeout(() => setDownloadSuccess(null), 3000);
    } catch (err: any) {
      console.error('PDF download error:', err);
      setErrorMsg('Failed to generate/download forensic PDF report. Please try again.');
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const handleDownloadJson = async () => {
    if (!emailId) return;
    try {
      setIsDownloadingJson(true);
      setErrorMsg(null);
      setDownloadSuccess(null);

      const response = await api.getReportJson(emailId);
      const jsonStr = JSON.stringify(response.data, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `forensic_report_${emailId}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setDownloadSuccess('json');
      setTimeout(() => setDownloadSuccess(null), 3000);
    } catch (err: any) {
      console.error('JSON export error:', err);
      setErrorMsg('Failed to export forensic JSON report. Please try again.');
    } finally {
      setIsDownloadingJson(false);
    }
  };

  const isDisabled = disabled || !emailId;

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <Button
          onClick={handleDownloadPdf}
          disabled={isDisabled || isDownloadingPdf}
          className="h-9 text-xs px-3.5 gap-2 font-medium bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm transition-all"
        >
          {isDownloadingPdf ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : downloadSuccess === 'pdf' ? (
            <Check className="w-4 h-4 text-emerald-400" />
          ) : (
            <FileDown className="w-4 h-4" />
          )}
          <span>{isDownloadingPdf ? 'Generating PDF...' : 'Download Forensic PDF'}</span>
        </Button>

        <Button
          variant="outline"
          onClick={handleDownloadJson}
          disabled={isDisabled || isDownloadingJson}
          className="h-9 text-xs px-3.5 gap-2 font-medium border-border/70 hover:bg-muted shadow-sm transition-all"
        >
          {isDownloadingJson ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : downloadSuccess === 'json' ? (
            <Check className="w-4 h-4 text-emerald-400" />
          ) : (
            <FileCode className="w-4 h-4" />
          )}
          <span>{isDownloadingJson ? 'Exporting JSON...' : 'Export JSON'}</span>
        </Button>
      </div>

      {errorMsg && (
        <div className="flex items-center gap-1.5 text-xs text-destructive bg-destructive/10 border border-destructive/20 rounded-md px-3 py-1.5 mt-1">
          <AlertCircle className="w-3.5 h-3.5 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}
    </div>
  );
}
