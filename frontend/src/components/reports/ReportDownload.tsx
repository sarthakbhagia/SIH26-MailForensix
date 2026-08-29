import { useState } from 'react';
import {
  AlertCircle,
  Check,
  FileCode,
  FileDown,
  Loader2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';

export interface ReportDownloadProps {
  emailId: string | null;
  emailSubject?: string;
  disabled?: boolean;
  className?: string;
}

export default function ReportDownload({ emailId, emailSubject, disabled, className }: ReportDownloadProps) {
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
      const sanitizedSubject = (emailSubject || emailId).replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 30);
      a.download = `forensic_report_${sanitizedSubject}_${emailId.substring(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setDownloadSuccess('pdf');
      setTimeout(() => setDownloadSuccess(null), 3000);
    } catch (err: any) {
      console.error('PDF download error:', err);
      const detail = err?.response?.data?.detail || 'Failed to generate cryptographic PDF report. Please verify email analysis is complete.';
      setErrorMsg(detail);
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
      const sanitizedSubject = (emailSubject || emailId).replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 30);
      a.download = `forensic_dossier_${sanitizedSubject}_${emailId.substring(0, 8)}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setDownloadSuccess('json');
      setTimeout(() => setDownloadSuccess(null), 3000);
    } catch (err: any) {
      console.error('JSON export error:', err);
      const detail = err?.response?.data?.detail || 'Failed to export forensic JSON dossier. Please verify email analysis is complete.';
      setErrorMsg(detail);
    } finally {
      setIsDownloadingJson(false);
    }
  };

  const isDisabled = disabled || !emailId;

  return (
    <div className={cn('flex flex-col gap-1.5', className)}>
      <div className="flex flex-wrap items-center gap-2">
        {/* PDF Download Button */}
        <Button
          onClick={handleDownloadPdf}
          disabled={isDisabled || isDownloadingPdf}
          className="h-8 text-xs font-mono font-bold px-3 gap-1.5 bg-primary text-primary-foreground"
        >
          {isDownloadingPdf ? (
            <Loader2 className="size-3.5 animate-spin" />
          ) : downloadSuccess === 'pdf' ? (
            <Check className="size-3.5 text-clean" />
          ) : (
            <FileDown className="size-3.5" />
          )}
          <span>{isDownloadingPdf ? 'COMPILING PDF...' : 'DOWNLOAD PDF'}</span>
        </Button>

        {/* JSON Export Button */}
        <Button
          variant="outline"
          onClick={handleDownloadJson}
          disabled={isDisabled || isDownloadingJson}
          className="h-8 text-xs font-mono font-bold px-3 gap-1.5 border-border bg-surface hover:bg-surface-2 text-foreground"
        >
          {isDownloadingJson ? (
            <Loader2 className="size-3.5 animate-spin" />
          ) : downloadSuccess === 'json' ? (
            <Check className="size-3.5 text-clean" />
          ) : (
            <FileCode className="size-3.5" />
          )}
          <span>{isDownloadingJson ? 'EXPORTING JSON...' : 'EXPORT JSON'}</span>
        </Button>
      </div>

      {errorMsg && (
        <div className="flex items-center gap-1.5 text-xs text-critical bg-critical/10 border border-critical/30 rounded px-2.5 py-1 font-mono">
          <AlertCircle className="size-3.5 shrink-0" />
          <span className="text-[11px]">{errorMsg}</span>
        </div>
      )}
    </div>
  );
}
