import { useCallback, useState } from 'react';
import { useDropzone, FileRejection } from 'react-dropzone';
import {
  Upload,
  Loader2,
  HardDriveDownload,
  CheckCircle2,
  AlertCircle,
  X,
  FileCode,
} from 'lucide-react';
import { useUploadEmail } from '@/hooks/useEmails';
import { useToast } from '@/components/ui/use-toast';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import { useQueryClient } from '@tanstack/react-query';

const EMAIL_EXTENSIONS = ['.eml', '.msg', '.txt', '.emlx', '.rfc822'];

type IngestStage = 'READY' | 'UPLOADING' | 'PARSING' | 'ANALYZING' | 'COMPLETE' | 'FAILED';

function isEmailFile(file: File): boolean {
  const name = file.name.toLowerCase();
  return EMAIL_EXTENSIONS.some((ext) => name.endsWith(ext));
}

export interface EmailUploadProps {
  className?: string;
  onUploadSuccess?: () => void;
}

export default function EmailUpload({ className, onUploadSuccess }: EmailUploadProps) {
  const uploadMutation = useUploadEmail();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const [stage, setStage] = useState<IngestStage>('READY');
  const [activeFileNames, setActiveFileNames] = useState<string[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const processUpload = async (files: File[]) => {
    if (files.length === 0) return;

    setActiveFileNames(files.map((f) => f.name));
    setErrorMessage(null);
    setStage('UPLOADING');

    try {
      // Transition from Uploading to Parsing
      const parseTimeout = setTimeout(() => {
        setStage('PARSING');
      }, 400);

      if (files.length === 1) {
        await uploadMutation.mutateAsync(files[0]);
      } else {
        await api.uploadEmails(files);
      }

      clearTimeout(parseTimeout);
      setStage('ANALYZING');

      // Invalidate queries to refresh evidence ledger and stats
      await queryClient.invalidateQueries({ queryKey: ['emails'] });
      await queryClient.invalidateQueries({ queryKey: ['dashboardStats'] });

      setStage('COMPLETE');
      toast({
        title: files.length === 1 ? 'Evidence Artifact Ingested' : `${files.length} Evidence Artifacts Ingested`,
        description: 'MIME payload parsed, authentication validated & threat scored.',
      });

      onUploadSuccess?.();

      setTimeout(() => {
        setStage('READY');
        setActiveFileNames([]);
      }, 2500);
    } catch (err: any) {
      setStage('FAILED');
      const errDetail = err?.response?.data?.detail || err?.message || 'Ingestion pipeline encountered an error.';
      setErrorMessage(String(errDetail));

      toast({
        variant: 'destructive',
        title: 'Ingestion Pipeline Error',
        description: errDetail,
      });
    }
  };

  const onDrop = useCallback(
    (acceptedFiles: File[], fileRejections: FileRejection[]) => {
      const validFiles: File[] = [...acceptedFiles];

      fileRejections.forEach((rejection) => {
        if (isEmailFile(rejection.file) && !validFiles.some((f) => f.name === rejection.file.name)) {
          validFiles.push(rejection.file);
        }
      });

      if (validFiles.length === 0) {
        if (fileRejections.length > 0) {
          setErrorMessage(`Unsupported format. Accepted: ${EMAIL_EXTENSIONS.join(', ')}`);
        }
        return;
      }

      processUpload(validFiles);
    },
    [uploadMutation, toast, queryClient]
  );

  const { getRootProps, getInputProps, isDragActive, isDragReject } = useDropzone({
    onDrop,
    accept: {
      'message/rfc822': ['.eml', '.emlx', '.rfc822'],
      'application/octet-stream': ['.eml', '.msg', '.txt', '.emlx'],
      'text/plain': ['.txt', '.eml'],
      'application/x-mime': ['.eml'],
      'message/rfc822-headers': ['.eml'],
      'application/vnd.ms-outlook': ['.msg'],
    },
    multiple: true,
  });

  const isBusy = stage === 'UPLOADING' || stage === 'PARSING' || stage === 'ANALYZING';

  return (
    <div className={cn('panel p-4 flex flex-col justify-between space-y-3 select-none h-full', className)}>
      {/* Ingestion Header */}
      <div className="flex items-center justify-between border-b border-border/50 pb-2.5 shrink-0">
        <div className="flex items-center gap-2">
          <HardDriveDownload className="size-4 text-primary" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
            Ingestion Dock
          </h3>
        </div>

        {/* Live Stage Status Indicator */}
        <span
          className={cn(
            'inline-flex items-center gap-1 font-mono text-[9px] font-bold uppercase px-2 py-0.5 rounded border',
            stage === 'READY' && 'bg-surface-2 text-muted-foreground border-border',
            isBusy && 'bg-primary/10 text-primary border-primary/30 animate-pulse',
            stage === 'COMPLETE' && 'bg-clean/15 text-clean border-clean/30',
            stage === 'FAILED' && 'bg-critical/15 text-critical border-critical/30'
          )}
        >
          {isBusy && <span className="size-1.5 rounded-full bg-primary animate-ping" />}
          {stage === 'COMPLETE' && <CheckCircle2 className="size-2.5 text-clean" />}
          {stage === 'FAILED' && <AlertCircle className="size-2.5 text-critical" />}
          {stage}
        </span>
      </div>

      {/* Dropzone Area */}
      <div
        {...getRootProps()}
        className={cn(
          'flex flex-col items-center justify-center flex-1 min-h-[220px] p-4 border-2 border-dashed rounded cursor-pointer transition-all duration-150 text-center bg-surface-2/30',
          isDragActive && !isDragReject
            ? 'border-primary bg-primary/10 scale-[1.01]'
            : isDragReject
            ? 'border-critical bg-critical/10'
            : 'border-border/70 hover:border-primary/50 hover:bg-surface-2/60'
        )}
      >
        <input {...getInputProps()} disabled={isBusy} />

        {isBusy ? (
          <div className="flex flex-col items-center space-y-3 w-full max-w-[220px]">
            <Loader2 className="size-8 text-primary animate-spin" />
            <div className="space-y-1 text-center">
              <h4 className="text-xs font-mono font-bold text-foreground truncate max-w-[200px]">
                {activeFileNames.length === 1 ? activeFileNames[0] : `${activeFileNames.length} Evidence Artifacts`}
              </h4>
              <p className="label-mono text-[9px] text-muted-foreground">
                {stage === 'UPLOADING' && 'TRANSMITTING ARTIFACT BINARY...'}
                {stage === 'PARSING' && 'PARSING RFC-822 HEADERS & MIME...'}
                {stage === 'ANALYZING' && 'RUNNING NLP & THREAT HEURISTICS...'}
              </p>
            </div>
          </div>
        ) : stage === 'COMPLETE' ? (
          <div className="flex flex-col items-center space-y-2 text-clean">
            <CheckCircle2 className="size-9" />
            <div className="space-y-0.5">
              <h4 className="text-xs font-bold font-mono">INGESTION COMPLETE</h4>
              <p className="text-[10px] text-muted-foreground font-mono">
                {activeFileNames.length} artifact(s) added to evidence ledger
              </p>
            </div>
          </div>
        ) : (
          <>
            <div
              className={cn(
                'p-2.5 rounded-full mb-2.5 transition-colors border',
                isDragActive ? 'bg-primary/20 text-primary border-primary/40' : 'bg-surface text-muted-foreground border-border'
              )}
            >
              <Upload className="size-5" />
            </div>

            <h4 className="text-xs font-semibold tracking-tight text-foreground mb-0.5">
              {isDragActive ? 'Drop evidence artifact' : 'Drag & drop raw email files'}
            </h4>
            <p className="text-[11px] text-muted-foreground max-w-[210px] mb-2.5 leading-tight">
              Automated extraction of headers, relay hops, attachments, and URLs.
            </p>

            {/* Supported Extensions List */}
            <div className="flex flex-wrap items-center justify-center gap-1 mb-3">
              {EMAIL_EXTENSIONS.map((ext) => (
                <span
                  key={ext}
                  className="font-mono text-[9px] font-semibold uppercase px-1.5 py-0.2 rounded bg-surface border border-border/70 text-muted-foreground"
                >
                  {ext}
                </span>
              ))}
            </div>

            <div className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-surface border border-border hover:bg-surface-2 text-foreground text-[11px] font-mono transition-colors">
              <FileCode className="size-3 text-primary" />
              <span>Browse Local Disk</span>
            </div>
          </>
        )}
      </div>

      {/* Error Message Toast in Dock */}
      {errorMessage && (
        <div className="p-2.5 rounded bg-critical/10 border border-critical/30 flex items-start justify-between gap-2 text-critical text-xs font-mono shrink-0">
          <div className="flex items-start gap-1.5 min-w-0">
            <AlertCircle className="size-3.5 shrink-0 mt-0.5" />
            <span className="text-[11px] break-words">{errorMessage}</span>
          </div>
          <button
            onClick={() => {
              setErrorMessage(null);
              setStage('READY');
            }}
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="size-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}
