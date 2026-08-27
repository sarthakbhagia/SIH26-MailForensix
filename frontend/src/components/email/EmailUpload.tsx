import { useCallback, useState } from 'react';
import { useDropzone, FileRejection } from 'react-dropzone';
import { Upload, FileText, Loader2, HardDriveDownload } from 'lucide-react';
import { useUploadEmail } from '@/hooks/useEmails';
import { useToast } from '@/components/ui/use-toast';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import { useQueryClient } from '@tanstack/react-query';

const EMAIL_EXTENSIONS = ['.eml', '.msg', '.txt', '.emlx', '.rfc822'];

function isEmailFile(file: File): boolean {
  const name = file.name.toLowerCase();
  return EMAIL_EXTENSIONS.some((ext) => name.endsWith(ext));
}

export default function EmailUpload() {
  const uploadMutation = useUploadEmail();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [uploadingFiles, setUploadingFiles] = useState<string[]>([]);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isProcessing, setIsProcessing] = useState(false);

  const processUpload = async (files: File[]) => {
    if (files.length === 0) return;

    setIsProcessing(true);
    setUploadingFiles(files.map((f) => f.name));
    setUploadProgress(20);

    const progressInterval = setInterval(() => {
      setUploadProgress((p) => Math.min(p + 18, 88));
    }, 150);

    try {
      if (files.length === 1) {
        await uploadMutation.mutateAsync(files[0]);
      } else {
        await api.uploadEmails(files);
      }

      clearInterval(progressInterval);
      setUploadProgress(100);
      queryClient.invalidateQueries({ queryKey: ['emails'] });
      queryClient.invalidateQueries({ queryKey: ['dashboardStats'] });

      toast({
        title: files.length === 1 ? 'Evidence Artifact Ingested' : `${files.length} Evidence Artifacts Ingested`,
        description: 'MIME parsing, threat scoring & IOC extraction initiated.',
      });

      setTimeout(() => {
        setUploadingFiles([]);
        setUploadProgress(0);
        setIsProcessing(false);
      }, 1400);
    } catch (err) {
      clearInterval(progressInterval);
      setUploadProgress(0);
      setIsProcessing(false);
      setUploadingFiles([]);

      const errorMsg = err instanceof Error ? err.message : 'Failed to ingest artifact.';
      toast({
        variant: 'destructive',
        title: 'Ingestion Pipeline Error',
        description: errorMsg,
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
          toast({
            variant: 'destructive',
            title: 'Unsupported Artifact Type',
            description: `Please upload standard email artifacts (${EMAIL_EXTENSIONS.join(', ')}).`,
          });
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

  return (
    <div className="panel p-5 h-full flex flex-col justify-between space-y-4">
      <div>
        <div className="flex items-center justify-between border-b border-border/50 pb-3">
          <div className="flex items-center gap-2">
            <HardDriveDownload className="size-4 text-primary" />
            <h3 className="text-sm font-semibold tracking-tight text-foreground">Ingest Email Evidence</h3>
          </div>
          <span className="label-mono text-[9px]">RFC-822 / MIME</span>
        </div>
      </div>

      <div
        {...getRootProps()}
        className={cn(
          'flex flex-col items-center justify-center flex-1 min-h-[300px] p-6 border-2 border-dashed rounded-lg cursor-pointer transition-all duration-200 text-center select-none bg-surface/40',
          isDragActive && !isDragReject
            ? 'border-primary bg-primary/10 shadow-glow scale-[1.01]'
            : isDragReject
            ? 'border-critical bg-critical/10'
            : 'border-border/70 hover:border-primary/60 hover:bg-surface-2/40'
        )}
      >
        <input {...getInputProps()} />

        {isProcessing ? (
          <div className="flex flex-col items-center space-y-3.5 w-full max-w-xs">
            <Loader2 className="size-10 text-primary animate-spin" />
            <div className="space-y-1 text-center">
              <h4 className="text-xs font-mono font-bold text-foreground break-all">
                {uploadingFiles.length === 1 ? uploadingFiles[0] : `${uploadingFiles.length} Artifacts Processing`}
              </h4>
              <p className="label-mono text-[10px] text-muted-foreground">
                PARSING HEADERS, PAYLOADS & IOCS...
              </p>
            </div>

            <div className="w-full h-1.5 bg-surface-2 rounded-full overflow-hidden border border-border/40 mt-1">
              <div
                className="h-full bg-primary transition-all duration-300 ease-out"
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
            <span className="font-mono text-[10px] text-primary font-semibold">{uploadProgress}%</span>
          </div>
        ) : (
          <>
            <div
              className={cn(
                'p-3.5 rounded-full mb-3.5 transition-colors duration-200 border',
                isDragActive
                  ? 'bg-primary/20 text-primary border-primary/40'
                  : 'bg-surface text-muted-foreground border-border'
              )}
            >
              <Upload className="size-6" />
            </div>

            <h4 className="text-sm font-semibold tracking-tight text-foreground mb-1">
              {isDragActive ? 'Drop artifact to ingest' : 'Drag & drop evidence files here'}
            </h4>
            <p className="text-xs text-muted-foreground max-w-[240px] mb-3 leading-relaxed">
              Automated ingestion extracts SPF/DKIM/DMARC, hops, IOCs, and NLP threat classification.
            </p>

            <div className="flex flex-wrap items-center justify-center gap-1 mb-4">
              {EMAIL_EXTENSIONS.map((ext) => (
                <span
                  key={ext}
                  className="font-mono text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded bg-surface border border-border/60 text-muted-foreground"
                >
                  {ext}
                </span>
              ))}
            </div>

            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-surface border border-border hover:bg-muted text-foreground text-xs font-mono transition-colors">
              <FileText className="size-3 text-primary" />
              <span>Browse Local Disk</span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

