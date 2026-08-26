import { useCallback, useState } from 'react';
import { useDropzone, FileRejection } from 'react-dropzone';
import { Upload, FileText, Loader2 } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
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
    setUploadProgress(15);

    const progressInterval = setInterval(() => {
      setUploadProgress((p) => Math.min(p + 15, 85));
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

      toast({
        title: files.length === 1 ? 'Email Uploaded Successfully' : `${files.length} Emails Uploaded`,
        description: 'Forensics analysis and threat intelligence dispatch initiated.',
      });

      setTimeout(() => {
        setUploadingFiles([]);
        setUploadProgress(0);
        setIsProcessing(false);
      }, 1500);
    } catch (err) {
      clearInterval(progressInterval);
      setUploadProgress(0);
      setIsProcessing(false);
      setUploadingFiles([]);

      const errorMsg = err instanceof Error ? err.message : 'Failed to upload email file.';
      toast({
        variant: 'destructive',
        title: 'Upload Failed',
        description: errorMsg,
      });
    }
  };

  const onDrop = useCallback(
    (acceptedFiles: File[], fileRejections: FileRejection[]) => {
      // 1. Gather valid files from both acceptedFiles and extension-matched rejectedFiles
      const validFiles: File[] = [...acceptedFiles];

      fileRejections.forEach((rejection) => {
        if (isEmailFile(rejection.file) && !validFiles.some((f) => f.name === rejection.file.name)) {
          validFiles.push(rejection.file);
        }
      });

      // 2. If no valid files found, notify user
      if (validFiles.length === 0) {
        if (fileRejections.length > 0) {
          toast({
            variant: 'destructive',
            title: 'Unsupported File Type',
            description: `Please upload standard email files (${EMAIL_EXTENSIONS.join(', ')}).`,
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
    <Card className="h-full bg-card/50 border-border/80 shadow-sm">
      <CardContent className="p-6 h-full flex flex-col">
        <div
          {...getRootProps()}
          className={cn(
            'flex flex-col items-center justify-center flex-1 min-h-[320px] p-8 border-2 border-dashed rounded-xl cursor-pointer transition-all duration-200 text-center select-none',
            isDragActive && !isDragReject
              ? 'border-primary bg-primary/10 scale-[1.01]'
              : isDragReject
              ? 'border-destructive bg-destructive/10'
              : 'border-border/60 hover:bg-muted/40 hover:border-primary/50'
          )}
        >
          <input {...getInputProps()} />

          {isProcessing ? (
            <div className="flex flex-col items-center space-y-3">
              <Loader2 className="h-12 w-12 text-primary animate-spin" />
              <div className="space-y-1">
                <h4 className="text-base font-semibold text-foreground">
                  Ingesting {uploadingFiles.length === 1 ? uploadingFiles[0] : `${uploadingFiles.length} files`}...
                </h4>
                <p className="text-xs text-muted-foreground">Parsing headers, attachments, and URLs</p>
              </div>
              <div className="w-48 h-2 bg-muted rounded-full overflow-hidden mt-2">
                <div
                  className="h-full bg-primary transition-all duration-300 ease-out"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          ) : (
            <>
              <div
                className={cn(
                  'p-4 rounded-full mb-4 transition-colors duration-200',
                  isDragActive ? 'bg-primary/20 text-primary' : 'bg-muted text-muted-foreground'
                )}
              >
                <Upload className="h-8 w-8" />
              </div>

              <h3 className="text-lg font-bold tracking-tight text-foreground mb-1">
                {isDragActive ? 'Drop email files to upload' : 'Drag & drop email files here'}
              </h3>
              <p className="text-xs text-muted-foreground max-w-[240px] mb-4">
                Supports <span className="font-mono text-foreground">.eml</span>,{' '}
                <span className="font-mono text-foreground">.msg</span>, and raw email text files
              </p>

              <div className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md bg-secondary text-secondary-foreground text-xs font-medium border border-border">
                <FileText className="h-3.5 w-3.5 text-primary" />
                <span>or click to browse from device</span>
              </div>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
