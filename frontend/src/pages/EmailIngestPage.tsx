import EmailUpload from '@/components/email/EmailUpload';
import EmailList from '@/components/email/EmailList';
import { HardDriveDownload, Database } from 'lucide-react';

export default function EmailIngestPage() {
  return (
    <div className="flex flex-col h-[calc(100vh-4.5rem)] space-y-3 max-w-full pb-4">
      {/* 1. Header Toolbar */}
      <div className="panel p-4 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div>
          <h1 className="text-lg sm:text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <HardDriveDownload className="size-4 text-primary" />
            Forensic Ingestion & Evidence Ledger
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Ingest raw RFC-822/MIME artifacts for header parsing, MTA relay extraction, and NLP threat classification.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 text-[10px] font-mono px-2.5 py-1 rounded border border-primary/30 bg-primary/10 text-primary font-bold">
            <Database className="size-3.5" />
            RFC-822 / MIME PIPELINE ACTIVE
          </span>
        </div>
      </div>

      {/* 2. Main 2-Column Split: Ingestion Dock (Left) | Evidence Ledger (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 flex-1 min-h-0">
        {/* Left: Forensic Ingestion Dock (4 cols on lg, 3.5 on xl) */}
        <div className="lg:col-span-4 xl:col-span-3 flex flex-col h-full min-h-0">
          <EmailUpload />
        </div>

        {/* Right: Ingested Evidence Ledger (8 cols on lg, 8.5 on xl) */}
        <div className="lg:col-span-8 xl:col-span-9 flex flex-col h-full min-h-0 overflow-hidden">
          <EmailList />
        </div>
      </div>
    </div>
  );
}
