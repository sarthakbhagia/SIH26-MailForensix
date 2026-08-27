import EmailUpload from '@/components/email/EmailUpload';
import EmailList from '@/components/email/EmailList';
import { HardDriveDownload, Database } from 'lucide-react';

export default function EmailIngestPage() {
  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      {/* Top Forensic Ingest Header */}
      <div className="panel relative p-5 overflow-hidden">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
                <HardDriveDownload className="size-5 text-primary" />
                Evidence Ingestion & Triage
              </h1>

              <span className="flex items-center gap-1.5 text-[10px] font-mono px-2 py-0.5 rounded border border-primary/30 bg-primary/10 text-primary">
                <Database className="size-3" />
                RFC-822 / MIME PIPELINE ACTIVE
              </span>
            </div>

            <p className="text-xs text-muted-foreground">
              Ingest raw email artifacts for automated heuristic parsing, SPF/DKIM authentication, MTA relay analysis, and NLP threat classification.
            </p>
          </div>
        </div>
      </div>

      {/* Main 2-Column Grid */}
      <div className="grid gap-6 grid-cols-1 lg:grid-cols-3">
        <div className="lg:col-span-1">
          <EmailUpload />
        </div>
        <div className="lg:col-span-2">
          <EmailList />
        </div>
      </div>
    </div>
  );
}

