import EmailUpload from '@/components/email/EmailUpload';
import EmailList from '@/components/email/EmailList';

export default function EmailIngestPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Email Ingestion</h1>
        <p className="text-muted-foreground mt-2">Upload and analyze new suspicious emails.</p>
      </div>
      
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-1">
          <EmailUpload />
        </div>
        <div className="lg:col-span-2">
          <h2 className="text-xl font-semibold mb-4">Recent Uploads</h2>
          <EmailList />
        </div>
      </div>
    </div>
  );
}
