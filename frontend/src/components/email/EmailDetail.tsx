import { EmailDetail as EmailDetailType } from '@/types/email';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Paperclip, Link as LinkIcon } from 'lucide-react';

export default function EmailDetail({ email }: { email: EmailDetailType }) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3 border-b border-border">
          <CardTitle className="text-xl">{email.subject}</CardTitle>
        </CardHeader>
        <CardContent className="pt-4 space-y-4">
          <div className="grid grid-cols-[100px_1fr] gap-2 text-sm">
            <span className="text-muted-foreground font-medium">From:</span>
            <span className="font-mono">{email.sender}</span>
            
            <span className="text-muted-foreground font-medium">To:</span>
            <span className="font-mono">{email.recipients?.join(', ')}</span>
            
            <span className="text-muted-foreground font-medium">Date:</span>
            <span>{new Date(email.ingested_at).toLocaleString()}</span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="py-3 px-4 border-b">
          <CardTitle className="text-sm font-medium">Body</CardTitle>
        </CardHeader>
        <CardContent className="p-4">
          <div className="bg-muted/30 p-4 rounded-md whitespace-pre-wrap font-mono text-sm max-h-[400px] overflow-y-auto">
            {email.body_text || 'No text content available.'}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="py-3 px-4 border-b flex flex-row items-center gap-2">
            <Paperclip className="h-4 w-4" />
            <CardTitle className="text-sm font-medium">Attachments ({email.attachments?.length || 0})</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <ul className="divide-y divide-border">
              {email.attachments?.map((att, i) => (
                <li key={i} className="p-3 text-sm flex justify-between items-center hover:bg-muted/50">
                  <span className="font-medium truncate mr-2">{att.filename}</span>
                  <Badge variant="outline">{att.size} bytes</Badge>
                </li>
              ))}
              {(!email.attachments || email.attachments.length === 0) && (
                <li className="p-4 text-sm text-muted-foreground text-center">No attachments</li>
              )}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="py-3 px-4 border-b flex flex-row items-center gap-2">
            <LinkIcon className="h-4 w-4" />
            <CardTitle className="text-sm font-medium">Extracted URLs ({email.urls?.length || 0})</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <ul className="divide-y divide-border max-h-48 overflow-y-auto">
              {email.urls?.map((url, i) => (
                <li key={i} className="p-3 text-sm truncate font-mono text-blue-400 hover:underline cursor-pointer">
                  {url}
                </li>
              ))}
              {(!email.urls || email.urls.length === 0) && (
                <li className="p-4 text-sm text-muted-foreground text-center">No URLs found</li>
              )}
            </ul>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
