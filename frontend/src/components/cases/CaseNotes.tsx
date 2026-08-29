import { useState } from 'react';
import { AlertCircle, Loader2, MessageSquare, Plus, Send, User } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useAddCaseNote, useCaseNotes } from '@/hooks/useCases';
import { safeFormatDistanceToNow } from '@/lib/utils';

interface CaseNotesProps {
  caseId: string;
}

export default function CaseNotes({ caseId }: CaseNotesProps) {
  const { data: notes, isLoading, isError, refetch } = useCaseNotes(caseId);
  const addNoteMutation = useAddCaseNote();

  const [content, setContent] = useState('');
  const [author, setAuthor] = useState('Lead Analyst');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;

    try {
      setErrorMsg(null);
      await addNoteMutation.mutateAsync({
        caseId,
        note: {
          content: content.trim(),
          author: author.trim() || 'Analyst',
        },
      });
      setContent('');
    } catch (err: any) {
      console.error('Failed to add note:', err);
      setErrorMsg('Failed to add investigation note. Please try again.');
    }
  };

  return (
    <div className="space-y-4">
      {/* Add Note Form */}
      <div className="panel p-4 space-y-3">
        <form onSubmit={handleAddNote} className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="label-mono font-bold flex items-center gap-1.5 text-foreground">
              <Plus className="size-3.5 text-primary" />
              ADD INVESTIGATION NOTE
            </h4>
            <div className="flex items-center gap-1.5">
              <User className="size-3.5 text-muted-foreground" />
              <Input
                value={author}
                onChange={(e) => setAuthor(e.target.value)}
                placeholder="Author name"
                className="h-7 text-xs font-mono w-36 bg-background/60 border-border"
              />
            </div>
          </div>

          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Record technical findings, evidence correlations, adversary tactics, or remediation steps..."
            rows={3}
            className="w-full text-xs rounded bg-background/60 border border-border p-2.5 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary transition-all resize-y font-mono"
          />

          {errorMsg && (
            <div className="flex items-center gap-1.5 text-xs text-critical bg-critical/10 border border-critical/20 rounded p-2 font-mono">
              <AlertCircle className="size-3.5 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="flex justify-end">
            <Button
              type="submit"
              size="sm"
              disabled={!content.trim() || addNoteMutation.isPending}
              className="h-8 text-xs font-mono font-bold px-3 gap-1.5"
            >
              {addNoteMutation.isPending ? (
                <Loader2 className="size-3.5 animate-spin" />
              ) : (
                <Send className="size-3.5" />
              )}
              <span>POST NOTE</span>
            </Button>
          </div>
        </form>
      </div>

      {/* Notes List */}
      <div className="space-y-2.5">
        {isLoading && (
          <div className="panel flex flex-col items-center justify-center p-8 text-muted-foreground gap-2">
            <Loader2 className="size-6 animate-spin text-primary" />
            <span className="label-mono text-[10px]">FETCHING CASE NOTES...</span>
          </div>
        )}

        {!isLoading && isError && (
          <div className="panel p-4 text-center text-xs text-medium border-medium/30">
            Failed to load notes.{' '}
            <button onClick={() => refetch()} className="underline font-semibold ml-1">
              Retry
            </button>
          </div>
        )}

        {!isLoading && !isError && (!notes || notes.length === 0) && (
          <div className="panel flex flex-col items-center justify-center p-8 text-center text-muted-foreground border-dashed">
            <MessageSquare className="size-8 opacity-40 mb-2 text-muted-foreground" />
            <p className="text-xs font-medium text-foreground">No notes posted yet</p>
            <p className="text-[11px] text-muted-foreground mt-0.5 max-w-xs">
              Record analyst remarks, adversary insights, and containment steps above.
            </p>
          </div>
        )}

        {!isLoading &&
          !isError &&
          notes &&
          notes.map((note) => (
            <div
              key={note.id}
              className="panel p-3.5 space-y-2"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
                    <span className="size-1.5 rounded-full bg-primary" />
                    {note.author}
                  </span>
                  <span className="label-mono text-[9px] bg-surface px-1.5 py-0.5 rounded border border-border">
                    Analyst
                  </span>
                </div>
                <span className="text-[10px] text-muted-foreground font-mono">
                  {safeFormatDistanceToNow(note.created_at, { addSuffix: true }, 'recently')}
                </span>
              </div>

              <p className="text-xs text-foreground/90 whitespace-pre-wrap leading-relaxed font-mono pl-3 border-l-2 border-primary/50">
                {note.content}
              </p>
            </div>
          ))}
      </div>
    </div>
  );
}

