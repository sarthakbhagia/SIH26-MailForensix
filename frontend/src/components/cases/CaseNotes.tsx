import { useState } from 'react';
import { formatDistanceToNow } from 'date-fns';
import { AlertCircle, Loader2, MessageSquare, Plus, Send, User } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { useAddCaseNote, useCaseNotes } from '@/hooks/useCases';

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
      <Card className="bg-card/70 border-border/60 shadow-sm overflow-hidden">
        <form onSubmit={handleAddNote} className="p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <Plus className="w-3.5 h-3.5 text-primary" />
              Add Investigation Note
            </h4>
            <div className="flex items-center gap-1.5">
              <User className="w-3.5 h-3.5 text-muted-foreground" />
              <Input
                value={author}
                onChange={(e) => setAuthor(e.target.value)}
                placeholder="Author name"
                className="h-7 text-xs w-36 bg-background/60 border-border/60"
              />
            </div>
          </div>

          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Record technical findings, evidence correlations, adversary tactics, or remediation steps..."
            rows={3}
            className="w-full text-xs rounded-md bg-background/60 border border-border/60 p-2.5 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary transition-all resize-y"
          />

          {errorMsg && (
            <div className="flex items-center gap-1.5 text-xs text-destructive bg-destructive/10 border border-destructive/20 rounded-md p-2">
              <AlertCircle className="w-3.5 h-3.5 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="flex justify-end">
            <Button
              type="submit"
              size="sm"
              disabled={!content.trim() || addNoteMutation.isPending}
              className="h-8 text-xs px-3 gap-1.5 font-medium"
            >
              {addNoteMutation.isPending ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Send className="w-3.5 h-3.5" />
              )}
              <span>Post Note</span>
            </Button>
          </div>
        </form>
      </Card>

      {/* Notes List */}
      <div className="space-y-2.5">
        {isLoading && (
          <div className="flex flex-col items-center justify-center p-8 text-muted-foreground gap-2">
            <Loader2 className="w-6 h-6 animate-spin text-primary" />
            <span className="text-xs">Loading case notes...</span>
          </div>
        )}

        {!isLoading && isError && (
          <div className="p-4 text-center text-xs text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded-lg">
            Failed to load notes.{' '}
            <button onClick={() => refetch()} className="underline font-semibold ml-1">
              Retry
            </button>
          </div>
        )}

        {!isLoading && !isError && (!notes || notes.length === 0) && (
          <Card className="flex flex-col items-center justify-center p-8 text-center text-muted-foreground border-dashed bg-card/30">
            <MessageSquare className="w-8 h-8 opacity-40 mb-2 text-muted-foreground" />
            <p className="text-xs font-medium text-foreground">No notes posted yet</p>
            <p className="text-[11px] text-muted-foreground mt-0.5 max-w-xs">
              Record analyst remarks, adversary insights, and containment steps above.
            </p>
          </Card>
        )}

        {!isLoading &&
          !isError &&
          notes &&
          notes.map((note) => (
            <Card
              key={note.id}
              className="bg-card/50 border-border/50 shadow-sm hover:border-border/80 transition-colors"
            >
              <CardContent className="p-3.5 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-primary" />
                      {note.author}
                    </span>
                    <span className="text-[10px] text-muted-foreground bg-muted px-2 py-0.5 rounded font-mono">
                      Analyst
                    </span>
                  </div>
                  <span className="text-[10px] text-muted-foreground font-mono">
                    {note.created_at
                      ? formatDistanceToNow(new Date(note.created_at), { addSuffix: true })
                      : 'recently'}
                  </span>
                </div>

                <p className="text-xs text-foreground/90 whitespace-pre-wrap leading-relaxed font-sans pl-3.5 border-l-2 border-primary/40">
                  {note.content}
                </p>
              </CardContent>
            </Card>
          ))}
      </div>
    </div>
  );
}
