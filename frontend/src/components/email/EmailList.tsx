import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Input } from '@/components/ui/input';
import { Search, Inbox } from 'lucide-react';
import { formatDate } from '@/lib/utils';
import { EmailSummary } from '@/types/email';
import { useEmails } from '@/hooks/useEmails';
import { cn } from '@/lib/utils';

export function EmailList() {
  const navigate = useNavigate();
  const [page] = useState(1);
  const [globalFilter, setGlobalFilter] = useState('');
  const { data, isLoading } = useEmails(page);

  const tableData: EmailSummary[] = data?.items ?? (data as any)?.data ?? [];

  const getScoreStyle = (score: number) => {
    if (score >= 75) return { text: 'text-critical', bg: 'bg-critical/15 border-critical/30' };
    if (score >= 50) return { text: 'text-high', bg: 'bg-high/15 border-high/30' };
    if (score >= 25) return { text: 'text-medium', bg: 'bg-medium/15 border-medium/30' };
    return { text: 'text-clean', bg: 'bg-clean/15 border-clean/30' };
  };

  const columns = [
    {
      accessorKey: 'sender',
      header: 'Sender (From)',
      cell: ({ row }: any) => {
        const sender = row.getValue('sender') as string;
        return (
          <span className="font-mono text-xs text-foreground font-medium truncate block max-w-[180px] sm:max-w-[220px]" title={sender}>
            {sender || '—'}
          </span>
        );
      },
    },
    {
      accessorKey: 'subject',
      header: 'Subject / Evidence Subject',
      cell: ({ row }: any) => {
        const subject = row.getValue('subject') as string;
        return (
          <span className="text-xs text-foreground font-medium truncate block max-w-[200px] sm:max-w-[320px]" title={subject}>
            {subject || '(No Subject)'}
          </span>
        );
      },
    },
    {
      accessorKey: 'ingested_at',
      header: 'Ingested',
      cell: ({ row }: any) => (
        <span className="label-mono text-[10px] whitespace-nowrap">
          {formatDate(row.getValue('ingested_at'))}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }: any) => {
        const status = String(row.getValue('status') || 'analyzed').toLowerCase();
        const isAnalyzing = status === 'analyzing' || status === 'pending';
        return (
          <span
            className={cn(
              'inline-flex items-center gap-1 font-mono text-[9px] font-bold uppercase px-2 py-0.5 rounded border',
              isAnalyzing
                ? 'bg-primary/10 text-primary border-primary/30'
                : 'bg-surface-2 text-foreground/80 border-border'
            )}
          >
            {isAnalyzing && <span className="size-1.5 rounded-full bg-primary animate-pulse" />}
            {status}
          </span>
        );
      },
    },
    {
      accessorKey: 'risk_score',
      header: 'Risk Score',
      cell: ({ row }: any) => {
        const score = row.getValue('risk_score') as number;
        if (score === undefined || score === null) return <span className="text-muted-foreground font-mono text-xs">—</span>;
        const style = getScoreStyle(score);
        return (
          <span
            className={cn(
              'inline-flex items-center gap-1.5 font-mono text-[10px] font-bold px-2 py-0.5 rounded border',
              style.bg,
              style.text
            )}
          >
            <span className={cn('size-1.5 rounded-full', score >= 75 ? 'bg-critical' : score >= 50 ? 'bg-high' : score >= 25 ? 'bg-medium' : 'bg-clean')} />
            {score.toFixed(0)} / 100
          </span>
        );
      },
    },
  ];

  const table = useReactTable({
    data: tableData,
    columns,
    state: { globalFilter },
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  });

  return (
    <div className="panel p-5 space-y-4">
      {/* Search & Filter Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/50 pb-3">
        <div className="relative w-full max-w-sm">
          <Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search sender, subject, or message..."
            value={globalFilter ?? ''}
            onChange={(e) => setGlobalFilter(e.target.value)}
            className="pl-8 h-8 text-xs font-mono bg-background/60 border-border"
          />
        </div>

        <div className="label-mono text-[10px]">
          {table.getFilteredRowModel().rows.length} OF {tableData.length} ARTIFACTS
        </div>
      </div>

      {/* Table Container */}
      <div className="rounded border border-border/70 overflow-x-auto bg-surface/30">
        <Table>
          <TableHeader className="bg-surface-2/60 border-b border-border">
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id} className="hover:bg-transparent border-border/60">
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id} className="label-mono text-[10px] text-muted-foreground h-9">
                    {flexRender(header.column.columnDef.header, header.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={columns.length} className="text-center h-36">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <div className="size-6 rounded-full border-2 border-muted border-t-primary animate-spin" />
                    <span className="label-mono text-[10px]">FETCHING INGESTION LEDGER...</span>
                  </div>
                </TableCell>
              </TableRow>
            ) : table.getRowModel().rows?.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  className="cursor-pointer transition-colors hover:bg-surface-2/60 border-b border-border/40 group"
                  onClick={() => navigate(`/emails/${row.original.id}`)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id} className="py-2.5">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={columns.length} className="text-center py-10 text-muted-foreground">
                  <Inbox className="size-7 mx-auto opacity-40 mb-1.5" />
                  <p className="text-xs font-semibold text-foreground">No email records found</p>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    {globalFilter ? 'Try clearing your search query filter.' : 'Upload an email artifact to begin forensic analysis.'}
                  </p>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

export default EmailList;

