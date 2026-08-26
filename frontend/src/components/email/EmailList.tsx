import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Search } from 'lucide-react';
import { formatDate, getSeverityColor } from '@/lib/utils';
import { EmailSummary } from '@/types/email';
import { useEmails } from '@/hooks/useEmails';

export default function EmailList() {
  const navigate = useNavigate();
  const [page] = useState(1);
  const [globalFilter, setGlobalFilter] = useState('');
  const { data, isLoading } = useEmails(page);

  const tableData: EmailSummary[] = data?.items ?? (data as any)?.data ?? [];

  const columns = [
    { accessorKey: 'sender', header: 'Sender' },
    { accessorKey: 'subject', header: 'Subject' },
    {
      accessorKey: 'ingested_at',
      header: 'Date',
      cell: ({ row }: any) => formatDate(row.getValue('ingested_at')),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }: any) => <Badge variant="outline" className="uppercase text-[10px] tracking-wider">{row.getValue('status')}</Badge>,
    },
    {
      accessorKey: 'risk_score',
      header: 'Risk Score',
      cell: ({ row }: any) => {
        const score = row.getValue('risk_score') as number;
        if (score === undefined) return '-';
        return (
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full bg-severity-${score >= 76 ? 'critical' : score >= 51 ? 'high' : score >= 26 ? 'medium' : 'low'}`} />
            <span className={`font-bold ${getSeverityColor(score)}`}>{score}</span>
          </div>
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
    <div className="space-y-4">
      <div className="relative w-full max-w-md">
        <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input 
          placeholder="Search by sender, subject..." 
          value={globalFilter ?? ''}
          onChange={(e) => setGlobalFilter(e.target.value)}
          className="pl-9 bg-card/50"
        />
      </div>
      <div className="rounded-xl border border-border/60 bg-card/50 overflow-hidden shadow-sm">
        <Table>
          <TableHeader className="bg-muted/30">
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id} className="hover:bg-transparent border-border/40">
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id} className="font-semibold text-muted-foreground h-10">
                    {flexRender(header.column.columnDef.header, header.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow><TableCell colSpan={columns.length} className="text-center h-32 text-muted-foreground">Loading...</TableCell></TableRow>
            ) : table.getRowModel().rows?.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  className="cursor-pointer transition-colors hover:bg-muted/40 border-border/40"
                  onClick={() => navigate(`/emails/${row.original.id}`)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id} className="py-3">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={columns.length} className="text-center text-muted-foreground h-32">
                  No results found.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
