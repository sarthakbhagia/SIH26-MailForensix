import { Table, TableHeader, TableRow, TableCell } from "@/components/ui/table";

interface IOCItem {
  type: "URL" | "IP" | "Domain" | "Hash";
  value: string;
  risk_score: number;
  reason: string;
  source: string;
}

interface IOCTableProps {
  iocs: IOCItem[];
  onRowClick?: (value: string, type: string) => void;
}

export function IOCTable({ iocs, onRowClick }: IOCTableProps) {
  const handleClick = (value: string, type: string) => {
    onRowClick?.(value, type);
  };

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableCell>Type</TableCell>
          <TableCell>Value</TableCell>
          <TableCell>Risk Score</TableCell>
          <TableCell>Reason</TableCell>
          <TableCell>Source</TableCell>
        </TableRow>
      </TableHeader>
      {iocs.map((ioc, index) => (
        <TableRow key={index} onClick={() => handleClick(ioc.value, ioc.type)}>
          <TableCell>
            <span className="text-lg">
              {ioc.type === "URL" && "🌐"}{
              ioc.type === "IP" && "🖥"}{
              ioc.type === "Domain" && "🌍"}{
              ioc.type === "Hash" && "📊"}
            </span>
            {ioc.type}
          </TableCell>
          <TableCell>{ioc.value}</TableCell>
          <TableCell>
            <span className="badge badge-ghost badge-sm">
              {ioc.risk_score}
            </span>
          </TableCell>
          <TableCell>{ioc.reason}</TableCell>
          <TableCell>{ioc.source}</TableCell>
        </TableRow>
      ))}
    </Table>
  );
}