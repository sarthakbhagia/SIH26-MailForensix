import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface RelayHop {
  hop_number: number;
  from_host: string;
  by_host: string;
  ip: string;
  timestamp: string;
  protocol: string;
  delay_seconds: number;
  is_private: boolean;
  infrastructure_type: string;
  anomalies: any[];
}

export function RelayPathViewer({ hops }: { hops: RelayHop[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Relay Path ({hops.length} Hops)</CardTitle>
      </CardHeader>

      <CardContent>
        {hops.map((hop, index) => {
          const isPrivate = hop.is_private;
          const infraClass = isPrivate
            ? "bg-gray-100 text-gray-800"
            : hop.infrastructure_type === "known_vpn"
              ? "bg-red-100 text-red-800"
              : hop.infrastructure_type === "aws_cloud"
                ? "bg-orange-100 text-orange-800"
                : "bg-green-100 text-green-800";

          const delayStr = hop.delay_seconds > 0
            ? `─── ${hop.delay_seconds.toFixed(1)}s delay`
            : "";

          const anomalyBads = hop.anomalies
            .filter((a) => a.severity === "critical" || a.severity === "warning")
            .map((a) => (
              <span key={a.type} className="text-red-600 text-xs font-medium">
                {a.type}
              </span>
            ));

          return (
            <div key={index} className="flex items-start gap-4 pb-4 border-b last:border-0">
              <span className="font-medium text-sm flex-1">
                {index + 1}├─ {hop.by_host || hop.ip}
              </span>

              <Badge
                variant="outline"
                className={infraClass}
              >
                {hop.infrastructure_type || "unknown"}
              </Badge>

              <span className="text-xs text-muted-foreground ml-2">
                {hop.timestamp}
              </span>

              {delayStr && (
                <span className="text-xs ml-2 text-muted-foreground">
                  {delayStr}
                </span>
              )}

              <span className="text-xs text-gray-500 ml-auto">
                {hop.ip}
              </span>

              {anomalyBads.length > 0 && (
                <div className="ml-4 text-right">
                  {anomalyBads}
                </div>
              )}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}