import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CheckCircle2, XCircle, AlertCircle } from "lucide-react";


interface SPFResult {
  status: "pass" | "fail" | "none" | "softfail";
  domain: string;
  ip: string;
  record: string;
}

interface DKIMResult {
  status: "pass" | "fail" | "none";
  domain: string;
  selector: string;
  details: string;
}

interface DMARCResult {
  status: "pass" | "fail" | "none";
  policy: "none" | "quarantine" | "reject";
  domain: string;
  alignment_spf: boolean;
  alignment_dkim: boolean;
  record: string;
}

export function AuthenticationPanel({
  spf,
  dkim,
  dmarc,
}: {
  spf: SPFResult;
  dkim: DKIMResult;
  dmarc: DMARCResult;
}) {
  const renderStatusIcon = (status: string) => {
    if (status === "pass") return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    if (status === "fail") return <XCircle className="h-4 w-4 text-red-500" />;
    return <AlertCircle className="h-4 w-4 text-yellow-500" />;
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>SPF</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-baseline gap-2">
            {renderStatusIcon(spf.status)}
            <span className="font-medium">Status: {spf.status}</span>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            Domain: {spf.domain} IP: {spf.ip}
          </p>
          <p className="mt-2 text-xs opacity-70">
            Record: {spf.record?.substring(0, 80) || ""}{(spf.record?.length || 0) > 80 ? "..." : ""}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>DKIM</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-baseline gap-2">
            {renderStatusIcon(dkim.status)}
            <span className="font-medium">Status: {dkim.status}</span>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            Domain: {dkim.domain} Selector: {dkim.selector}
          </p>
          <p className="mt-2 text-xs opacity-70">{dkim.details}</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>DMARC</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-baseline gap-2">
            {renderStatusIcon(dmarc.status)}
            <span className="font-medium">Status: {dmarc.status}</span>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            Domain: {dmarc.domain} Policy: {dmarc.policy}
          </p>
          <p className="mt-2 text-xs opacity-70">
            Alignment: SPF={dmarc.alignment_spf ? "pass" : "fail"}, DKIM={
              dmarc.alignment_dkim ? "pass" : "fail"
            }
          </p>
          <p className="mt-2 text-xs opacity-70">
            Record: {dmarc.record?.substring(0, 80) || ""}{(dmarc.record?.length || 0) > 80 ? "..." : ""}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}