import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, XCircle, AlertCircle, HelpCircle, ShieldCheck, ShieldAlert, Shield } from "lucide-react";

export type AuthStatus = "pass" | "fail" | "softfail" | "neutral" | "none" | "unavailable";

export interface SPFResult {
  status: AuthStatus;
  domain: string;
  ip?: string;
  record?: string;
  details?: string;
}

export interface DKIMResult {
  status: AuthStatus;
  domain: string;
  selector?: string;
  details?: string;
}

export interface DMARCResult {
  status: AuthStatus;
  policy: "none" | "quarantine" | "reject" | string;
  domain: string;
  alignment_spf?: boolean;
  alignment_dkim?: boolean;
  record?: string;
  details?: string;
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
  const renderBadge = (rawStatus: string) => {
    const s = (rawStatus || "unavailable").toLowerCase();
    switch (s) {
      case "pass":
        return (
          <Badge className="bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 flex items-center gap-1 font-semibold uppercase text-xs">
            <CheckCircle2 className="h-3.5 w-3.5" />
            PASS
          </Badge>
        );
      case "fail":
        return (
          <Badge className="bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/30 flex items-center gap-1 font-semibold uppercase text-xs">
            <XCircle className="h-3.5 w-3.5" />
            FAIL
          </Badge>
        );
      case "softfail":
        return (
          <Badge className="bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30 flex items-center gap-1 font-semibold uppercase text-xs">
            <AlertCircle className="h-3.5 w-3.5" />
            SOFTFAIL
          </Badge>
        );
      case "neutral":
        return (
          <Badge className="bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30 flex items-center gap-1 font-semibold uppercase text-xs">
            <AlertCircle className="h-3.5 w-3.5" />
            NEUTRAL
          </Badge>
        );
      case "none":
        return (
          <Badge variant="outline" className="bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/20 flex items-center gap-1 font-medium uppercase text-xs">
            <HelpCircle className="h-3.5 w-3.5" />
            NONE
          </Badge>
        );
      case "unavailable":
      default:
        return (
          <Badge variant="outline" className="bg-muted text-muted-foreground border-border flex items-center gap-1 font-medium uppercase text-xs">
            <HelpCircle className="h-3.5 w-3.5" />
            UNAVAILABLE
          </Badge>
        );
    }
  };

  return (
    <div className="space-y-4">
      {/* SPF Card */}
      <Card className="border border-border shadow-sm">
        <CardHeader className="pb-2 pt-4 px-4 flex flex-row items-center justify-between space-y-0">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <CardTitle className="text-sm font-semibold tracking-wide uppercase">SPF Verification</CardTitle>
          </div>
          {renderBadge(spf?.status)}
        </CardHeader>
        <CardContent className="px-4 pb-4 pt-1 text-xs space-y-2">
          <div className="grid grid-cols-2 gap-2 text-muted-foreground">
            <div>
              <span className="font-medium text-foreground">Domain: </span>
              {spf?.domain || "Unavailable"}
            </div>
            <div>
              <span className="font-medium text-foreground">Sender IP: </span>
              {spf?.ip || "Unavailable"}
            </div>
          </div>
          {spf?.details && (
            <p className="text-xs text-muted-foreground font-mono bg-muted/40 p-1.5 rounded border border-border/50">
              {spf.details}
            </p>
          )}
          {spf?.record && (
            <p className="text-[11px] font-mono text-muted-foreground/80 break-all bg-muted/20 p-1.5 rounded">
              <span className="font-semibold text-foreground/80">Record: </span>
              {spf.record.substring(0, 120)}{spf.record.length > 120 ? "..." : ""}
            </p>
          )}
        </CardContent>
      </Card>

      {/* DKIM Card */}
      <Card className="border border-border shadow-sm">
        <CardHeader className="pb-2 pt-4 px-4 flex flex-row items-center justify-between space-y-0">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-primary" />
            <CardTitle className="text-sm font-semibold tracking-wide uppercase">DKIM Signature</CardTitle>
          </div>
          {renderBadge(dkim?.status)}
        </CardHeader>
        <CardContent className="px-4 pb-4 pt-1 text-xs space-y-2">
          <div className="grid grid-cols-2 gap-2 text-muted-foreground">
            <div>
              <span className="font-medium text-foreground">Domain: </span>
              {dkim?.domain || "Unavailable"}
            </div>
            <div>
              <span className="font-medium text-foreground">Selector: </span>
              {dkim?.selector || "Unavailable"}
            </div>
          </div>
          {dkim?.details && (
            <p className="text-xs text-muted-foreground font-mono bg-muted/40 p-1.5 rounded border border-border/50">
              {dkim.details}
            </p>
          )}
        </CardContent>
      </Card>

      {/* DMARC Card */}
      <Card className="border border-border shadow-sm">
        <CardHeader className="pb-2 pt-4 px-4 flex flex-row items-center justify-between space-y-0">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-primary" />
            <CardTitle className="text-sm font-semibold tracking-wide uppercase">DMARC Policy</CardTitle>
          </div>
          {renderBadge(dmarc?.status)}
        </CardHeader>
        <CardContent className="px-4 pb-4 pt-1 text-xs space-y-2">
          <div className="grid grid-cols-2 gap-2 text-muted-foreground">
            <div>
              <span className="font-medium text-foreground">Domain: </span>
              {dmarc?.domain || "Unavailable"}
            </div>
            <div>
              <span className="font-medium text-foreground">Policy: </span>
              <span className="uppercase font-mono font-semibold">{dmarc?.policy || "none"}</span>
            </div>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono">
            <span>
              SPF Alignment:{" "}
              <strong className={dmarc?.alignment_spf ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"}>
                {dmarc?.alignment_spf ? "PASS" : "FAIL"}
              </strong>
            </span>
            <span>
              DKIM Alignment:{" "}
              <strong className={dmarc?.alignment_dkim ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"}>
                {dmarc?.alignment_dkim ? "PASS" : "FAIL"}
              </strong>
            </span>
          </div>
          {dmarc?.details && (
            <p className="text-xs text-muted-foreground font-mono bg-muted/40 p-1.5 rounded border border-border/50">
              {dmarc.details}
            </p>
          )}
          {dmarc?.record && (
            <p className="text-[11px] font-mono text-muted-foreground/80 break-all bg-muted/20 p-1.5 rounded">
              <span className="font-semibold text-foreground/80">Record: </span>
              {dmarc.record.substring(0, 120)}{dmarc.record.length > 120 ? "..." : ""}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}