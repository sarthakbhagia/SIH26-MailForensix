import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState, useCallback } from "react";
import {
  ShieldAlert,
  Radar,
  Fingerprint,
  MapPin,
  FileText,
  Network,
  Mail,
  Download,
  Copy,
  Trash2,
  Lock,
  UploadCloud,
  FileUp,
  Loader2,
  CheckCircle2,
  XCircle,
  FileDown as FilePdf,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { RiskGauge, verdictColor } from "@/components/forensics/RiskGauge";
import { TraceMap } from "@/components/forensics/TraceMap";
import {
  analyzeEmailAsync,
  buildReport,
  buildPdfReport,
  SAMPLE_EMAIL,
  type Analysis,
  type Finding,
} from "@/lib/email-forensics";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "MailForensix — Email Threat Detection & Origin Intelligence" },
      {
        name: "description",
        content:
          "Analyse raw email headers to detect phishing, spoofing and BEC, validate SPF/DKIM/DMARC, reconstruct SMTP relay paths, estimate sender geolocation and export forensic reports.",
      },
      { property: "og:title", content: "MailForensix — Email Threat & Origin Intelligence" },
      {
        property: "og:description",
        content:
          "Header forensics, relay-path reconstruction, geolocation estimation and forensic reporting for suspicious email investigation.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

const SEVERITY_TOKEN: Record<Finding["severity"], string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--muted-foreground)",
};

function AuthPill({
  label,
  state,
  dnsState,
}: {
  label: string;
  state: string;
  dnsState?: "verified" | "disagrees" | "pending" | null;
}) {
  const color =
    state === "pass"
      ? "var(--clean)"
      : state === "fail"
        ? "var(--critical)"
        : state === "softfail"
          ? "var(--high)"
          : "var(--muted-foreground)";
  return (
    <div className="panel flex flex-col gap-1.5 px-4 py-3">
      <div className="flex items-center justify-between">
        <span className="label-mono">{label}</span>
        <span className="font-mono text-sm uppercase" style={{ color }}>
          {state}
        </span>
      </div>
      {dnsState && (
        <div className="flex items-center gap-1.5 mt-0.5">
          {dnsState === "pending" ? (
            <><Loader2 className="size-2.5 animate-spin text-muted-foreground" />
            <span className="font-mono text-[0.55rem] text-muted-foreground">dns lookup…</span></>
          ) : dnsState === "verified" ? (
            <><CheckCircle2 className="size-2.5 text-green-500" />
            <span className="font-mono text-[0.55rem] text-green-500">dns verified</span></>
          ) : (
            <><XCircle className="size-2.5 text-red-500" />
            <span className="font-mono text-[0.55rem] text-red-500">dns disagrees</span></>
          )}
        </div>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="panel px-4 py-3">
      <p className="label-mono">{label}</p>
      <p className="mt-1 break-all font-mono text-sm text-foreground">{value}</p>
    </div>
  );
}

function Index() {
  const [inputType, setInputType] = useState<"upload" | "paste">("upload");
  const [raw, setRaw] = useState("");
  const [fileMeta, setFileMeta] = useState<{ name: string; size: number } | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [isPdfGenerating, setIsPdfGenerating] = useState(false);
  const report = useMemo(() => (analysis ? buildReport(analysis) : ""), [analysis]);

  const run = useCallback(async (input: string) => {
    const source = input.trim();
    if (!source) return;
    setIsRunning(true);
    // Set initial synchronous analysis immediately for fast perceived feedback,
    // then update with async enriched version once live lookups complete.
    try {
      const enriched = await analyzeEmailAsync(source);
      setAnalysis(enriched);
    } finally {
      setIsRunning(false);
    }
  }, []);

  const handleFileChange = (file: File | undefined) => {
    if (!file) return;
    setFileMeta({
      name: file.name,
      size: file.size,
    });
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      const parsedText = text || "";
      setRaw(parsedText);
      if (parsedText.trim()) {
        void run(parsedText);
      }
    };
    reader.readAsText(file);
  };

  const handleLoadSample = () => {
    setRaw(SAMPLE_EMAIL);
    setFileMeta(null);
    setInputType("paste");
    void run(SAMPLE_EMAIL);
  };

  const handleClear = () => {
    setRaw("");
    setFileMeta(null);
    setAnalysis(null);
  };

  const download = () => {
    if (!analysis) return;
    const blob = new Blob([report], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `forensic-report-${analysis.id.slice(0, 24) || "case"}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadPdf = async () => {
    if (!analysis || isPdfGenerating) return;
    setIsPdfGenerating(true);
    try {
      const blob = await buildPdfReport(analysis);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `forensic-report-${analysis.id.slice(0, 24) || "case"}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setIsPdfGenerating(false);
    }
  };

  return (
    <main className="mx-auto max-w-7xl px-5 py-10 md:px-8">
      <header className="flex flex-col gap-6 border-b border-border pb-8 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="label-mono flex items-center gap-2">
            <Radar className="size-3.5 text-primary" /> forensic intelligence console
          </p>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight md:text-4xl">
            MailForensix — Email Threat Detection, Geolocation &amp; Forensics
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted-foreground">
            Submit a raw email (headers and body) or upload an EML file to validate sender
            authentication, reconstruct the SMTP relay chain, extract indicators of compromise,
            estimate probable origin, and generate an evidentiary report. Analysis runs entirely in
            your browser.
          </p>
        </div>
        <div className="panel flex items-center gap-3 px-4 py-3">
          <Lock className="size-4 text-primary" />
          <div>
            <p className="label-mono">privacy mode</p>
            <p className="font-mono text-xs text-foreground">Local processing · no upload</p>
          </div>
        </div>
      </header>

      <section className="mt-8 grid gap-6 lg:grid-cols-[1.35fr_1fr]">
        <div className="panel p-5">
          <div className="flex items-center justify-between mb-4">
            <p className="label-mono flex items-center gap-2">
              <Radar className="size-3.5 text-primary" /> raw message input
            </p>
            <div className="flex gap-2">
              <Button variant="ghost" size="sm" onClick={handleLoadSample}>
                Load sample case
              </Button>
              <Button variant="ghost" size="sm" onClick={handleClear} disabled={!raw && !fileMeta}>
                <Trash2 className="size-3.5" /> Clear
              </Button>
            </div>
          </div>

          <Tabs
            value={inputType}
            onValueChange={(val) => setInputType(val as "upload" | "paste")}
            className="w-full"
          >
            <TabsList className="grid w-full grid-cols-2 mb-4">
              <TabsTrigger value="upload" className="flex items-center gap-2">
                <FileUp className="size-3.5" /> Upload EML File
              </TabsTrigger>
              <TabsTrigger value="paste" className="flex items-center gap-2">
                <Mail className="size-3.5" /> Paste Raw Text
              </TabsTrigger>
            </TabsList>

            <TabsContent value="upload" className="outline-none">
              {fileMeta ? (
                <div className="flex flex-col items-center justify-center border border-dashed border-primary/50 bg-primary/5 rounded-lg p-10 text-center gap-4 transition-all duration-300">
                  <div className="flex size-14 items-center justify-center rounded-full bg-primary/10 text-primary">
                    <FileText className="size-8" />
                  </div>
                  <div>
                    <p className="font-mono text-sm font-medium text-foreground max-w-xs md:max-w-md truncate">
                      {fileMeta.name}
                    </p>
                    <p className="font-mono text-xs text-muted-foreground mt-1">
                      {(fileMeta.size / 1024).toFixed(2)} KB
                    </p>
                  </div>
                  <div className="flex gap-2 mt-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setFileMeta(null);
                        setRaw("");
                      }}
                    >
                      <Trash2 className="size-3.5 mr-2" /> Remove File
                    </Button>
                  </div>
                </div>
              ) : (
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    setIsDragging(true);
                  }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={(e) => {
                    e.preventDefault();
                    setIsDragging(false);
                    const file = e.dataTransfer.files?.[0];
                    handleFileChange(file);
                  }}
                  onClick={() => document.getElementById("eml-file-input")?.click()}
                  className={`flex flex-col items-center justify-center border-2 border-dashed rounded-lg p-10 text-center cursor-pointer transition-all duration-300 ${
                    isDragging
                      ? "border-primary bg-primary/10 scale-[0.99] shadow-glow"
                      : "border-border hover:border-primary/50 hover:bg-muted/30"
                  }`}
                >
                  <input
                    id="eml-file-input"
                    type="file"
                    accept=".eml,message/rfc822,text/plain"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      handleFileChange(file);
                    }}
                  />
                  <div
                    className={`flex size-14 items-center justify-center rounded-full bg-muted text-muted-foreground mb-4 transition-colors ${isDragging ? "bg-primary/20 text-primary" : ""}`}
                  >
                    <UploadCloud className="size-8" />
                  </div>
                  <p className="text-sm font-medium text-foreground">
                    Drag &amp; drop your .eml file here
                  </p>
                  <p className="text-xs text-muted-foreground mt-1.5">
                    or click to browse from your computer
                  </p>
                  <span className="label-mono mt-4 text-[0.6rem] px-2.5 py-1 rounded bg-muted/50 border">
                    EML &amp; RAW RFC-822 Supported
                  </span>
                </div>
              )}
            </TabsContent>

            <TabsContent value="paste" className="outline-none">
              <Textarea
                value={raw}
                onChange={(e) => setRaw(e.target.value)}
                spellCheck={false}
                placeholder={
                  "Paste the complete email source here — Received headers, Authentication-Results, From, Reply-To, Subject, then the body."
                }
                className="h-64 resize-none bg-background/60 font-mono text-xs leading-relaxed"
              />
            </TabsContent>
          </Tabs>

          <div className="mt-6 flex flex-wrap items-center gap-3">
            <Button onClick={() => void run(raw)} disabled={!raw.trim() || isRunning}>
              {isRunning ? (
                <><Loader2 className="size-4 animate-spin" /> Enriching…</>
              ) : (
                <><Radar className="size-4" /> Analyse message</>
              )}
            </Button>
            {isRunning && (
              <span className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
                <Loader2 className="size-3 animate-spin" />
                Running live DNS · RDAP · geo lookups…
              </span>
            )}
            {!isRunning && (
              <p className="font-mono text-xs text-muted-foreground">
                {raw ? `${raw.split("\n").length} lines · ${raw.length} bytes` : "awaiting input"}
              </p>
            )}
          </div>
        </div>

        <div className="panel flex flex-col items-center justify-center gap-6 p-6">
          {analysis ? (
            <>
              <RiskGauge score={analysis.score} verdict={analysis.verdict} />
              <Separator />
              <div className="w-full space-y-2 text-center">
                <p className="label-mono">attribution assessment</p>
                <p className="text-sm font-medium text-foreground">
                  {analysis.attribution.scenario}
                </p>
                <p className="font-mono text-xs text-primary">
                  {analysis.attribution.confidence}% confidence
                </p>
              </div>
            </>
          ) : (
            <div className="space-y-3 text-center">
              <ShieldAlert className="mx-auto size-10 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                No case loaded. Submit a message to generate a fraud score, trace path and
                attribution assessment.
              </p>
            </div>
          )}
        </div>
      </section>

      {analysis && (
        <section className="mt-8">
          <Tabs defaultValue="overview">
            <TabsList className="flex-wrap">
              <TabsTrigger value="overview">
                <Fingerprint className="size-3.5" /> Overview
              </TabsTrigger>
              <TabsTrigger value="trace">
                <Network className="size-3.5" /> Relay trace
              </TabsTrigger>
              <TabsTrigger value="geo">
                <MapPin className="size-3.5" /> Geolocation
              </TabsTrigger>
              <TabsTrigger value="iocs">
                <ShieldAlert className="size-3.5" /> IOCs
              </TabsTrigger>
              <TabsTrigger value="headers">
                <Mail className="size-3.5" /> Headers
              </TabsTrigger>
              <TabsTrigger value="report">
                <FileText className="size-3.5" /> Report
              </TabsTrigger>
            </TabsList>

            {/* ---------------- overview ---------------- */}
            <TabsContent value="overview" className="mt-6 space-y-6">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <AuthPill
                  label="SPF"
                  state={analysis.auth.spf}
                  dnsState={
                    isRunning ? "pending" :
                    analysis.liveEnrichment
                      ? analysis.findings.some(f => f.id === "dns-spf-disagree")
                        ? "disagrees"
                        : analysis.liveEnrichment.spfDnsRecord !== null
                          ? "verified"
                          : null
                      : null
                  }
                />
                <AuthPill
                  label="DKIM"
                  state={analysis.auth.dkim}
                  dnsState={
                    isRunning ? "pending" :
                    analysis.liveEnrichment
                      ? analysis.findings.some(f => f.id === "dns-dkim-disagree")
                        ? "disagrees"
                        : analysis.liveEnrichment.dkimDnsRecord !== null
                          ? "verified"
                          : null
                      : null
                  }
                />
                <AuthPill label="DMARC" state={analysis.auth.dmarc} />
                <AuthPill label="Alignment" state={analysis.auth.aligned ? "pass" : "fail"} />
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <Metric label="subject" value={analysis.subject} />
                <Metric
                  label="from"
                  value={`${analysis.fromDisplay ? `"${analysis.fromDisplay}" ` : ""}<${analysis.fromAddress ?? "unknown"}>`}
                />
                <Metric label="reply-to" value={analysis.replyTo ?? "not set"} />
                <Metric label="return-path" value={analysis.returnPath ?? "not set"} />
                <Metric label="message-id" value={analysis.messageId ?? "absent"} />
                <Metric label="dkim d= domain" value={analysis.auth.dkimDomain ?? "unsigned"} />
              </div>

              <div>
                <p className="label-mono">findings · {analysis.findings.length} indicator(s)</p>
                <div className="mt-3 space-y-3">
                  {analysis.findings.length === 0 && (
                    <p className="panel px-4 py-6 text-center text-sm text-muted-foreground">
                      No adverse indicators detected. Authentication and routing are consistent with
                      the claimed sender.
                    </p>
                  )}
                  {analysis.findings.map((f) => (
                    <div
                      key={f.id}
                      className="panel border-l-2 px-4 py-3"
                      style={{ borderLeftColor: SEVERITY_TOKEN[f.severity] }}
                    >
                      <div className="flex flex-wrap items-center gap-3">
                        <span
                          className="font-mono text-[0.65rem] uppercase tracking-widest"
                          style={{ color: SEVERITY_TOKEN[f.severity] }}
                        >
                          {f.severity}
                        </span>
                        <span className="label-mono">{f.category}</span>
                        <span className="font-mono text-[0.65rem] text-muted-foreground">
                          +{f.weight} risk
                        </span>
                      </div>
                      <p className="mt-1.5 text-sm font-medium text-foreground">{f.title}</p>
                      <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
                        {f.detail}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="panel p-5">
                <p className="label-mono">attribution rationale</p>
                <ul className="mt-3 space-y-2">
                  {analysis.attribution.rationale.map((r) => (
                    <li key={r} className="flex gap-2 text-sm text-muted-foreground">
                      <span className="text-primary">›</span>
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            </TabsContent>

            {/* ---------------- relay trace ---------------- */}
            <TabsContent value="trace" className="mt-6">
              {analysis.hops.length === 0 ? (
                <p className="panel px-4 py-6 text-center text-sm text-muted-foreground">
                  No Received headers present — the transmission record is absent or was stripped.
                </p>
              ) : (
                <ol className="space-y-4">
                  {[...analysis.hops].reverse().map((hop, i) => (
                    <li key={hop.index} className="panel relative p-5">
                      <div className="flex flex-wrap items-center gap-3">
                        <span className="flex size-7 items-center justify-center rounded-full border border-primary font-mono text-xs text-primary">
                          {i + 1}
                        </span>
                        <span className="label-mono">
                          {i === 0
                            ? "origin node"
                            : i === analysis.hops.length - 1
                              ? "final delivery"
                              : "intermediate relay"}
                        </span>
                        <span className="font-mono text-xs text-muted-foreground">
                          {hop.protocol ? `via ${hop.protocol}` : "protocol unknown"}
                        </span>
                      </div>
                      <div className="mt-3 grid gap-3 md:grid-cols-3">
                        <div>
                          <p className="label-mono">from</p>
                          <p className="break-all font-mono text-sm">{hop.from ?? "—"}</p>
                        </div>
                        <div>
                          <p className="label-mono">ip ({hop.ipClass})</p>
                          <p className="break-all font-mono text-sm text-primary">
                            {hop.ip ?? "—"}
                          </p>
                        </div>
                        <div>
                          <p className="label-mono">received by</p>
                          <p className="break-all font-mono text-sm">{hop.by ?? "—"}</p>
                        </div>
                      </div>
                      {hop.timestamp && (
                        <p className="mt-3 font-mono text-xs text-muted-foreground">
                          {hop.timestamp}
                        </p>
                      )}
                      {hop.notes.map((n) => (
                        <p
                          key={n}
                          className="mt-2 font-mono text-xs"
                          style={{ color: "var(--high)" }}
                        >
                          ⚠ {n}
                        </p>
                      ))}
                    </li>
                  ))}
                </ol>
              )}
            </TabsContent>

            {/* ---------------- geolocation ---------------- */}
            <TabsContent value="geo" className="mt-6 space-y-6">
              <TraceMap origin={analysis.origin} />
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                <Metric label="origin ip" value={analysis.origin.ip ?? "undetermined"} />
                <Metric label="reverse host" value={analysis.origin.reverseHost ?? "n/a"} />
                <Metric
                  label="network / provider"
                  value={analysis.origin.provider ?? "unclassified"}
                />
                <Metric label="infrastructure type" value={analysis.origin.infrastructure} />
              </div>
              <div className="panel p-5">
                <p className="label-mono">estimation basis</p>
                <ul className="mt-3 space-y-2">
                  {analysis.origin.basis.map((b) => (
                    <li key={b} className="flex gap-2 text-sm text-muted-foreground">
                      <span className="text-primary">›</span>
                      {b}
                    </li>
                  ))}
                </ul>
                <p className="mt-4 text-xs leading-relaxed text-muted-foreground">
                  Geolocation reflects network allocation intelligence and may represent
                  intermediary infrastructure rather than the actor's physical position. Treat all
                  values as investigative leads requiring corroboration.
                </p>
              </div>
            </TabsContent>

            {/* ---------------- iocs ---------------- */}
            <TabsContent value="iocs" className="mt-6">
              <div className="panel divide-y divide-border">
                {analysis.iocs.map((ioc, i) => (
                  <div
                    key={`${ioc.type}-${i}`}
                    className="flex flex-wrap items-center gap-4 px-4 py-3"
                  >
                    <span className="label-mono w-24">{ioc.type}</span>
                    <span className="min-w-0 flex-1 break-all font-mono text-sm text-foreground">
                      {ioc.value}
                    </span>
                    <span
                      className="font-mono text-[0.65rem] uppercase tracking-widest"
                      style={{
                        color:
                          ioc.risk === "high"
                            ? "var(--critical)"
                            : ioc.risk === "medium"
                              ? "var(--medium)"
                              : "var(--clean)",
                      }}
                    >
                      {ioc.risk}
                    </span>
                    <span className="w-full text-xs text-muted-foreground md:w-72">{ioc.note}</span>
                  </div>
                ))}
                {analysis.iocs.length === 0 && (
                  <p className="px-4 py-6 text-center text-sm text-muted-foreground">
                    No indicators extracted from this message.
                  </p>
                )}
              </div>
            </TabsContent>

            {/* ---------------- headers ---------------- */}
            <TabsContent value="headers" className="mt-6">
              <div className="panel divide-y divide-border">
                {analysis.headers.map((h, i) => (
                  <div
                    key={`${h.name}-${i}`}
                    className="grid gap-1 px-4 py-3 md:grid-cols-[220px_1fr]"
                  >
                    <span className="label-mono">{h.name}</span>
                    <span className="break-all font-mono text-xs text-foreground">{h.value}</span>
                  </div>
                ))}
              </div>
            </TabsContent>

            {/* ---------------- report ---------------- */}
            <TabsContent value="report" className="mt-6 space-y-4">
              <div className="flex flex-wrap gap-3">
                <Button onClick={download}>
                  <Download className="size-4" /> Download .txt
                </Button>
                <Button onClick={() => void downloadPdf()} disabled={isPdfGenerating}>
                  {isPdfGenerating ? (
                    <><Loader2 className="size-4 animate-spin" /> Generating PDF…</>
                  ) : (
                    <><FilePdf className="size-4" /> Download PDF</>
                  )}
                </Button>
                <Button variant="secondary" onClick={() => navigator.clipboard?.writeText(report)}>
                  <Copy className="size-4" /> Copy to clipboard
                </Button>
                <span
                  className="rounded-md border px-3 py-2 font-mono text-xs"
                  style={{
                    color: verdictColor(analysis.verdict),
                    borderColor: verdictColor(analysis.verdict),
                  }}
                >
                  case {analysis.id.slice(0, 28) || "unreferenced"}
                </span>
              </div>
              <pre className="panel max-h-[36rem] overflow-auto p-5 font-mono text-xs leading-relaxed text-foreground">
                {report}
              </pre>
            </TabsContent>
          </Tabs>
        </section>
      )}

      <footer className="mt-14 border-t border-border pt-6 text-xs leading-relaxed text-muted-foreground">
        Findings are probabilistic investigative indicators, not conclusive proof of identity.
        Preserve the original message and the generated report together to maintain chain of
        custody, and handle personal data in accordance with your organisation's retention and
        privacy policy.
      </footer>
    </main>
  );
}
