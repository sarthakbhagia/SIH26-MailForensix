import type { Verdict } from "@/lib/email-forensics";

const VERDICT_LABEL: Record<Verdict, string> = {
  legitimate: "Legitimate",
  suspicious: "Suspicious",
  impersonation: "Impersonation",
  phishing: "Phishing",
  fraud: "Fraud / BEC",
};

export function verdictColor(verdict: Verdict) {
  if (verdict === "fraud") return "var(--critical)";
  if (verdict === "phishing") return "var(--high)";
  if (verdict === "impersonation") return "var(--medium)";
  if (verdict === "suspicious") return "var(--low)";
  return "var(--clean)";
}

export function RiskGauge({ score, verdict }: { score: number; verdict: Verdict }) {
  const r = 62;
  const c = 2 * Math.PI * r;
  const dash = (Math.min(100, Math.max(0, score)) / 100) * c;
  const color = verdictColor(verdict);

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative">
        <svg width="156" height="156" viewBox="0 0 156 156" className="-rotate-90">
          <circle cx="78" cy="78" r={r} fill="none" stroke="var(--muted)" strokeWidth="12" />
          <circle
            cx="78"
            cy="78"
            r={r}
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${c}`}
            style={{ transition: "stroke-dasharray 700ms ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-4xl font-semibold" style={{ color }}>
            {score}
          </span>
          <span className="label-mono">risk / 100</span>
        </div>
      </div>
      <div
        className="rounded-full border px-4 py-1 font-mono text-xs uppercase tracking-widest"
        style={{ color, borderColor: color }}
      >
        {VERDICT_LABEL[verdict]}
      </div>
    </div>
  );
}
