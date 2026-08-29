import { getSeverityTokens } from '@/lib/severity';

export default function ThreatScoreBadge({ score }: { score: number }) {
  const tokens = getSeverityTokens(score);

  return (
    <div className={`flex flex-col items-center justify-center w-20 h-20 rounded border-2 shadow-sm ${tokens.borderColor} ${tokens.bgColor} bg-surface`}>
      <span className="label-mono text-[10px]">RISK</span>
      <span className={`text-2xl font-bold font-mono tabular-nums ${tokens.textColor}`}>{score}</span>
    </div>
  );
}
