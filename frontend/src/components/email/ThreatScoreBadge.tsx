import { getSeverityColor, getSeverityBg } from '@/lib/utils';

export default function ThreatScoreBadge({ score }: { score: number }) {
  const color = getSeverityColor(score);
  const bg = getSeverityBg(score);

  return (
    <div className={`flex flex-col items-center justify-center w-24 h-24 rounded-full border-4 shadow-lg ${bg.replace('bg-', 'border-')} bg-background`}>
      <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Risk</span>
      <span className={`text-3xl font-bold ${color}`}>{score}</span>
    </div>
  );
}
