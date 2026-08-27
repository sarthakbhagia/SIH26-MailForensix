import { Users, Clock, Network, Globe, Server, ArrowRight } from 'lucide-react';
import { Button } from '../ui/button';
import { Campaign } from '../../types/graph';
import { cn } from '../../lib/utils';

interface CampaignCanvasProps {
  campaigns: Campaign[];
  onSelectCampaign: (campaignId: string) => void;
}

export default function CampaignCanvas({
  campaigns,
  onSelectCampaign,
}: CampaignCanvasProps) {
  if (campaigns.length === 0) {
    return (
      <div className="panel flex flex-col items-center justify-center p-12 text-center">
        <Users className="size-10 text-muted-foreground/40 mb-3" />
        <h3 className="text-base font-semibold text-foreground">No Campaign Clusters Detected</h3>
        <p className="text-xs text-muted-foreground max-w-md mt-1">
          Coordinated email threats sharing common relay IPs, domain registrars, or structural content will be automatically clustered here.
        </p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {campaigns.map((camp) => {
        const isHighConfidence = camp.confidence >= 75;
        return (
          <div key={camp.campaign_id} className="panel p-4 hover:border-pink-500/50 transition-all flex flex-col justify-between space-y-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded bg-pink-500/10 text-pink-400 border border-pink-500/30">
                  {camp.attribution}
                </span>
                <span
                  className={cn(
                    'font-mono text-[10px] font-bold px-1.5 py-0.5 rounded border',
                    isHighConfidence ? 'bg-critical/15 text-critical border-critical/30' : 'bg-high/15 text-high border-high/30'
                  )}
                >
                  {camp.confidence}% CONFIDENCE
                </span>
              </div>

              <div className="flex items-center gap-2 pt-1">
                <Network className="size-4 text-pink-400 shrink-0" />
                <h4 className="font-bold text-sm text-foreground">{camp.email_ids.length} Correlated Emails</h4>
              </div>

              <p className="text-xs text-muted-foreground line-clamp-2">
                {camp.summary}
              </p>
            </div>

            <div className="space-y-3 pt-2 text-xs border-t border-border/50">
              {/* Metrics Row */}
              <div className="grid grid-cols-2 gap-2 py-1 font-mono text-[11px] text-muted-foreground">
                <div className="flex items-center gap-1.5">
                  <Clock className="size-3 text-muted-foreground" />
                  <span>SPAN: <strong className="text-foreground">{camp.temporal_span_hours}h</strong></span>
                </div>
                <div>
                  <span>SIMILARITY: <strong className="text-foreground">{Math.round(camp.content_similarity * 100)}%</strong></span>
                </div>
              </div>

              {/* Shared Indicators Badges */}
              <div className="space-y-1.5">
                <span className="label-mono text-[9px] block">SHARED INFRASTRUCTURE:</span>
                <div className="flex flex-wrap gap-1.5 max-h-20 overflow-y-auto">
                  {camp.shared_indicators.ips.map((ip) => (
                    <span key={ip} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-critical/10 text-critical border border-critical/20 text-[10px] font-mono">
                      <Server className="size-2.5" />
                      {ip}
                    </span>
                  ))}
                  {camp.shared_indicators.domains.map((dom) => (
                    <span key={dom} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 text-[10px] font-mono">
                      <Globe className="size-2.5" />
                      {dom}
                    </span>
                  ))}
                </div>
              </div>

              {/* Action Button */}
              <div className="pt-1">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => onSelectCampaign(camp.campaign_id)}
                  className="w-full gap-1.5 text-xs font-mono font-semibold border-border bg-surface hover:bg-primary hover:text-primary-foreground transition-colors"
                >
                  <span>INSPECT ATTRIBUTION GRAPH</span>
                  <ArrowRight className="size-3.5" />
                </Button>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

