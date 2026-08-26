import { Users, Clock, Network, Globe, Server, ArrowRight } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../ui/card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Campaign } from '../../types/graph';

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
      <div className="flex flex-col items-center justify-center p-12 bg-card border border-border rounded-lg text-center">
        <Users className="h-12 w-12 text-muted-foreground/50 mb-3" />
        <h3 className="text-base font-semibold text-foreground">No Campaign Clusters Detected</h3>
        <p className="text-sm text-muted-foreground max-w-md mt-1">
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
          <Card key={camp.campaign_id} className="border-border hover:border-pink-500/50 transition-all shadow-sm flex flex-col justify-between">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <Badge variant="outline" className="bg-pink-500/10 text-pink-400 border-pink-500/30 text-xs font-semibold">
                  {camp.attribution}
                </Badge>
                <Badge variant={isHighConfidence ? 'destructive' : 'secondary'} className="text-[10px] font-bold">
                  {camp.confidence}% Confidence
                </Badge>
              </div>
              <CardTitle className="text-base text-foreground flex items-center gap-2">
                <Network className="h-4 w-4 text-pink-400 shrink-0" />
                <span>{camp.email_ids.length} Correlated Emails</span>
              </CardTitle>
              <CardDescription className="text-xs line-clamp-2 mt-1">
                {camp.summary}
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-3 pt-0 text-xs">
              {/* Metrics Row */}
              <div className="grid grid-cols-2 gap-2 py-2 border-y border-border/60 text-muted-foreground">
                <div className="flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                  <span>Duration: <strong className="text-foreground">{camp.temporal_span_hours}h</strong></span>
                </div>
                <div>
                  <span>Content Sim: <strong className="text-foreground">{Math.round(camp.content_similarity * 100)}%</strong></span>
                </div>
              </div>

              {/* Shared Indicators Badges */}
              <div className="space-y-1.5">
                <span className="text-[11px] font-medium text-muted-foreground block">Shared Infrastructure:</span>
                <div className="flex flex-wrap gap-1.5 max-h-20 overflow-y-auto">
                  {camp.shared_indicators.ips.map((ip) => (
                    <span key={ip} className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 text-[10px] font-mono">
                      <Server className="h-2.5 w-2.5" />
                      {ip}
                    </span>
                  ))}
                  {camp.shared_indicators.domains.map((dom) => (
                    <span key={dom} className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 text-[10px] font-mono">
                      <Globe className="h-2.5 w-2.5" />
                      {dom}
                    </span>
                  ))}
                </div>
              </div>

              {/* Action Button */}
              <div className="pt-2">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => onSelectCampaign(camp.campaign_id)}
                  className="w-full gap-1.5 text-xs font-medium hover:bg-primary hover:text-primary-foreground transition-colors"
                >
                  Inspect in Attribution Graph
                  <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
