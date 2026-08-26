import { X, ExternalLink, ShieldAlert, Globe, Server, Mail, Building, Users } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { GraphNode } from '../../types/graph';

interface NodeDetailPanelProps {
  node: GraphNode;
  onClose: () => void;
}

export default function NodeDetailPanel({
  node,
  onClose,
}: NodeDetailPanelProps) {
  const getIcon = () => {
    switch (node.type) {
      case 'email':
        return <Mail className="h-5 w-5 text-blue-400" />;
      case 'domain':
        return <Globe className="h-5 w-5 text-purple-400" />;
      case 'ip':
        return <Server className="h-5 w-5 text-red-400" />;
      case 'asn':
        return <Building className="h-5 w-5 text-emerald-400" />;
      case 'registrar':
        return <Building className="h-5 w-5 text-amber-400" />;
      case 'campaign':
        return <Users className="h-5 w-5 text-pink-400" />;
      default:
        return <Globe className="h-5 w-5 text-slate-400" />;
    }
  };

  const getCleanEmailId = (idStr: string) => {
    return idStr.replace('email:', '');
  };

  return (
    <div className="w-80 md:w-96 bg-card/95 backdrop-blur border-l border-border h-full flex flex-col shadow-2xl z-10 animate-in slide-in-from-right duration-200">
      {/* Panel Header */}
      <div className="p-4 border-b border-border flex items-center justify-between bg-muted/40">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="p-1.5 rounded-md bg-background border border-border shrink-0">
            {getIcon()}
          </div>
          <div className="min-w-0">
            <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground block">
              {node.type} Node
            </span>
            <h3 className="text-sm font-semibold truncate text-foreground" title={node.label}>
              {node.label}
            </h3>
          </div>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} className="h-8 w-8 text-muted-foreground hover:text-foreground">
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* Panel Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        {/* Risk Score Banner */}
        {node.risk_score !== undefined && node.risk_score !== null && (
          <div className="flex items-center justify-between p-3 rounded-lg bg-background border border-border">
            <div className="flex items-center gap-2 text-muted-foreground">
              <ShieldAlert className="h-4 w-4 text-amber-500" />
              <span className="font-medium">Threat Risk Score</span>
            </div>
            <Badge
              variant={node.risk_score >= 80 ? 'destructive' : node.risk_score >= 50 ? 'outline' : 'secondary'}
              className="text-xs font-bold px-2 py-0.5"
            >
              {Math.round(node.risk_score)} / 100
            </Badge>
          </div>
        )}

        {/* Email Node Details */}
        {node.type === 'email' && (
          <div className="space-y-3">
            <div>
              <span className="text-muted-foreground block text-[11px] mb-1">Subject</span>
              <p className="font-medium text-foreground bg-background p-2.5 rounded border border-border/60">
                {node.subject || node.label}
              </p>
            </div>
            <div>
              <span className="text-muted-foreground block text-[11px] mb-1">Sender</span>
              <p className="font-mono text-[11px] text-foreground bg-background p-2 rounded border border-border/60 break-all">
                {node.sender || 'Unknown'}
              </p>
            </div>
            {node.analyzed_at && (
              <div>
                <span className="text-muted-foreground block text-[11px] mb-1">Analyzed At</span>
                <p className="text-foreground">{new Date(node.analyzed_at).toLocaleString()}</p>
              </div>
            )}
            <div className="pt-2">
              <Link to={`/emails/${getCleanEmailId(node.id)}`}>
                <Button className="w-full gap-2 h-9 text-xs" size="sm">
                  View Full Forensics Analysis
                  <ExternalLink className="h-3.5 w-3.5" />
                </Button>
              </Link>
            </div>
          </div>
        )}

        {/* IP Node Details */}
        {node.type === 'ip' && (
          <div className="space-y-2.5">
            <div className="grid grid-cols-2 gap-2">
              <div className="p-2.5 bg-background rounded border border-border/60">
                <span className="text-muted-foreground block text-[10px]">Country</span>
                <span className="font-semibold text-foreground">{node.country || 'Unknown'}</span>
              </div>
              <div className="p-2.5 bg-background rounded border border-border/60">
                <span className="text-muted-foreground block text-[10px]">City</span>
                <span className="font-semibold text-foreground">{node.city || 'Unknown'}</span>
              </div>
            </div>
            <div className="p-2.5 bg-background rounded border border-border/60">
              <span className="text-muted-foreground block text-[10px]">ISP / Organization</span>
              <span className="font-medium text-foreground">{node.isp || 'Unknown'}</span>
            </div>
            {node.infrastructure_type && node.infrastructure_type !== 'unknown' && (
              <div className="flex items-center justify-between p-2 bg-amber-500/10 border border-amber-500/30 rounded text-amber-400">
                <span>Infrastructure Type:</span>
                <Badge variant="outline" className="text-[10px] uppercase font-bold border-amber-500/40 text-amber-400">
                  {node.infrastructure_type}
                </Badge>
              </div>
            )}
          </div>
        )}

        {/* Domain Node Details */}
        {node.type === 'domain' && (
          <div className="space-y-2.5">
            <div className="p-2.5 bg-background rounded border border-border/60">
              <span className="text-muted-foreground block text-[10px]">Domain Name</span>
              <span className="font-mono font-medium text-foreground">{node.label}</span>
            </div>
            <div className="p-2.5 bg-background rounded border border-border/60">
              <span className="text-muted-foreground block text-[10px]">Registrar</span>
              <span className="font-medium text-foreground">{node.registrar || 'Unknown'}</span>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="p-2.5 bg-background rounded border border-border/60">
                <span className="text-muted-foreground block text-[10px]">Domain Age</span>
                <span className="font-semibold text-foreground">
                  {node.age_days !== undefined && node.age_days >= 0 ? `${node.age_days} days` : 'Unknown'}
                </span>
              </div>
              <div className="p-2.5 bg-background rounded border border-border/60">
                <span className="text-muted-foreground block text-[10px]">Newly Registered</span>
                <span className={`font-bold ${node.is_newly_registered ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {node.is_newly_registered ? 'Yes (< 30 days)' : 'No'}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* ASN Node Details */}
        {node.type === 'asn' && (
          <div className="space-y-2.5">
            <div className="p-2.5 bg-background rounded border border-border/60">
              <span className="text-muted-foreground block text-[10px]">Autonomous System</span>
              <span className="font-mono font-medium text-foreground">{node.label}</span>
            </div>
            <div className="p-2.5 bg-background rounded border border-border/60">
              <span className="text-muted-foreground block text-[10px]">Organization</span>
              <span className="font-medium text-foreground">{node.org || 'Unknown'}</span>
            </div>
          </div>
        )}

        {/* Campaign Node Details */}
        {node.type === 'campaign' && (
          <div className="space-y-3">
            <div className="p-3 bg-pink-500/10 border border-pink-500/30 rounded-lg">
              <span className="text-pink-400 font-bold block text-xs mb-1">
                Campaign Confidence: {node.confidence || 85}%
              </span>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                {node.summary || 'Coordinated attack campaign detected across shared threat infrastructure.'}
              </p>
            </div>

            <div className="p-2.5 bg-background rounded border border-border/60">
              <span className="text-muted-foreground block text-[10px]">Correlated Email Cases</span>
              <span className="font-bold text-foreground text-sm">{node.email_count || 2} emails linked</span>
            </div>
          </div>
        )}

        {/* Raw Attributes Dump for Deep Investigation */}
        <div className="pt-2 border-t border-border">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block mb-1.5">
            Node Attributes
          </span>
          <div className="bg-slate-950 p-2.5 rounded border border-border font-mono text-[10px] text-slate-300 max-h-36 overflow-y-auto space-y-1">
            <div>ID: {node.id}</div>
            <div>Type: {node.type}</div>
            {Object.entries(node)
              .filter(([k]) => !['id', 'type', 'label', 'color', 'val', 'x', 'y', 'vx', 'vy'].includes(k))
              .map(([k, v]) => (
                <div key={k} className="truncate">
                  {k}: {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                </div>
              ))}
          </div>
        </div>
      </div>
    </div>
  );
}
