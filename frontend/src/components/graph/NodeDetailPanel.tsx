import { X, ExternalLink, ShieldAlert, Globe, Server, Mail, Building, Users } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button } from '../ui/button';
import { GraphNode } from '../../types/graph';
import { cn } from '../../lib/utils';

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
        return <Mail className="size-4 text-primary" />;
      case 'domain':
        return <Globe className="size-4 text-purple-400" />;
      case 'ip':
        return <Server className="size-4 text-critical" />;
      case 'asn':
        return <Building className="size-4 text-clean" />;
      case 'registrar':
        return <Building className="size-4 text-amber-400" />;
      case 'campaign':
        return <Users className="size-4 text-pink-400" />;
      default:
        return <Globe className="size-4 text-muted-foreground" />;
    }
  };

  const getCleanEmailId = (idStr: string) => {
    return idStr.replace('email:', '');
  };

  return (
    <div className="w-80 md:w-96 panel h-full flex flex-col shadow-2xl z-10 animate-in slide-in-from-right duration-200 border-l border-border p-0">
      {/* Panel Header */}
      <div className="p-3.5 border-b border-border/50 flex items-center justify-between bg-surface-2/60">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="p-1.5 rounded bg-surface border border-border shrink-0">
            {getIcon()}
          </div>
          <div className="min-w-0">
            <span className="label-mono text-[9px] block">
              {node.type} NODE
            </span>
            <h3 className="text-xs font-bold truncate text-foreground font-mono" title={node.label}>
              {node.label}
            </h3>
          </div>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} className="h-7 w-7 text-muted-foreground hover:text-foreground">
          <X className="size-4" />
        </Button>
      </div>

      {/* Panel Body */}
      <div className="flex-1 overflow-y-auto p-3.5 space-y-3.5 text-xs">
        {/* Risk Score Banner */}
        {node.risk_score !== undefined && node.risk_score !== null && (
          <div className="flex items-center justify-between p-2.5 rounded bg-surface border border-border">
            <div className="flex items-center gap-2 text-muted-foreground">
              <ShieldAlert className="size-3.5 text-medium" />
              <span className="label-mono text-[10px]">THREAT RISK SCORE</span>
            </div>
            <span
              className={cn(
                'font-mono text-xs font-bold px-2 py-0.5 rounded border',
                node.risk_score >= 75
                  ? 'bg-critical/15 text-critical border-critical/30'
                  : node.risk_score >= 50
                  ? 'bg-high/15 text-high border-high/30'
                  : 'bg-clean/15 text-clean border-clean/30'
              )}
            >
              {Math.round(node.risk_score)} / 100
            </span>
          </div>
        )}

        {/* Email Node Details */}
        {node.type === 'email' && (
          <div className="space-y-2.5">
            <div>
              <span className="label-mono text-[9px] block mb-1">SUBJECT</span>
              <p className="font-medium text-foreground bg-surface p-2.5 rounded border border-border text-xs">
                {node.subject || node.label}
              </p>
            </div>
            <div>
              <span className="label-mono text-[9px] block mb-1">SENDER</span>
              <p className="font-mono text-xs text-foreground bg-surface p-2 rounded border border-border break-all">
                {node.sender || 'Unknown'}
              </p>
            </div>
            {node.analyzed_at && (
              <div>
                <span className="label-mono text-[9px] block mb-1">ANALYZED AT</span>
                <p className="text-foreground font-mono text-xs">{new Date(node.analyzed_at).toLocaleString()}</p>
              </div>
            )}
            <div className="pt-2">
              <Link to={`/emails/${getCleanEmailId(node.id)}`}>
                <Button className="w-full gap-2 h-8 text-xs font-mono font-semibold" size="sm">
                  VIEW FULL FORENSICS
                  <ExternalLink className="size-3.5" />
                </Button>
              </Link>
            </div>
          </div>
        )}

        {/* IP Node Details */}
        {node.type === 'ip' && (
          <div className="space-y-2.5">
            <div className="grid grid-cols-2 gap-2">
              <div className="p-2 bg-surface rounded border border-border">
                <span className="label-mono text-[9px] block">COUNTRY</span>
                <span className="font-semibold text-foreground text-xs">{node.country || 'Unknown'}</span>
              </div>
              <div className="p-2 bg-surface rounded border border-border">
                <span className="label-mono text-[9px] block">CITY</span>
                <span className="font-semibold text-foreground text-xs">{node.city || 'Unknown'}</span>
              </div>
            </div>
            <div className="p-2 bg-surface rounded border border-border">
              <span className="label-mono text-[9px] block">ISP / ORGANIZATION</span>
              <span className="font-mono text-xs text-foreground">{node.isp || 'Unknown'}</span>
            </div>
            {node.infrastructure_type && node.infrastructure_type !== 'unknown' && (
              <div className="flex items-center justify-between p-2 bg-amber-500/10 border border-amber-500/30 rounded text-amber-400 font-mono text-xs">
                <span>Infrastructure:</span>
                <span className="uppercase font-bold text-[10px]">
                  {node.infrastructure_type}
                </span>
              </div>
            )}
          </div>
        )}

        {/* Domain Node Details */}
        {node.type === 'domain' && (
          <div className="space-y-2.5">
            <div className="p-2.5 bg-surface rounded border border-border">
              <span className="label-mono text-[9px] block">DOMAIN NAME</span>
              <span className="font-mono font-medium text-foreground text-xs">{node.label}</span>
            </div>
            <div className="p-2.5 bg-surface rounded border border-border">
              <span className="label-mono text-[9px] block">REGISTRAR</span>
              <span className="font-mono text-xs text-foreground">{node.registrar || 'Unknown'}</span>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="p-2 bg-surface rounded border border-border">
                <span className="label-mono text-[9px] block">DOMAIN AGE</span>
                <span className="font-mono text-xs font-semibold text-foreground">
                  {node.age_days !== undefined && node.age_days >= 0 ? `${node.age_days}d` : 'Unknown'}
                </span>
              </div>
              <div className="p-2 bg-surface rounded border border-border">
                <span className="label-mono text-[9px] block">NEWLY REGISTERED</span>
                <span className={cn('font-mono text-xs font-bold', node.is_newly_registered ? 'text-critical' : 'text-clean')}>
                  {node.is_newly_registered ? 'YES (< 30d)' : 'NO'}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* ASN Node Details */}
        {node.type === 'asn' && (
          <div className="space-y-2.5">
            <div className="p-2.5 bg-surface rounded border border-border">
              <span className="label-mono text-[9px] block">AUTONOMOUS SYSTEM</span>
              <span className="font-mono font-medium text-foreground text-xs">{node.label}</span>
            </div>
            <div className="p-2.5 bg-surface rounded border border-border">
              <span className="label-mono text-[9px] block">ORGANIZATION</span>
              <span className="font-medium text-foreground text-xs">{node.org || 'Unknown'}</span>
            </div>
          </div>
        )}

        {/* Campaign Node Details */}
        {node.type === 'campaign' && (
          <div className="space-y-3">
            <div className="p-3 bg-pink-500/10 border border-pink-500/30 rounded">
              <span className="text-pink-400 font-bold font-mono block text-xs mb-1">
                CAMPAIGN CONFIDENCE: {node.confidence || 85}%
              </span>
              <p className="text-foreground/90 text-xs leading-relaxed">
                {node.summary || 'Coordinated attack campaign detected across shared threat infrastructure.'}
              </p>
            </div>

            <div className="p-2.5 bg-surface rounded border border-border">
              <span className="label-mono text-[9px] block">CORRELATED EMAIL EVIDENCE</span>
              <span className="font-mono font-bold text-foreground text-xs">{node.email_count || 2} emails linked</span>
            </div>
          </div>
        )}

        {/* Raw Attributes Dump for Deep Investigation */}
        <div className="pt-2 border-t border-border/50">
          <span className="label-mono text-[9px] block mb-1.5">
            NODE METADATA ATTRIBUTES
          </span>
          <div className="bg-background/80 p-2.5 rounded border border-border font-mono text-[10px] text-muted-foreground max-h-36 overflow-y-auto space-y-0.5">
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

