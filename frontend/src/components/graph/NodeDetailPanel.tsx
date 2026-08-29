import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  X,
  ExternalLink,
  ShieldAlert,
  Globe,
  Server,
  Mail,
  Building,
  Users,
  FolderPlus,
  Copy,
  Check,
  ArrowRight,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { GraphNode, GraphLink } from '@/types/graph';
import { cn, safeFormatDate } from '@/lib/utils';
import { getSeverityTokens } from '@/lib/severity';

export interface NodeDetailPanelProps {
  node: GraphNode;
  onClose: () => void;
  allLinks?: GraphLink[];
  allNodes?: GraphNode[];
  onSelectNode?: (node: GraphNode) => void;
}

export function NodeDetailPanel({
  node,
  onClose,
  allLinks = [],
  allNodes = [],
  onSelectNode,
}: NodeDetailPanelProps) {
  const navigate = useNavigate();
  const [copiedText, setCopiedText] = useState(false);

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

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(true);
    setTimeout(() => setCopiedText(false), 1800);
  };

  // Connected 1-hop neighbor nodes
  const connectedNeighbors = allLinks
    .filter((l) => {
      const srcId = typeof l.source === 'object' ? (l.source as any).id : l.source;
      const tgtId = typeof l.target === 'object' ? (l.target as any).id : l.target;
      return srcId === node.id || tgtId === node.id;
    })
    .map((l) => {
      const srcId = typeof l.source === 'object' ? (l.source as any).id : l.source;
      const tgtId = typeof l.target === 'object' ? (l.target as any).id : l.target;
      const otherId = srcId === node.id ? tgtId : srcId;
      const targetNode = allNodes.find((n) => n.id === otherId);
      return {
        relationship: l.relationship,
        targetNode: targetNode || { id: otherId, label: otherId, type: 'domain' as const, color: '#a78bfa', val: 5 },
      };
    });

  const getExternalLookupUrl = (rawVal: string, type: string) => {
    const encoded = encodeURIComponent(rawVal.trim());
    if (type === 'ip') return `https://www.virustotal.com/gui/ip-address/${encoded}`;
    if (type === 'domain') return `https://www.virustotal.com/gui/domain/${encoded}`;
    if (type === 'hash') return `https://www.virustotal.com/gui/file/${encoded}`;
    return `https://www.virustotal.com/gui/search/${encoded}`;
  };

  return (
    <div className="w-80 md:w-96 panel h-full flex flex-col shadow-2xl z-20 animate-in slide-in-from-right duration-200 border-l border-border p-0 bg-surface">
      {/* Panel Header */}
      <div className="p-3.5 border-b border-border/50 flex items-center justify-between bg-surface-2/60">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="p-1.5 rounded bg-surface border border-border shrink-0">
            {getIcon()}
          </div>
          <div className="min-w-0">
            <span className="label-mono text-[9px] block uppercase">
              {node.type} ENTITY
            </span>
            <h3 className="text-xs font-bold truncate text-foreground font-mono" title={node.label}>
              {node.label}
            </h3>
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={() => handleCopy(node.label || node.id)}
            className="p-1 rounded text-muted-foreground hover:text-foreground hover:bg-surface-2 transition-colors"
            title="Copy value"
          >
            {copiedText ? <Check className="size-3.5 text-clean" /> : <Copy className="size-3.5" />}
          </button>
          <Button variant="ghost" size="icon" onClick={onClose} className="h-7 w-7 text-muted-foreground hover:text-foreground">
            <X className="size-4" />
          </Button>
        </div>
      </div>

      {/* Panel Body */}
      <div className="flex-1 overflow-y-auto p-3.5 space-y-3.5 text-xs font-mono">
        {/* Risk Score Banner */}
        {node.risk_score !== undefined && node.risk_score !== null && (
          <div className="flex items-center justify-between p-2.5 rounded bg-surface-2 border border-border">
            <div className="flex items-center gap-2 text-muted-foreground">
              <ShieldAlert className="size-3.5 text-critical" />
              <span className="label-mono text-[10px]">THREAT RISK SCORE</span>
            </div>
            {(() => {
              const tokens = getSeverityTokens(node.risk_score);
              return (
                <span className={cn('font-mono text-xs font-bold px-2 py-0.5 rounded border tabular-nums', tokens.badgeClass)}>
                  {Math.round(node.risk_score)} / 100
                </span>
              );
            })()}
          </div>
        )}

        {/* Email Node Details */}
        {node.type === 'email' && (
          <div className="space-y-2.5">
            <div>
              <span className="label-mono text-[9px] block mb-1">SUBJECT</span>
              <p className="font-medium text-foreground bg-surface-2 p-2.5 rounded border border-border text-xs break-words">
                {node.subject || node.label}
              </p>
            </div>
            <div>
              <span className="label-mono text-[9px] block mb-1">SENDER</span>
              <p className="text-xs text-foreground bg-surface-2 p-2 rounded border border-border break-all">
                {node.sender || 'Unknown'}
              </p>
            </div>
            {node.analyzed_at && (
              <div>
                <span className="label-mono text-[9px] block mb-1">INGESTED TIMESTAMP</span>
                <p className="text-foreground text-xs">{safeFormatDate(node.analyzed_at)}</p>
              </div>
            )}
            <div className="pt-2 flex flex-col gap-2">
              <Button
                onClick={() => navigate(`/emails/${getCleanEmailId(node.id)}`)}
                className="w-full gap-2 h-8 text-xs font-mono font-semibold bg-primary text-primary-foreground"
                size="sm"
              >
                <span>OPEN INVESTIGATION WORKSTATION</span>
                <ExternalLink className="size-3.5" />
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate(`/cases?new=true&title=${encodeURIComponent(`Investigate Email: ${node.subject || node.label}`)}`)}
                className="w-full gap-1.5 h-7 text-xs font-mono border-border"
              >
                <FolderPlus className="size-3 text-muted-foreground" />
                <span>Attach to Case</span>
              </Button>
            </div>
          </div>
        )}

        {/* Domain Node Details */}
        {node.type === 'domain' && (
          <div className="space-y-2.5">
            {node.registrar && (
              <div>
                <span className="label-mono text-[9px] block mb-1">REGISTRAR</span>
                <p className="text-foreground bg-surface-2 p-2 rounded border border-border">{node.registrar}</p>
              </div>
            )}
            {node.created_date && (
              <div>
                <span className="label-mono text-[9px] block mb-1">CREATION DATE</span>
                <p className="text-foreground bg-surface-2 p-2 rounded border border-border">{node.created_date}</p>
              </div>
            )}

            <div className="pt-2 flex flex-col gap-2">
              <a
                href={getExternalLookupUrl(node.label || node.id, 'domain')}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded border border-border bg-surface-2 hover:bg-surface-3 text-xs font-mono font-semibold text-foreground transition-colors"
              >
                <span>VirusTotal Dossier</span>
                <ExternalLink className="size-3 text-primary" />
              </a>

              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate(`/cases?new=true&title=${encodeURIComponent(`Investigate Domain: ${node.label || node.id}`)}`)}
                className="w-full gap-1.5 h-7 text-xs font-mono border-border"
              >
                <FolderPlus className="size-3 text-muted-foreground" />
                <span>Attach to Case</span>
              </Button>
            </div>
          </div>
        )}

        {/* IP Node Details */}
        {node.type === 'ip' && (
          <div className="space-y-2.5">
            {node.country && (
              <div>
                <span className="label-mono text-[9px] block mb-1">GEOLOCATION</span>
                <p className="text-foreground bg-surface-2 p-2 rounded border border-border">
                  {node.country} {node.country_code ? `(${node.country_code})` : ''}
                </p>
              </div>
            )}
            {node.asn && (
              <div>
                <span className="label-mono text-[9px] block mb-1">AUTONOMOUS SYSTEM (ASN)</span>
                <p className="text-foreground bg-surface-2 p-2 rounded border border-border">{node.asn}</p>
              </div>
            )}

            <div className="pt-2 flex flex-col gap-2">
              <a
                href={getExternalLookupUrl(node.label || node.id, 'ip')}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded border border-border bg-surface-2 hover:bg-surface-3 text-xs font-mono font-semibold text-foreground transition-colors"
              >
                <span>AbuseIPDB / VirusTotal</span>
                <ExternalLink className="size-3 text-primary" />
              </a>

              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate(`/cases?new=true&title=${encodeURIComponent(`Investigate IP: ${node.label || node.id}`)}`)}
                className="w-full gap-1.5 h-7 text-xs font-mono border-border"
              >
                <FolderPlus className="size-3 text-muted-foreground" />
                <span>Attach to Case</span>
              </Button>
            </div>
          </div>
        )}

        {/* Campaign Details */}
        {node.type === 'campaign' && (
          <div className="space-y-2.5">
            <div>
              <span className="label-mono text-[9px] block mb-1">CAMPAIGN ATTRIBUTION</span>
              <p className="text-foreground bg-surface-2 p-2.5 rounded border border-border">
                {node.label}
              </p>
            </div>
            {node.email_count && (
              <div>
                <span className="label-mono text-[9px] block mb-1">CORRELATED THREAT CLUSTER</span>
                <p className="text-primary font-bold">{node.email_count} emails attributed</p>
              </div>
            )}
          </div>
        )}

        {/* Connected 1-Hop Neighbors List */}
        {connectedNeighbors.length > 0 && (
          <div className="pt-3 border-t border-border/50 space-y-2">
            <span className="label-mono text-[9px] block">
              CORRELATED NEIGHBORS ({connectedNeighbors.length})
            </span>

            <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
              {connectedNeighbors.map((cn, i) => (
                <div
                  key={i}
                  onClick={() => onSelectNode?.(cn.targetNode)}
                  className="p-2 rounded bg-surface-2 hover:bg-surface-3 border border-border/70 flex items-center justify-between gap-2 cursor-pointer transition-colors"
                >
                  <div className="truncate min-w-0">
                    <span className="label-mono text-[8px] block text-muted-foreground">
                      {cn.relationship.replace(/_/g, ' ')}
                    </span>
                    <span className="font-semibold text-foreground truncate block text-xs" title={cn.targetNode.label}>
                      {cn.targetNode.label}
                    </span>
                  </div>
                  <ArrowRight className="size-3 text-muted-foreground shrink-0" />
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default NodeDetailPanel;
