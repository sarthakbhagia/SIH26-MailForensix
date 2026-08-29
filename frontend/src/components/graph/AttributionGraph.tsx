import { useRef, useCallback, useMemo, useState, useEffect } from 'react';
import ForceGraph2D, { ForceGraphMethods } from 'react-force-graph-2d';
import {
  ZoomIn,
  ZoomOut,
  RotateCcw,
  ShieldAlert,
} from 'lucide-react';
import { GraphNode, GraphLink } from '@/types/graph';

export interface AttributionGraphProps {
  graphData: {
    nodes: GraphNode[];
    links: GraphLink[];
  };
  selectedNodeId?: string | null;
  highlightCampaignId?: string | null;
  onNodeClick?: (node: GraphNode) => void;
  onBackgroundClick?: () => void;
  width?: number;
  height?: number;
}

const TYPE_PALETTE: Record<string, string> = {
  email: '#00e5ff',     // Cyan
  domain: '#a78bfa',    // Soft Indigo/Purple
  ip: '#ff2a55',        // Crimson Red
  asn: '#10b981',       // Emerald Clean
  registrar: '#f59e0b', // Amber
  campaign: '#ec4899',  // Pink/Magenta
  hash: '#eab308',      // Gold
};

export default function AttributionGraph({
  graphData,
  selectedNodeId,
  highlightCampaignId,
  onNodeClick,
  onBackgroundClick,
  width,
  height,
}: AttributionGraphProps) {
  const fgRef = useRef<ForceGraphMethods>();
  const [hoverNode, setHoverNode] = useState<GraphNode | null>(null);

  // Focus on selected node when selectedNodeId changes
  useEffect(() => {
    if (selectedNodeId && fgRef.current) {
      const node = graphData.nodes.find((n) => n.id === selectedNodeId);
      if (node && node.x !== undefined && node.y !== undefined) {
        fgRef.current.centerAt(node.x, node.y, 700);
        fgRef.current.zoom(2.2, 700);
      }
    }
  }, [selectedNodeId, graphData.nodes]);

  // Zoom controls
  const handleZoomIn = () => {
    if (fgRef.current) {
      const currentZoom = fgRef.current.zoom();
      fgRef.current.zoom(currentZoom * 1.3, 400);
    }
  };

  const handleZoomOut = () => {
    if (fgRef.current) {
      const currentZoom = fgRef.current.zoom();
      fgRef.current.zoom(currentZoom / 1.3, 400);
    }
  };

  const handleZoomToFit = () => {
    if (fgRef.current) {
      fgRef.current.zoomToFit(600, 50);
    }
  };

  // Compute 1-hop neighborhood of hovered or selected node
  const focusNodeId = hoverNode?.id || selectedNodeId;

  const connectedNodeIds = useMemo(() => {
    const set = new Set<string>();
    if (focusNodeId) {
      set.add(focusNodeId);
      graphData.links.forEach((link) => {
        const srcId = typeof link.source === 'object' ? (link.source as any).id : link.source;
        const tgtId = typeof link.target === 'object' ? (link.target as any).id : link.target;
        if (srcId === focusNodeId) set.add(tgtId);
        if (tgtId === focusNodeId) set.add(srcId);
      });
    }
    return set;
  }, [focusNodeId, graphData.links]);

  const activeLinks = useMemo(() => {
    const set = new Set<GraphLink>();
    if (focusNodeId) {
      graphData.links.forEach((link) => {
        const srcId = typeof link.source === 'object' ? (link.source as any).id : link.source;
        const tgtId = typeof link.target === 'object' ? (link.target as any).id : link.target;
        if (srcId === focusNodeId || tgtId === focusNodeId) {
          set.add(link);
        }
      });
    }
    return set;
  }, [focusNodeId, graphData.links]);

  // Custom Node Canvas Painter
  const drawNode = useCallback(
    (node: GraphNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const x = node.x || 0;
      const y = node.y || 0;
      const isSelected = selectedNodeId === node.id;
      const isHovered = hoverNode?.id === node.id;
      const isConnected = connectedNodeIds.size === 0 || connectedNodeIds.has(node.id);
      const isCampaignMatch = highlightCampaignId && node.type === 'campaign' && node.id.includes(highlightCampaignId);

      const color = node.color || TYPE_PALETTE[node.type] || '#64748b';
      const baseRadius = node.type === 'campaign' ? 14 : node.type === 'email' ? 10 : node.type === 'domain' ? 8 : 6.5;
      const radius = isSelected || isHovered ? baseRadius * 1.35 : baseRadius;

      ctx.save();
      ctx.globalAlpha = isConnected ? 1.0 : 0.15;

      // Selection or Campaign Highlight Ring
      if (isSelected || isCampaignMatch || isHovered) {
        ctx.beginPath();
        ctx.arc(x, y, radius + 5, 0, 2 * Math.PI, false);
        ctx.fillStyle = isCampaignMatch ? 'rgba(236, 72, 153, 0.25)' : 'rgba(0, 229, 255, 0.25)';
        ctx.fill();
        ctx.lineWidth = 2;
        ctx.strokeStyle = isCampaignMatch ? '#ec4899' : '#00e5ff';
        ctx.stroke();
      }

      // Draw Shape based on Type
      ctx.fillStyle = color;
      ctx.strokeStyle = isSelected ? '#ffffff' : 'rgba(255, 255, 255, 0.6)';
      ctx.lineWidth = isSelected ? 2 : 1;

      if (node.type === 'ip') {
        // Diamond for IP
        ctx.beginPath();
        ctx.moveTo(x, y - radius * 1.1);
        ctx.lineTo(x + radius * 1.1, y);
        ctx.lineTo(x, y + radius * 1.1);
        ctx.lineTo(x - radius * 1.1, y);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      } else if (node.type === 'domain') {
        // Hexagon for Domain
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
          const angle = (Math.PI / 3) * i;
          const px = x + radius * Math.cos(angle);
          const py = y + radius * Math.sin(angle);
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      } else if (node.type === 'asn') {
        // Square for ASN
        ctx.fillRect(x - radius * 0.8, y - radius * 0.8, radius * 1.6, radius * 1.6);
        ctx.strokeRect(x - radius * 0.8, y - radius * 0.8, radius * 1.6, radius * 1.6);
      } else if (node.type === 'registrar') {
        // Triangle for Registrar
        ctx.beginPath();
        ctx.moveTo(x, y - radius * 1.1);
        ctx.lineTo(x + radius * 1.1, y + radius * 0.9);
        ctx.lineTo(x - radius * 1.1, y + radius * 0.9);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      } else {
        // Circle (Email, Campaign)
        ctx.beginPath();
        ctx.arc(x, y, radius, 0, 2 * Math.PI, false);
        ctx.fill();
        ctx.stroke();
      }

      // Campaign member count inner label
      if (node.type === 'campaign' && node.email_count) {
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${Math.max(8, radius * 0.75)}px JetBrains Mono, monospace`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(String(node.email_count), x, y);
      }

      // High-Contrast Monospace Text Label
      if (globalScale > 1.0 || isHovered || isSelected) {
        const label = node.label || node.id;
        const fontSize = Math.max(9, Math.min(13, 11 / globalScale));
        ctx.font = `${isSelected || isHovered ? 'bold ' : ''}${fontSize}px JetBrains Mono, monospace`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';

        // Background chip
        const textWidth = ctx.measureText(label).width;
        ctx.fillStyle = 'rgba(12, 14, 20, 0.85)';
        ctx.fillRect(x - textWidth / 2 - 3, y + radius + 4, textWidth + 6, fontSize + 4);
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.15)';
        ctx.strokeRect(x - textWidth / 2 - 3, y + radius + 4, textWidth + 6, fontSize + 4);

        ctx.fillStyle = '#f8fafc';
        ctx.fillText(label, x, y + radius + 6);
      }

      ctx.restore();
    },
    [selectedNodeId, highlightCampaignId, hoverNode, connectedNodeIds]
  );

  // Custom Link Canvas Painter
  const drawLink = useCallback(
    (link: GraphLink, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const src = link.source as any;
      const tgt = link.target as any;
      if (!src || !tgt || src.x === undefined || tgt.x === undefined) return;

      const isConnected = activeLinks.size === 0 || activeLinks.has(link);
      const isDirectFocus = activeLinks.has(link);

      ctx.save();
      ctx.globalAlpha = isConnected ? (isDirectFocus ? 1.0 : 0.45) : 0.08;

      let strokeColor = '#475569';
      let isDashed = false;
      let lineWidth = Math.max(1, (link.weight || 1) * 1.2);

      if (link.relationship === 'sent_from') {
        strokeColor = '#00e5ff';
      } else if (link.relationship === 'relayed_through') {
        strokeColor = '#f97316';
        isDashed = true;
      } else if (
        link.relationship === 'shares_infrastructure' ||
        link.relationship === 'shares_ip' ||
        link.relationship === 'shares_domain'
      ) {
        strokeColor = '#ff2a55';
        lineWidth = Math.max(2, (link.weight || 1) * 2);
      } else if (link.relationship === 'in_campaign') {
        strokeColor = '#ec4899';
        isDashed = true;
      }

      ctx.beginPath();
      if (isDashed) {
        ctx.setLineDash([4, 3]);
      } else {
        ctx.setLineDash([]);
      }

      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = lineWidth;
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.stroke();

      // Draw edge relationship label when hovered
      if (isDirectFocus && globalScale > 0.85) {
        const midX = (src.x + tgt.x) / 2;
        const midY = (src.y + tgt.y) / 2;
        ctx.font = '9px JetBrains Mono, monospace';
        ctx.fillStyle = '#cbd5e1';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(link.relationship.replace(/_/g, ' '), midX, midY - 6);
      }

      ctx.restore();
    },
    [activeLinks]
  );

  return (
    <div className="relative w-full h-full panel bg-[#0c0e14] overflow-hidden p-0 border border-border">
      {graphData.nodes.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-full text-muted-foreground p-8">
          <ShieldAlert className="size-8 opacity-40 mb-2" />
          <p className="text-sm font-semibold text-foreground">No Correlated Entities in Current Scope</p>
          <p className="label-mono text-[10px] mt-0.5">Adjust search query or category filters to display correlation graph.</p>
        </div>
      ) : (
        <>
          <ForceGraph2D
            ref={fgRef as any}
            graphData={graphData}
            width={width}
            height={height}
            nodeCanvasObject={drawNode as any}
            linkCanvasObject={drawLink as any}
            nodePointerAreaPaint={(node: any, color, ctx) => {
              ctx.fillStyle = color;
              ctx.beginPath();
              ctx.arc(node.x, node.y, 16, 0, 2 * Math.PI, false);
              ctx.fill();
            }}
            onNodeClick={(node: any) => onNodeClick && onNodeClick(node as GraphNode)}
            onNodeHover={(node: any) => setHoverNode(node ? (node as GraphNode) : null)}
            onBackgroundClick={() => onBackgroundClick && onBackgroundClick()}
            cooldownTicks={120}
            d3AlphaDecay={0.025}
            d3VelocityDecay={0.35}
            enableNodeDrag={true}
          />

          {/* Floating Canvas Navigation Toolbar */}
          <div className="absolute top-3 left-3 flex items-center gap-1 p-1 rounded border border-border bg-surface/90 backdrop-blur z-10 shadow-md">
            <button
              onClick={handleZoomIn}
              className="p-1.5 rounded hover:bg-surface-2 text-muted-foreground hover:text-foreground transition-colors"
              title="Zoom in"
            >
              <ZoomIn className="size-3.5" />
            </button>
            <button
              onClick={handleZoomOut}
              className="p-1.5 rounded hover:bg-surface-2 text-muted-foreground hover:text-foreground transition-colors"
              title="Zoom out"
            >
              <ZoomOut className="size-3.5" />
            </button>
            <button
              onClick={handleZoomToFit}
              className="p-1.5 rounded hover:bg-surface-2 text-muted-foreground hover:text-foreground transition-colors"
              title="Fit all entities"
            >
              <RotateCcw className="size-3.5" />
            </button>
          </div>

          {/* Color-Coded Entity Legend */}
          <div className="absolute bottom-3 left-3 panel bg-background/90 backdrop-blur p-2.5 text-xs text-foreground shadow-2xl space-y-1.5 pointer-events-none border border-border select-none">
            <div className="label-mono font-bold text-foreground mb-1 text-[9px]">ENTITY TOPOLOGY</div>
            <div className="flex items-center gap-2 font-mono text-[10px]">
              <span className="size-2 rounded-full bg-[#00e5ff]" />
              <span>Email Artifact</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[10px]">
              <span className="size-2 rotate-45 bg-[#a78bfa]" />
              <span>Domain</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[10px]">
              <span className="size-2 rotate-45 bg-[#ff2a55]" />
              <span>Relay IP</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[10px]">
              <span className="size-2 bg-[#10b981]" />
              <span>ASN</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[10px]">
              <span className="size-2 border-b-4 border-l-2 border-r-2 border-transparent border-b-[#f59e0b]" />
              <span>Registrar</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[10px]">
              <span className="size-2 rounded-full ring-2 ring-[#ec4899] bg-transparent" />
              <span>Campaign Cluster</span>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
