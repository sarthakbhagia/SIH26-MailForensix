import { useRef, useCallback, useMemo, useState } from 'react';
import ForceGraph2D, { ForceGraphMethods } from 'react-force-graph-2d';
import { GraphNode, GraphLink, GraphNodeType } from '../../types/graph';

interface AttributionGraphProps {
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

const TYPE_COLORS: Record<GraphNodeType, string> = {
  email: '#00e5ff',     // Cyan
  domain: '#b388ff',    // Purple
  ip: '#ff3366',        // Critical Red
  registrar: '#ffb020', // Amber
  asn: '#00e699',       // Clean Green
  campaign: '#ff4081',  // Pink
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

  // Compute 1-hop neighborhood of hovered node for visual highlighting
  const highlightNodes = useMemo(() => {
    const set = new Set<string>();
    if (hoverNode) {
      set.add(hoverNode.id);
      graphData.links.forEach((link) => {
        const srcId = typeof link.source === 'object' ? (link.source as any).id : link.source;
        const tgtId = typeof link.target === 'object' ? (link.target as any).id : link.target;
        if (srcId === hoverNode.id) set.add(tgtId);
        if (tgtId === hoverNode.id) set.add(srcId);
      });
    }
    return set;
  }, [hoverNode, graphData.links]);

  const highlightLinks = useMemo(() => {
    const set = new Set<GraphLink>();
    if (hoverNode) {
      graphData.links.forEach((link) => {
        const srcId = typeof link.source === 'object' ? (link.source as any).id : link.source;
        const tgtId = typeof link.target === 'object' ? (link.target as any).id : link.target;
        if (srcId === hoverNode.id || tgtId === hoverNode.id) {
          set.add(link);
        }
      });
    }
    return set;
  }, [hoverNode, graphData.links]);

  // Custom Node Canvas Painter
  const drawNode = useCallback(
    (node: GraphNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const x = node.x || 0;
      const y = node.y || 0;
      const isSelected = selectedNodeId === node.id;
      const isHovered = hoverNode?.id === node.id;
      const isHighlighted = highlightNodes.size === 0 || highlightNodes.has(node.id);
      const isCampaignMatch = highlightCampaignId && node.type === 'campaign' && node.id.includes(highlightCampaignId);

      const color = node.color || TYPE_COLORS[node.type] || '#666';
      const baseRadius = node.type === 'campaign' ? 14 : node.type === 'email' ? 10 : node.type === 'domain' ? 8 : 6;
      const radius = isSelected || isHovered ? baseRadius * 1.3 : baseRadius;

      ctx.save();
      ctx.globalAlpha = isHighlighted ? 1.0 : 0.2;

      // Selection or Campaign Glow Ring
      if (isSelected || isCampaignMatch || isHovered) {
        ctx.beginPath();
        ctx.arc(x, y, radius + 4, 0, 2 * Math.PI, false);
        ctx.fillStyle = isCampaignMatch ? 'rgba(236, 72, 153, 0.35)' : 'rgba(59, 130, 246, 0.35)';
        ctx.fill();
        ctx.lineWidth = 2;
        ctx.strokeStyle = isCampaignMatch ? '#EC4899' : '#60A5FA';
        ctx.stroke();
      }

      // Draw Shape based on Type
      ctx.fillStyle = color;
      ctx.strokeStyle = '#FFFFFF';
      ctx.lineWidth = isSelected ? 2 : 1;

      if (node.type === 'ip') {
        // Diamond
        ctx.beginPath();
        ctx.moveTo(x, y - radius);
        ctx.lineTo(x + radius, y);
        ctx.lineTo(x, y + radius);
        ctx.lineTo(x - radius, y);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      } else if (node.type === 'domain') {
        // Hexagon / Rounded Rect
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
        // Square
        ctx.fillRect(x - radius * 0.8, y - radius * 0.8, radius * 1.6, radius * 1.6);
        ctx.strokeRect(x - radius * 0.8, y - radius * 0.8, radius * 1.6, radius * 1.6);
      } else if (node.type === 'registrar') {
        // Triangle
        ctx.beginPath();
        ctx.moveTo(x, y - radius);
        ctx.lineTo(x + radius, y + radius);
        ctx.lineTo(x - radius, y + radius);
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

      // Inner icon / count indicator
      if (node.type === 'campaign' && node.email_count) {
        ctx.fillStyle = '#FFFFFF';
        ctx.font = `bold ${Math.max(8, radius * 0.7)}px sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(String(node.email_count), x, y);
      }

      // Text Label (rendered when zoomed in or hovered/selected)
      if (globalScale > 1.1 || isHovered || isSelected) {
        const label = node.label || node.id;
        const fontSize = Math.max(9, Math.min(14, 12 / globalScale));
        ctx.font = `${isSelected || isHovered ? 'bold ' : ''}${fontSize}px sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';

        // Text background for readability
        const textWidth = ctx.measureText(label).width;
        ctx.fillStyle = 'rgba(15, 23, 42, 0.75)';
        ctx.fillRect(x - textWidth / 2 - 3, y + radius + 3, textWidth + 6, fontSize + 4);

        ctx.fillStyle = '#F8FAFC';
        ctx.fillText(label, x, y + radius + 5);
      }

      ctx.restore();
    },
    [selectedNodeId, highlightCampaignId, hoverNode, highlightNodes]
  );

  // Custom Link Canvas Painter
  const drawLink = useCallback(
    (link: GraphLink, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const src = link.source as any;
      const tgt = link.target as any;
      if (!src || !tgt || src.x === undefined || tgt.x === undefined) return;

      const isHighlighted = highlightLinks.size === 0 || highlightLinks.has(link);
      const isDirectHover = highlightLinks.has(link);

      ctx.save();
      ctx.globalAlpha = isHighlighted ? (isDirectHover ? 1.0 : 0.6) : 0.1;

      // Select Link Color & Pattern
      let strokeColor = '#64748B';
      let isDashed = false;
      let lineWidth = Math.max(1, (link.weight || 1) * 1.5);

      if (link.relationship === 'sent_from') {
        strokeColor = '#3B82F6';
      } else if (link.relationship === 'relayed_through') {
        strokeColor = '#F97316';
        isDashed = true;
      } else if (
        link.relationship === 'shares_infrastructure' ||
        link.relationship === 'shares_ip' ||
        link.relationship === 'shares_domain'
      ) {
        strokeColor = '#EF4444';
        lineWidth = Math.max(2, (link.weight || 1) * 2.5);
      } else if (link.relationship === 'in_campaign') {
        strokeColor = '#EC4899';
        isDashed = true;
      }

      ctx.beginPath();
      if (isDashed) {
        ctx.setLineDash([4, 4]);
      } else {
        ctx.setLineDash([]);
      }

      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = lineWidth;
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.stroke();

      // Draw label on hovered connection
      if (isDirectHover && globalScale > 0.8) {
        const midX = (src.x + tgt.x) / 2;
        const midY = (src.y + tgt.y) / 2;
        ctx.font = '10px sans-serif';
        ctx.fillStyle = '#CBD5E1';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(link.relationship.replace(/_/g, ' '), midX, midY - 6);
      }

      ctx.restore();
    },
    [highlightLinks]
  );

  return (
    <div className="relative w-full h-full panel bg-slate-950 overflow-hidden shadow-inner p-0">
      {graphData.nodes.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-full text-muted-foreground p-8">
          <p className="text-sm font-semibold text-foreground">No Graph Data Available</p>
          <p className="label-mono text-[10px] mt-1">Upload and analyze emails to populate the threat attribution graph.</p>
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
            cooldownTicks={100}
            d3AlphaDecay={0.02}
            d3VelocityDecay={0.3}
            enableNodeDrag={true}
          />

          {/* Color-Coded Legend Overlay */}
          <div className="absolute bottom-3 left-3 panel bg-background/90 backdrop-blur-md p-2.5 text-xs text-foreground shadow-2xl space-y-1.5 pointer-events-none border border-border">
            <div className="label-mono font-bold text-foreground mb-1">ENTITY TOPOLOGY</div>
            <div className="flex items-center gap-2 font-mono text-[10px]">
              <span className="size-2 rounded-full bg-[#00e5ff]" />
              <span>Email Artifact</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[10px]">
              <span className="size-2 rotate-45 bg-[#b388ff]" />
              <span>Sender Domain</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[10px]">
              <span className="size-2 rotate-45 bg-[#ff3366]" />
              <span>Relay IP Address</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[10px]">
              <span className="size-2 bg-[#00e699]" />
              <span>Autonomous System (ASN)</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[10px]">
              <span className="size-2 border-b-4 border-l-2 border-r-2 border-transparent border-b-[#ffb020]" />
              <span>Registrar</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[10px]">
              <span className="size-2 rounded-full ring-2 ring-[#ff4081] bg-transparent" />
              <span>Campaign Cluster</span>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

