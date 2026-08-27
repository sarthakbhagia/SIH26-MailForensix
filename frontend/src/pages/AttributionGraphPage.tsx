import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Network, Users, Share2, Layers, RefreshCw, AlertCircle } from 'lucide-react';
import { api } from '../lib/api';
import AttributionGraph from '../components/graph/AttributionGraph';
import GraphControls from '../components/graph/GraphControls';
import NodeDetailPanel from '../components/graph/NodeDetailPanel';
import CampaignCanvas from '../components/graph/CampaignCanvas';
import { Button } from '../components/ui/button';
import { GraphNode, GraphLink, GraphFilters, GraphNodeType } from '../types/graph';
import { cn } from '../lib/utils';

const defaultFilters: GraphFilters = {
  searchQuery: '',
  nodeTypes: {
    email: true,
    domain: true,
    ip: true,
    asn: true,
    registrar: true,
    campaign: true,
  },
  minRiskScore: 0,
  selectedCampaignId: null,
};

export default function AttributionGraphPage() {
  const [activeTab, setActiveTab] = useState<'graph' | 'campaigns'>('graph');
  const [filters, setFilters] = useState<GraphFilters>(defaultFilters);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  // Fetch full attribution graph and campaign data
  const {
    data: graphResponse,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['attribution-graph'],
    queryFn: async () => {
      const res = await api.getGraph();
      return res.data;
    },
    staleTime: 30000,
  });

  const rawNodes: GraphNode[] = graphResponse?.nodes || [];
  const rawLinks: GraphLink[] = graphResponse?.links || [];
  const campaigns = graphResponse?.campaigns || [];
  const stats = graphResponse?.stats || {
    node_count: 0,
    edge_count: 0,
    density: 0,
    connected_components: 0,
    email_count: 0,
    campaign_count: 0,
  };

  // Apply filters to nodes and prune dangling links
  const filteredGraphData = useMemo(() => {
    if (!rawNodes.length) return { nodes: [], links: [] };

    const searchLower = filters.searchQuery.toLowerCase().trim();

    // 1. Filter Nodes
    const visibleNodes = rawNodes.filter((node) => {
      // Type filter
      if (!filters.nodeTypes[node.type as GraphNodeType]) {
        return false;
      }

      // Risk score filter (only applied if node has a risk score)
      if (node.risk_score !== undefined && node.risk_score !== null) {
        if (node.risk_score < filters.minRiskScore) {
          return false;
        }
      }

      // Campaign filter
      if (filters.selectedCampaignId) {
        const camp = campaigns.find((c) => c.campaign_id === filters.selectedCampaignId);
        if (camp) {
          const isCampNode = node.id === `campaign:${camp.campaign_id}`;
          const isMemberEmail = camp.email_ids.some((eid) => node.id === `email:${eid}`);
          const isSharedIP = camp.shared_indicators.ips.some((ip) => node.id === `ip:${ip}`);
          const isSharedDomain = camp.shared_indicators.domains.some((d) => node.id === `domain:${d}`);
          if (!isCampNode && !isMemberEmail && !isSharedIP && !isSharedDomain) {
            return false;
          }
        }
      }

      // Search text filter
      if (searchLower) {
        const matchLabel = (node.label || '').toLowerCase().includes(searchLower);
        const matchId = node.id.toLowerCase().includes(searchLower);
        const matchSubj = (node.subject || '').toLowerCase().includes(searchLower);
        const matchSender = (node.sender || '').toLowerCase().includes(searchLower);
        const matchIsp = (node.isp || '').toLowerCase().includes(searchLower);
        if (!matchLabel && !matchId && !matchSubj && !matchSender && !matchIsp) {
          return false;
        }
      }

      return true;
    });

    const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));

    // 2. Filter Links (both source and target must be visible)
    const visibleLinks = rawLinks.filter((link) => {
      const srcId = typeof link.source === 'object' ? (link.source as any).id : link.source;
      const tgtId = typeof link.target === 'object' ? (link.target as any).id : link.target;
      return visibleNodeIds.has(srcId) && visibleNodeIds.has(tgtId);
    });

    return {
      nodes: visibleNodes,
      links: visibleLinks,
    };
  }, [rawNodes, rawLinks, filters, campaigns]);

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(graphResponse, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `threat_attribution_graph_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleResetFilters = () => {
    setFilters(defaultFilters);
    setSelectedNode(null);
  };

  const handleSelectCampaignFromCanvas = (campaignId: string) => {
    setFilters((prev) => ({ ...prev, selectedCampaignId: campaignId }));
    setActiveTab('graph');
  };

  return (
    <div className="flex flex-col h-[calc(100vh-5.5rem)] space-y-3 max-w-7xl mx-auto pb-6">
      {/* Header & Stats Badges */}
      <div className="panel p-4 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <Share2 className="size-5 text-primary" />
            Threat Attribution Graph
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Cross-email correlation engine detecting shared infrastructure, relays, and campaign clusters.
          </p>
        </div>

        {/* View Toggle Tabs */}
        <div className="flex items-center gap-1.5 bg-surface-2 p-1 rounded border border-border">
          <button
            onClick={() => setActiveTab('graph')}
            className={cn(
              'px-3 py-1 rounded text-xs font-mono font-semibold flex items-center gap-1.5 transition-all',
              activeTab === 'graph' ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <Network className="size-3.5" />
            ATTRIBUTION GRAPH
          </button>
          <button
            onClick={() => setActiveTab('campaigns')}
            className={cn(
              'px-3 py-1 rounded text-xs font-mono font-semibold flex items-center gap-1.5 transition-all',
              activeTab === 'campaigns' ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <Users className="size-3.5" />
            CAMPAIGN CLUSTERS ({campaigns.length})
          </button>
        </div>
      </div>

      {/* Stats Summary Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 shrink-0">
        <div className="panel p-3 flex items-center gap-3">
          <div className="p-2 rounded bg-primary/10 text-primary border border-primary/20">
            <Network className="size-4" />
          </div>
          <div>
            <span className="label-mono text-[9px] block">TOTAL ENTITIES</span>
            <span className="text-base font-bold font-mono text-foreground">{stats.node_count}</span>
          </div>
        </div>

        <div className="panel p-3 flex items-center gap-3">
          <div className="p-2 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Share2 className="size-4" />
          </div>
          <div>
            <span className="label-mono text-[9px] block">CORRELATION EDGES</span>
            <span className="text-base font-bold font-mono text-foreground">{stats.edge_count}</span>
          </div>
        </div>

        <div className="panel p-3 flex items-center gap-3">
          <div className="p-2 rounded bg-clean/10 text-clean border border-clean/20">
            <Layers className="size-4" />
          </div>
          <div>
            <span className="label-mono text-[9px] block">ANALYZED EVIDENCE</span>
            <span className="text-base font-bold font-mono text-foreground">{stats.email_count}</span>
          </div>
        </div>

        <div className="panel p-3 flex items-center gap-3">
          <div className="p-2 rounded bg-pink-500/10 text-pink-400 border border-pink-500/20">
            <Users className="size-4" />
          </div>
          <div>
            <span className="label-mono text-[9px] block">ATTRIBUTION CAMPAIGNS</span>
            <span className="text-base font-bold font-mono text-foreground">{stats.campaign_count}</span>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      {isLoading ? (
        <div className="panel flex-1 flex flex-col items-center justify-center p-12 text-center">
          <RefreshCw className="size-8 text-primary animate-spin mb-3" />
          <p className="text-sm font-semibold text-foreground">Extracting Graph Topology...</p>
          <p className="label-mono text-[10px] text-muted-foreground mt-1">Cross-referencing IOCs and relay nodes</p>
        </div>
      ) : isError ? (
        <div className="panel flex-1 flex flex-col items-center justify-center p-12 text-center border-critical/40">
          <AlertCircle className="size-10 text-critical mb-3" />
          <h3 className="text-base font-semibold text-foreground">Failed to Load Graph</h3>
          <p className="text-xs text-muted-foreground max-w-sm mt-1 mb-4">
            {error instanceof Error ? error.message : 'An unexpected error occurred while communicating with the server.'}
          </p>
          <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-2 text-xs font-mono border-border">
            <RefreshCw className="size-3.5" />
            Retry
          </Button>
        </div>
      ) : activeTab === 'campaigns' ? (
        <div className="flex-1 overflow-y-auto pr-1">
          <CampaignCanvas campaigns={campaigns} onSelectCampaign={handleSelectCampaignFromCanvas} />
        </div>
      ) : (
        <div className="flex-1 flex flex-col min-h-0">
          <GraphControls
            filters={filters}
            onFilterChange={setFilters}
            campaigns={campaigns}
            onExportJson={handleExportJson}
            onReset={handleResetFilters}
          />
          <div className="flex-1 flex min-h-0 relative">
            <AttributionGraph
              graphData={filteredGraphData}
              selectedNodeId={selectedNode?.id}
              highlightCampaignId={filters.selectedCampaignId}
              onNodeClick={(node) => setSelectedNode(node)}
              onBackgroundClick={() => setSelectedNode(null)}
            />
            {selectedNode && (
              <NodeDetailPanel
                node={selectedNode}
                onClose={() => setSelectedNode(null)}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

