import logging
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class CampaignCluster:
    campaign_id: str              # UUID string
    email_ids: List[str]          # Emails in this campaign (clean UUIDs)
    shared_indicators: Dict[str, List[str]]  # {"ips": [...], "domains": [...], "asns": [...]}
    content_similarity: float     # Average pairwise cosine/jaccard similarity (0.0 to 1.0)
    temporal_span_hours: float    # Time between first and last email in cluster
    confidence: float             # 0-100 campaign detection confidence
    attribution: str              # Attribution category
    summary: str                  # Human-readable campaign summary


class CampaignClusterer:
    """Detects coordinated threat campaigns by combining graph community detection with content similarity."""

    SIMILARITY_THRESHOLD = 0.70    # Minimum similarity for strong content linkage
    TEMPORAL_WINDOW_HOURS = 168   # 7-day window for temporal clustering

    def __init__(self, use_transformer: bool = False):
        self.use_transformer = use_transformer
        self.embedder = None

    def _get_embedder(self):
        if not self.use_transformer:
            return None
        if self.embedder is None:
            try:
                from sentence_transformers import SentenceTransformer
                self.embedder = SentenceTransformer("all-MiniLM-L6-v2", local_files_only=True)
            except Exception as e:
                logger.debug(f"SentenceTransformer local load skipped ({e}); using token similarity fallback.")
                self.embedder = False
        return self.embedder

    def cluster(
        self,
        graph: nx.Graph,
        emails: List[Any],
        analysis_results: List[Any],
    ) -> List[CampaignCluster]:
        """Detect campaign clusters using graph community detection + content similarity deterministically."""
        if graph.number_of_nodes() == 0:
            return []

        # 1. Graph Community Detection (Louvain)
        communities = self._detect_communities(graph)

        # 2. Map email bodies and dates by clean email ID
        email_map: Dict[str, dict] = {}
        for em in emails:
            if isinstance(em, dict):
                eid = str(em.get("id", "")).replace("email:", "")
                email_map[eid] = em
            else:
                eid = str(getattr(em, "id", "")).replace("email:", "")
                email_map[eid] = em.__dict__ if hasattr(em, "__dict__") else {}

        analysis_map: Dict[str, dict] = {}
        for a in analysis_results:
            if isinstance(a, dict):
                eid = str(a.get("email_id", "") or a.get("id", "")).replace("email:", "")
                analysis_map[eid] = a
            else:
                eid = str(getattr(a, "email_id", "") or getattr(a, "id", "")).replace("email:", "")
                analysis_map[eid] = a.__dict__ if hasattr(a, "__dict__") else {}

        # 3. Process multi-email communities
        campaigns: List[CampaignCluster] = []
        for comm_id, node_ids in sorted(communities.items(), key=lambda x: str(x[0])):
            email_ids = sorted([n.replace("email:", "") for n in node_ids if graph.nodes[n].get("type") == "email"])
            if len(email_ids) < 2:
                continue

            campaign = self._build_campaign(
                comm_id=str(comm_id),
                email_ids=email_ids,
                graph=graph,
                emails=email_map,
                analysis_results=analysis_map,
            )

            # Report clusters with meaningful confidence
            if campaign.confidence >= 40.0:
                campaigns.append(campaign)

        # Sort campaigns deterministically by confidence (descending), then ID
        campaigns.sort(key=lambda c: (-c.confidence, c.campaign_id))

        # 4. Add campaign nodes and edges back into the graph deterministically
        for camp in campaigns:
            camp_node_id = f"campaign:{camp.campaign_id}"
            max_risk = 0.0
            for eid in camp.email_ids:
                a_data = analysis_map.get(eid, {})
                max_risk = max(max_risk, float(a_data.get("composite_risk_score", 0.0) or 0.0))

            if not graph.has_node(camp_node_id):
                graph.add_node(
                    camp_node_id,
                    type="campaign",
                    label=f"Campaign: {camp.attribution} ({len(camp.email_ids)} emails)",
                    color="#EC4899",
                    risk_score=max_risk,
                    confidence=camp.confidence,
                    email_count=len(camp.email_ids),
                    summary=camp.summary,
                )

            for eid in camp.email_ids:
                email_node_id = f"email:{eid}"
                if graph.has_node(email_node_id) and not graph.has_edge(email_node_id, camp_node_id):
                    graph.add_edge(
                        email_node_id,
                        camp_node_id,
                        relationship="in_campaign",
                        weight=1.0,
                    )

        return campaigns

    def _detect_communities(self, graph: nx.Graph) -> Dict[Any, List[str]]:
        """Run Louvain community detection across the graph deterministically."""
        try:
            import community as community_louvain
            partition = community_louvain.best_partition(graph, weight="weight", resolution=1.0, random_state=42)
            communities: Dict[Any, List[str]] = {}
            for node_id, comm_id in partition.items():
                communities.setdefault(comm_id, []).append(node_id)
            return communities
        except Exception as e:
            logger.debug(f"python-louvain error: {e}. Falling back to NetworkX community or connected components.")

        try:
            from networkx.algorithms.community import louvain_communities
            nx_comms = louvain_communities(graph, weight="weight", seed=42)
            communities = {}
            for i, c_set in enumerate(nx_comms):
                communities[i] = sorted(list(c_set))
            return communities
        except Exception:
            # Fallback to connected components
            communities = {}
            for i, comp in enumerate(nx.connected_components(graph)):
                communities[i] = sorted(list(comp))
            return communities

    def _build_campaign(
        self,
        comm_id: str,
        email_ids: List[str],
        graph: nx.Graph,
        emails: Dict[str, dict],
        analysis_results: Dict[str, dict],
    ) -> CampaignCluster:
        """Construct a detailed CampaignCluster object from community emails."""
        sorted_eids = sorted(email_ids)
        campaign_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"campaign-{comm_id}-" + "-".join(sorted_eids)))

        # 1. Identify shared indicators
        shared_ips: Set[str] = set()
        shared_domains: Set[str] = set()
        shared_asns: Set[str] = set()

        for eid in sorted_eids:
            node_id = f"email:{eid}"
            if graph.has_node(node_id):
                for neighbor in graph.neighbors(node_id):
                    ndata = graph.nodes[neighbor]
                    ntype = ndata.get("type")
                    if ntype == "ip":
                        shared_ips.add(neighbor.replace("ip:", ""))
                    elif ntype == "domain":
                        shared_domains.add(neighbor.replace("domain:", ""))
                    elif ntype == "asn":
                        shared_asns.add(neighbor.replace("asn:", ""))

        # 2. Content similarity
        similarity = self._compute_content_similarity(sorted_eids, emails)

        # 3. Temporal span
        timestamps = []
        for eid in sorted_eids:
            em = emails.get(eid, {})
            ts_str = em.get("ingested_at") or em.get("timestamp")
            if ts_str:
                try:
                    if isinstance(ts_str, datetime):
                        timestamps.append(ts_str)
                    else:
                        dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
                        timestamps.append(dt)
                except Exception:
                    pass

        temporal_span = 0.0
        if len(timestamps) >= 2:
            timestamps.sort()
            delta = (timestamps[-1] - timestamps[0]).total_seconds()
            temporal_span = round(max(0.0, delta / 3600.0), 1)

        # 4. Campaign confidence scoring
        shared_dict = {
            "ips": sorted(list(shared_ips)),
            "domains": sorted(list(shared_domains)),
            "asns": sorted(list(shared_asns)),
        }
        confidence = self._compute_campaign_confidence(
            shared_indicators=shared_dict,
            content_similarity=similarity,
            temporal_span_hours=temporal_span,
            email_count=len(sorted_eids),
        )

        # 5. Attribution categorization & summary
        attribution = self._determine_attribution(shared_dict, similarity, analysis_results, sorted_eids)
        summary = (
            f"Campaign of {len(sorted_eids)} coordinated emails identified via shared "
            f"infrastructure ({len(shared_ips)} IPs, {len(shared_domains)} domains) "
            f"with {similarity * 100:.1f}% content similarity over {temporal_span:.1f} hours."
        )

        return CampaignCluster(
            campaign_id=campaign_id,
            email_ids=sorted_eids,
            shared_indicators=shared_dict,
            content_similarity=round(similarity, 3),
            temporal_span_hours=temporal_span,
            confidence=round(confidence, 1),
            attribution=attribution,
            summary=summary,
        )

    def _compute_content_similarity(
        self,
        email_ids: List[str],
        emails: Dict[str, dict],
    ) -> float:
        """Compute average pairwise cosine or token-set similarity across email body texts."""
        texts = []
        for eid in email_ids:
            em = emails.get(eid, {})
            body = em.get("body_text", "") or em.get("subject", "") or ""
            if body and body.strip():
                texts.append(body.strip())

        if len(texts) < 2:
            return 0.0

        embedder = self._get_embedder()
        if embedder and hasattr(embedder, "encode"):
            try:
                embeddings = embedder.encode(texts, convert_to_tensor=True)
                from sentence_transformers import util
                cos_sim_matrix = util.cos_sim(embeddings, embeddings)
                n = len(texts)
                total_sim = 0.0
                count = 0
                for i in range(n):
                    for j in range(i + 1, n):
                        total_sim += float(cos_sim_matrix[i][j])
                        count += 1
                return total_sim / count if count > 0 else 0.0
            except Exception as e:
                logger.warning(f"Error computing sentence embeddings: {e}")

        # Fallback: Token-based Jaccard similarity
        token_sets = [set(t.lower().split()) for t in texts]
        n = len(token_sets)
        total_sim = 0.0
        count = 0
        for i in range(n):
            for j in range(i + 1, n):
                union_len = len(token_sets[i] | token_sets[j])
                if union_len > 0:
                    sim = len(token_sets[i] & token_sets[j]) / union_len
                    total_sim += sim
                    count += 1
        return total_sim / count if count > 0 else 0.0

    def _compute_campaign_confidence(
        self,
        shared_indicators: Dict[str, List[str]],
        content_similarity: float,
        temporal_span_hours: float,
        email_count: int,
    ) -> float:
        """Score confidence that an email cluster represents an organized threat campaign."""
        score = 0.0

        # Shared infrastructure signals
        if len(shared_indicators.get("ips", [])) >= 1:
            score += 25.0
        if len(shared_indicators.get("domains", [])) >= 1:
            score += 20.0
        if len(shared_indicators.get("asns", [])) >= 1:
            score += 10.0

        # Content similarity
        if content_similarity >= 0.90:
            score += 30.0
        elif content_similarity >= 0.70:
            score += 20.0
        elif content_similarity >= 0.50:
            score += 10.0

        # Temporal burstiness
        if temporal_span_hours <= 1.0:
            score += 15.0
        elif temporal_span_hours <= 24.0:
            score += 10.0
        elif temporal_span_hours <= 168.0:
            score += 5.0

        # Volume bonus
        if email_count >= 5:
            score += 10.0
        elif email_count >= 3:
            score += 5.0

        return min(100.0, max(0.0, score))

    def _determine_attribution(
        self,
        shared_indicators: Dict[str, List[str]],
        similarity: float,
        analysis_results: Dict[str, dict],
        email_ids: List[str],
    ) -> str:
        """Categorize attribution type for the campaign."""
        labels = [analysis_results.get(eid, {}).get("nlp_label", "") for eid in email_ids]
        if any(l in ("BEC/Fraud", "BEC") for l in labels):
            return "BEC/Fraud Ring"
        if any(l == "Impersonation" for l in labels):
            return "Domain Impersonation Campaign"
        if similarity >= 0.85:
            return "Automated Phishing Campaign"
        if len(shared_indicators.get("ips", [])) >= 1:
            return "Shared Infrastructure Cluster"
        return "Coordinated Attack Group"
