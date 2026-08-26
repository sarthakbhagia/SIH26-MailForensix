import ipaddress
import logging
import re
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    id: str                   # Unique node ID e.g., "email:uuid", "ip:1.2.3.4", "domain:evil.com"
    type: str                 # "email" | "domain" | "ip" | "registrar" | "asn" | "campaign"
    label: str                # Human-readable display label
    attributes: Dict[str, Any]
    risk_score: Optional[float]
    color: str                # Hex color for visualization


@dataclass
class GraphEdge:
    source: str               # Source node ID
    target: str               # Target node ID
    relationship: str         # "sent_from" | "relayed_through" | "registered_by" | "belongs_to_asn" | "shares_infrastructure" | "shares_ip" | "shares_domain" | "in_campaign"
    weight: float             # Strength / weight of relationship (0.1 to 1.0)
    attributes: Dict[str, Any]


@dataclass
class AttributionGraph:
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    communities: List[Dict[str, Any]]
    graph_stats: Dict[str, Any]
    json_data: Dict[str, Any]


class GraphEngine:
    """Constructs deterministic multi-entity threat attribution graphs connecting emails, domains, IPs, ASNs, registrars, and campaigns."""

    NODE_COLORS = {
        "email": "#3B82F6",      # Blue
        "domain": "#8B5CF6",     # Purple
        "ip": "#EF4444",         # Red
        "registrar": "#F59E0B",  # Amber
        "asn": "#10B981",        # Emerald
        "campaign": "#EC4899",   # Pink
    }

    def __init__(self):
        self.graph = nx.Graph()

    def build(self, *args, **kwargs) -> Any:
        """Backward-compatible stub alias."""
        return self.to_json()

    @staticmethod
    def _clean_domain(sender_or_domain: Optional[str]) -> Optional[str]:
        """Extract canonical lowercase registered domain from sender or domain string."""
        if not sender_or_domain:
            return None
        text = str(sender_or_domain).strip()
        # Extract email from <user@domain.com>
        if "<" in text and ">" in text:
            m = re.search(r"<([^>]+)>", text)
            if m:
                text = m.group(1).strip()
        if "@" in text:
            text = text.split("@")[-1].strip()
        
        text = text.rstrip(".").lower()
        # Filter invalid dummy domains
        if not text or text in ("unknown-domain", "unknown", "n/a", "none", "localhost"):
            return None
        if "." not in text:
            return None
        return text

    RFC1918_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("0.0.0.0/8"),
    ]

    @classmethod
    def _is_public_ip(cls, ip_str: Optional[str]) -> bool:
        """Check if an IP string is a routable/public IP address (not RFC1918 private or loopback)."""
        if not ip_str:
            return False
        try:
            ip_obj = ipaddress.ip_address(str(ip_str).strip())
            for net in cls.RFC1918_NETWORKS:
                if ip_obj in net:
                    return False
            return True
        except ValueError:
            return False

    @staticmethod
    def _clean_asn(asn_val: Any) -> Optional[str]:
        """Extract canonical numeric ASN string (e.g., '15169')."""
        if asn_val is None:
            return None
        text = str(asn_val).strip()
        if text.upper().startswith("AS"):
            text = text[2:].strip()
        if not text.isdigit() or text in ("0", "unknown", "n/a"):
            return None
        return text

    @staticmethod
    def _clean_registrar(reg_val: Any) -> Optional[str]:
        """Extract canonical registrar name."""
        if not reg_val:
            return None
        text = str(reg_val).strip()
        if text.lower() in ("unknown", "n/a", "none", "", "null"):
            return None
        return text

    def _find_geo_for_ip(self, ip: str, geo_list: List[Any]) -> dict:
        """Helper to find matching geo dictionary for a given IP."""
        for geo in geo_list:
            if isinstance(geo, dict) and geo.get("ip") == ip:
                return geo
            elif hasattr(geo, "ip") and getattr(geo, "ip") == ip:
                return geo.__dict__ if hasattr(geo, "__dict__") else {}
        return {}

    def add_email(self, email: Any, analysis: Any) -> None:
        """Add a single email and all its infrastructure relationships to the graph deterministically."""
        # Extract email fields safely
        if isinstance(email, dict):
            email_id = str(email.get("id", ""))
            subject = str(email.get("subject", "No Subject") or "No Subject")
            sender = email.get("sender", "")
        else:
            email_id = str(getattr(email, "id", ""))
            subject = str(getattr(email, "subject", "No Subject") or "No Subject")
            sender = getattr(email, "sender", "")

        if not email_id:
            return

        node_email_id = f"email:{email_id}" if not email_id.startswith("email:") else email_id
        truncated_subj = (subject[:37] + "...") if len(subject) > 40 else subject

        # Extract analysis fields safely
        if isinstance(analysis, dict):
            risk_score = float(analysis.get("composite_risk_score", 0.0) or 0.0)
            domain_intel = analysis.get("domain_intel", {}) or {}
            relay_path = analysis.get("relay_path", []) or []
            geo_data = analysis.get("geo_data", []) or []
            analyzed_at = str(analysis.get("analyzed_at", ""))
        else:
            risk_score = float(getattr(analysis, "composite_risk_score", 0.0) or 0.0)
            domain_intel = getattr(analysis, "domain_intel", {}) or {}
            relay_path = getattr(analysis, "relay_path", []) or []
            geo_data = getattr(analysis, "geo_data", []) or []
            analyzed_at = str(getattr(analysis, "analyzed_at", ""))

        if not isinstance(domain_intel, dict) and hasattr(domain_intel, "__dict__"):
            domain_intel = domain_intel.__dict__

        # 1. Email Node
        self.graph.add_node(
            node_email_id,
            type="email",
            label=f"Email: {truncated_subj}",
            subject=subject,
            sender=sender or "unknown",
            risk_score=risk_score,
            color=self.NODE_COLORS["email"],
            analyzed_at=analyzed_at,
        )

        # 2. Sender Domain Node & Edge
        sender_domain = self._clean_domain(sender)
        if sender_domain:
            domain_node_id = f"domain:{sender_domain}"
            if not self.graph.has_node(domain_node_id):
                registrar = self._clean_registrar(domain_intel.get("registrar"))
                age_days = domain_intel.get("domain_age_days", -1)
                is_newly_registered = bool(domain_intel.get("is_newly_registered", False))
                self.graph.add_node(
                    domain_node_id,
                    type="domain",
                    label=sender_domain,
                    color=self.NODE_COLORS["domain"],
                    registrar=registrar or "Unknown",
                    age_days=age_days if age_days is not None else -1,
                    is_newly_registered=is_newly_registered,
                    risk_score=None,
                )
            self.graph.add_edge(
                node_email_id,
                domain_node_id,
                relationship="sent_from",
                weight=1.0,
            )

            # 3. Registrar Node & Edge
            registrar = self._clean_registrar(domain_intel.get("registrar"))
            if registrar:
                registrar_node_id = f"registrar:{registrar}"
                if not self.graph.has_node(registrar_node_id):
                    self.graph.add_node(
                        registrar_node_id,
                        type="registrar",
                        label=registrar,
                        color=self.NODE_COLORS["registrar"],
                        risk_score=None,
                    )
                self.graph.add_edge(
                    domain_node_id,
                    registrar_node_id,
                    relationship="registered_by",
                    weight=0.3,
                )

        # 4. Relay IP Nodes & Edges
        for hop in relay_path:
            ip = hop.get("ip") if isinstance(hop, dict) else getattr(hop, "ip", None)
            hop_num = hop.get("hop_number", 1) if isinstance(hop, dict) else getattr(hop, "hop_number", 1)

            if not ip or not self._is_public_ip(ip):
                continue

            ip_clean = str(ip).strip()
            ip_node_id = f"ip:{ip_clean}"
            if not self.graph.has_node(ip_node_id):
                geo = self._find_geo_for_ip(ip_clean, geo_data)
                self.graph.add_node(
                    ip_node_id,
                    type="ip",
                    label=ip_clean,
                    color=self.NODE_COLORS["ip"],
                    country=geo.get("country", "Unknown") or "Unknown",
                    city=geo.get("city", "Unknown") or "Unknown",
                    isp=geo.get("isp", "Unknown") or "Unknown",
                    infrastructure_type=geo.get("infrastructure_type", "unknown") or "unknown",
                    risk_score=None,
                )
            self.graph.add_edge(
                node_email_id,
                ip_node_id,
                relationship="relayed_through",
                weight=0.8,
                hop_number=hop_num,
            )

        # 5. ASN Nodes & Edges
        for geo in geo_data:
            asn_raw = geo.get("asn") if isinstance(geo, dict) else getattr(geo, "asn", None)
            ip_val = geo.get("ip") if isinstance(geo, dict) else getattr(geo, "ip", None)
            org = (geo.get("org") if isinstance(geo, dict) else getattr(geo, "org", None)) or "Unknown"

            clean_asn_num = self._clean_asn(asn_raw)
            if clean_asn_num:
                asn_node_id = f"asn:{clean_asn_num}"
                if not self.graph.has_node(asn_node_id):
                    self.graph.add_node(
                        asn_node_id,
                        type="asn",
                        label=f"AS{clean_asn_num} ({org})",
                        color=self.NODE_COLORS["asn"],
                        org=org,
                        risk_score=None,
                    )
                if ip_val and self._is_public_ip(ip_val):
                    ip_node_id = f"ip:{str(ip_val).strip()}"
                    if self.graph.has_node(ip_node_id):
                        self.graph.add_edge(
                            ip_node_id,
                            asn_node_id,
                            relationship="belongs_to_asn",
                            weight=0.5,
                        )

    def _add_shared_infrastructure_edges(self) -> None:
        """Find emails sharing common public infrastructure and add direct correlation edges deterministically."""
        email_nodes = sorted([n for n, d in self.graph.nodes(data=True) if d.get("type") == "email"])

        for i, email_a in enumerate(email_nodes):
            for email_b in email_nodes[i + 1:]:
                neighbors_a = set(self.graph.neighbors(email_a))
                neighbors_b = set(self.graph.neighbors(email_b))
                common = neighbors_a & neighbors_b

                shared_ips = sorted([n.replace("ip:", "") for n in common if self.graph.nodes[n].get("type") == "ip"])
                shared_domains = sorted([n.replace("domain:", "") for n in common if self.graph.nodes[n].get("type") == "domain"])

                if shared_ips and shared_domains:
                    self.graph.add_edge(
                        email_a,
                        email_b,
                        relationship="shares_infrastructure",
                        weight=min(1.0, len(shared_ips) * 0.4 + len(shared_domains) * 0.3),
                        shared_ips=shared_ips,
                        shared_domains=shared_domains,
                    )
                elif shared_ips:
                    self.graph.add_edge(
                        email_a,
                        email_b,
                        relationship="shares_ip",
                        weight=min(1.0, len(shared_ips) * 0.4),
                        shared_ips=shared_ips,
                    )
                elif shared_domains:
                    self.graph.add_edge(
                        email_a,
                        email_b,
                        relationship="shares_domain",
                        weight=min(1.0, len(shared_domains) * 0.3),
                        shared_domains=shared_domains,
                    )

    def build_graph(
        self,
        emails: List[Any],
        analysis_results: List[Any],
    ) -> AttributionGraph:
        """Build a full attribution graph across all provided emails deterministically."""
        self.graph = nx.Graph()

        # Map analysis results by email_id
        analysis_map: Dict[str, Any] = {}
        for a in analysis_results:
            if isinstance(a, dict):
                eid = str(a.get("email_id", "") or a.get("id", ""))
            else:
                eid = str(getattr(a, "email_id", "") or getattr(a, "id", ""))
            if eid:
                analysis_map[eid.replace("email:", "")] = a

        # Deterministically sort emails by ID
        sorted_emails = sorted(
            emails,
            key=lambda e: str(e.get("id", "") if isinstance(e, dict) else getattr(e, "id", ""))
        )

        for email in sorted_emails:
            eid = str(email.get("id", "") if isinstance(email, dict) else getattr(email, "id", "")).replace("email:", "")
            analysis = analysis_map.get(eid, {})
            self.add_email(email, analysis)

        self._add_shared_infrastructure_edges()

        stats = {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "density": round(nx.density(self.graph), 4) if self.graph.number_of_nodes() > 1 else 0.0,
            "connected_components": nx.number_connected_components(self.graph) if self.graph.number_of_nodes() > 0 else 0,
        }

        nodes = self._extract_nodes()
        edges = self._extract_edges()
        json_data = self.to_json()

        return AttributionGraph(
            nodes=nodes,
            edges=edges,
            communities=[],
            graph_stats=stats,
            json_data=json_data,
        )

    def _extract_nodes(self) -> List[GraphNode]:
        nodes = []
        for node_id, data in sorted(self.graph.nodes(data=True), key=lambda x: x[0]):
            node_type = data.get("type", "unknown")
            label = data.get("label", node_id)
            risk = data.get("risk_score")
            color = data.get("color", self.NODE_COLORS.get(node_type, "#999"))
            attrs = {k: v for k, v in data.items() if k not in ("type", "label", "risk_score", "color")}
            nodes.append(GraphNode(
                id=node_id,
                type=node_type,
                label=label,
                attributes=attrs,
                risk_score=risk,
                color=color,
            ))
        return nodes

    def _extract_edges(self) -> List[GraphEdge]:
        edges = []
        for source, target, data in sorted(self.graph.edges(data=True), key=lambda x: (x[0], x[1])):
            rel = data.get("relationship", "connected")
            w = float(data.get("weight", 1.0))
            attrs = {k: v for k, v in data.items() if k not in ("relationship", "weight")}
            edges.append(GraphEdge(
                source=source,
                target=target,
                relationship=rel,
                weight=w,
                attributes=attrs,
            ))
        return edges

    def get_node_connections(self, node_id: str) -> List[GraphEdge]:
        """Return all edges incident to a given node."""
        clean_id = node_id.strip()
        if not self.graph.has_node(clean_id):
            return []
        edges = []
        for neighbor in sorted(self.graph.neighbors(clean_id)):
            data = self.graph.get_edge_data(clean_id, neighbor) or {}
            edges.append(GraphEdge(
                source=clean_id,
                target=neighbor,
                relationship=data.get("relationship", "connected"),
                weight=float(data.get("weight", 1.0)),
                attributes={k: v for k, v in data.items() if k not in ("relationship", "weight")},
            ))
        return edges

    def find_shared_infrastructure(self) -> List[Dict[str, Any]]:
        """Identify infrastructure nodes shared across 2 or more emails."""
        shared = []
        infra_types = {"ip", "domain", "asn", "registrar"}

        for node_id, data in sorted(self.graph.nodes(data=True), key=lambda x: x[0]):
            if data.get("type") in infra_types:
                neighbors = sorted(list(self.graph.neighbors(node_id)))
                email_neighbors = [n for n in neighbors if self.graph.nodes[n].get("type") == "email"]
                if len(email_neighbors) >= 2:
                    shared.append({
                        "node_id": node_id,
                        "type": data.get("type"),
                        "label": data.get("label"),
                        "connected_emails": [e.replace("email:", "") for e in email_neighbors],
                        "email_count": len(email_neighbors),
                    })
        return sorted(shared, key=lambda x: x["email_count"], reverse=True)

    def get_subgraph_for_email(self, email_id: str, hops: int = 2) -> Dict[str, Any]:
        """Extract ego-subgraph centered around a specific email node."""
        node_id = f"email:{email_id}" if not email_id.startswith(("email:", "campaign:", "domain:", "ip:", "asn:", "registrar:")) else email_id
        if not self.graph.has_node(node_id):
            return {"nodes": [], "links": []}

        subgraph_nodes = set([node_id])
        frontier = {node_id}

        for _ in range(hops):
            next_frontier = set()
            for n in frontier:
                next_frontier.update(self.graph.neighbors(n))
            subgraph_nodes.update(next_frontier)
            frontier = next_frontier

        sub = self.graph.subgraph(sorted(list(subgraph_nodes)))
        return self._serialize_subgraph(sub)

    def _node_size(self, data: dict) -> int:
        sizes = {"email": 8, "domain": 6, "ip": 4, "asn": 5, "registrar": 3, "campaign": 12}
        return sizes.get(data.get("type"), 4)

    def _serialize_subgraph(self, g: nx.Graph) -> Dict[str, Any]:
        nodes = []
        for node_id, data in sorted(g.nodes(data=True), key=lambda x: x[0]):
            nodes.append({
                "id": node_id,
                "type": data.get("type", "unknown"),
                "label": data.get("label", node_id),
                "color": data.get("color", self.NODE_COLORS.get(data.get("type", ""), "#666")),
                "risk_score": data.get("risk_score"),
                "val": self._node_size(data),
                **{k: v for k, v in data.items() if k not in ("type", "label", "color", "risk_score")},
            })

        links = []
        for source, target, data in sorted(g.edges(data=True), key=lambda x: (x[0], x[1])):
            links.append({
                "source": source,
                "target": target,
                "relationship": data.get("relationship", "connected"),
                "weight": data.get("weight", 1.0),
                **{k: v for k, v in data.items() if k not in ("relationship", "weight")},
            })

        return {"nodes": nodes, "links": links}

    def to_json(self) -> Dict[str, Any]:
        """Serialize full graph into node/link format for React-Force-Graph."""
        return self._serialize_subgraph(self.graph)
