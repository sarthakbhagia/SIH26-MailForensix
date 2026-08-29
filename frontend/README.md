# MailForensix — Forensic Threat Intelligence Console
## Frontend UI/UX Redesign Assessment & Engineering Specification

> **Assessment Standard**: UI/UX Pro Max — Domain-Specific DFIR / SOC Cyber Threat Intelligence Workstation

---

## Executive Summary

This document details the comprehensive UI/UX redesign assessment conducted on the **MailForensix** frontend (`frontend/`). The objective is to elevate MailForensix from a prototype/generic SaaS aesthetic to an elite, production-grade **Security Operations Center (SOC)** and **Digital Forensics and Incident Response (DFIR)** command console.

---

## 1. Current Strengths

* **Domain-Specific Architectural Scope**: The application covers the complete DFIR email lifecycle:
  * RFC-822 / MIME raw email ingestion with multipart MIME parsing.
  * SPF, DKIM, DMARC cryptographic and domain alignment verification.
  * Multi-hop MTA transmission route extraction with hop-by-hop latency and anomaly flags.
  * IOC extraction (IPs, Domains, URLs, Hashes).
  * Force-directed graph campaign attribution clustering.
  * Global MTA relay flight path mapping via MapLibre GL.
  * Formal cryptographically signed PDF and JSON dossier reporting.
* **Typographic Foundations**: The baseline choice of **IBM Plex Sans** (UI interface) and **JetBrains Mono** (forensic data, SHA-256 digests, IP addresses, raw headers, tabular numbers) provides an authentic technical foundation.
* **Semantic Color Foundations**: A custom dark palette utilizing OKLCH color spaces with dedicated tokens for severity (`critical`, `high`, `medium`, `clean`, `primary cyan`, `accent amber`).
* **Interactive Data Visualizations**: Integration of specialized visualization engines:
  * Force-directed campaign attribution graph (`react-force-graph-2d`).
  * Real-world satellite/MTA transmission mapping (`maplibre-gl` / `react-map-gl`).
  * Time-series velocity and threat vector distribution (`recharts`).
* **Reactive Telemetry Infrastructure**: Built-in WebSocket stream integration (`useAlerts`, `WebSocketManager`) with auto-reconnect logic and live unacknowledged alert counters.

---

## 2. Current Weaknesses

* **Disjointed Investigation Workflows**: Forensic investigation is fragmented across isolated routes (`/emails/:id`, `/map?emailId=:id`, `/graph?emailId=:id`, `/reports?emailId=:id`). Analysts must constantly switch between tabs and pages to correlate a single envelope's geolocation, graph cluster, and raw headers.
* **Duplicated & Divergent Components**:
  * Two separate implementations of TraceMap: a static hardcoded SVG world map (`forensics/TraceMap.tsx`) and a full MapLibre GL map (`map/TraceMap.tsx`).
  * Inconsistent risk-tier calculations and color maps duplicated across 8+ different files (`RiskGauge.tsx`, `ThreatChart.tsx`, `IOCTable.tsx`, `EmailList.tsx`, `CasesPage.tsx`, etc.).
* **Rigid Viewport Math & Wasted Screen Real Estate**: Fixed container constraints (`max-w-7xl`) and brittle manual viewport heights (`h-[calc(100vh-210px)]`, `h-[calc(100vh-5.5rem)]`) waste screen area on ultrawide/1440p+ SOC monitors and cause scrollbar collisions on smaller displays.
* **Surface Hierarchy & Contrast Inconsistencies**: The vertical panel gradient (`linear-gradient(180deg, var(--surface), var(--background))`) combined with body radial glows creates washed-out, uneven contrast across nested cards and tables.

---

## 3. UX Problems

* **Misleading Global Search**: The header search bar claims to search *"cases, senders, IOCs..."*, but hard-redirects solely to `/cases?search=...`, failing to search email subjects, SHA-256 hashes, or IP indicators.
* **Lack of Quick Command Palette (`Ctrl+K` / `Cmd+K`)**: In modern incident triage, analysts need instant keyboard-driven search to jump to an envelope ID, IOC, case, or route without manual pointer navigation.
* **Static / Incomplete Email Ledger Operations**:
  * Ingestion page (`EmailList.tsx`) has hardcoded pagination (`page = 1`), no sortable columns, no multi-select batch actions, and no fast filters (by verdict, SPF failure, date range).
* **Missing Defanging & Threat Intel Actions on IOCs**:
  * In `IOCTable.tsx`, URLs are rendered without defanging (e.g., `hxxp[://]`), posing accidental click risks to analysts.
  * No one-click pivoting from an IOC directly into the Attribution Graph, VirusTotal, or WHOIS lookup.
* **Disconnected Alert Escalation**:
  * Live dashboard alerts in `RecentAlerts.tsx` allow acknowledging an alert, but offer no 1-click button to *"Promote to Case"* or *"Attach to Active Investigation"*.
* **Cases View Transition Friction**:
  * In `CasesPage.tsx`, selecting a case replaces the whole view with `CaseDetail.tsx` rather than offering an efficient master-detail split pane or dockable drawer.

---

## 4. Visual & Design Problems

* **Micro-Typography Overload**: Overuse of `text-[9px]` and `text-[10px]` all-caps strings (`.label-mono`) with low-contrast muted colors reduces legibility and visual stamina during long incident reviews.
* **Monospace Misalignment**: Monospace fonts are applied to standard UI navigation items and regular action buttons where a high-legibility geometric sans-serif would provide faster visual parsing.
* **Ambiguous Visual States**:
  * Table rows lack clear selected, active, or threat-state borders.
  * Tab bars have flat borders that lack clear active indicator bars or high-contrast state markers.
* **Lack of Dense, Tactical Data Displays**: Key forensic metrics (hop latency deltas, TLS encryption status, reverse-DNS match statuses) are either buried in text or displayed with excessive whitespace.
* **Inconsistent Iconography & Badge Encodings**: Mixed use of badge styles (some filled pills, some outlined badges, some with animated pings, some with raw OKLCH color mixing).

---

## 5. Information Hierarchy Problems

* **Email Analysis Workstation Overload**:
  * The top header of `EmailAnalysisPage.tsx` attempts to display the Subject, Sender, Recipients, Attribution, Navigation buttons, Action buttons, and a huge 148px Risk Gauge dial all in one block, causing layout wrapping on mid-size screens.
  * The `Overview` tab dumps Authentication, 6 Metric tiles, Threat Findings, Risk Vector Assessment, Body payload, Attachments, and URLs all vertically on one page, requiring excessive scrolling.
* **MTA Relay Path Triangulation Disconnect**:
  * In `RelayPathViewer.tsx`, relay hops are displayed as discrete vertical blocks with text, omitting a cohesive visual pipeline/timeline node graph showing ingress -> intermediate -> egress MTA nodes with timing deltas.
* **Attribution Graph Visual Density**:
  * In `AttributionGraphPage.tsx`, the node details drawer slides over 380px of the canvas without an option to pin or dock, blocking the relevant connected cluster.

---

## 6. Components That Should Be Redesigned

| Component | Target File | Rationale & Redesign Focus |
| :--- | :--- | :--- |
| **Top Navigation & Header** | `src/components/layout/Header.tsx` | Integrate global quick search with `Ctrl+K` command palette, live telemetry heartbeat indicator, active incident quick-switcher, and notification tray. |
| **App Layout & Frame** | `src/components/layout/DashboardLayout.tsx`, `Sidebar.tsx` | True edge-to-edge SOC layout (expandable / collapsible rail sidebar, breadcrumbs, persistent status bar, no arbitrary `max-w-7xl` gutters on large monitors). |
| **Email Analysis Workstation** | `src/pages/EmailAnalysisPage.tsx` | Transform into a unified multi-pane DFIR investigation workstation: persistent telemetry banner, integrated interactive map mini-viewport, interactive relay timeline, side-by-side header inspector & defanged payload viewer. |
| **Relay Path Viewer** | `src/components/analysis/RelayPathViewer.tsx`, `forensics/RelayHopNode.tsx` | Redesign as a structured horizontal/vertical MTA transmission pipeline with latency deltas, TLS handshake validation, anomaly callouts, and hop-by-hop geo tags. |
| **IOC Triage Matrix** | `src/components/analysis/IOCTable.tsx` | Automatic defanging toggle, 1-click pivot to Threat Graph, external threat lookup buttons (VirusTotal/WHOIS/AbuseIPDB), copy-all defanged artifacts, and bulk IOC export (STIX/CSV/JSON). |
| **MTA Trace Map Experience** | `src/pages/TraceMapPage.tsx`, `src/components/map/TraceMap.tsx` | Full dark tactical map HUD with animated hop progression (Hop 1 -> Hop 2 -> Destination), IP classification overlays (Tor/VPN/Data Center), and synchronized telemetry timeline. |
| **Attribution Graph Workbench** | `src/pages/AttributionGraphPage.tsx` | Crisp tactical canvas styling, customizable physics layout modes, dockable/resizable node inspector, campaign clustering matrix, and IOC neighbor expansion. |
| **SOC Dashboard** | `src/pages/DashboardPage.tsx` | High-density telemetry cards with sparklines, time-range selectors (1h/24h/7d/30d), operational live alert triage queue with 1-click case promotion. |
| **Case Investigation Center** | `src/pages/CasesPage.tsx`, `src/components/cases/CaseDetail.tsx` | Master-detail split view with persistent case queue on left, rich evidence linking drawer, markdown-supported analyst notes, and interactive audit timeline. |
| **Evidence Ingestion & Dropzone** | `src/pages/EmailIngestPage.tsx`, `EmailUpload.tsx`, `EmailList.tsx` | Compact drag-and-drop ingestion dock with live parsing progress, coupled with a dense, searchable, filterable, and paginated forensic evidence ledger. |

---

## 7. Components That Should Be Preserved

* **Authentication Logic & Data Contracts**:
  * `AuthenticationPanel.tsx` & `AuthPill.tsx`: The core SPF/DKIM/DMARC and alignment verification architecture is sound; preserved with crisper border states and clearer DNS mismatch chips.
* **Risk Gauge Visualization Geometry**:
  * `RiskGauge.tsx`: The SVG stroke-dash calculations and circular verdict display are clean; preserved and adapted for compact header integration.
* **Header Inspector Dual-Mode Mechanism**:
  * `HeaderInspector.tsx`: The Grid Inspector vs. Raw RFC-822 tab toggle and instant key/value search are highly valuable for DFIR workflows and will be preserved.
* **Report Generation & A4 Preview System**:
  * `ReportsPage.tsx`, `ReportPreview.tsx`, `ReportDownload.tsx`: Preserves direct PDF/JSON download mechanics, zoom controls, and iframe rendering with an updated dark workstation frame.
* **API Client & WebSocket Manager**:
  * `api.ts` & `websocket.ts`: Preserves the backend communication layer and query invalidation pipelines.

---

## 8. Recommended Overall Design Direction

### Visual & Aesthetic System
* **Style Archetype**: **Professional SOC / Threat Intel Workstation** (inspired by platforms like CrowdStrike Falcon, SentinelOne, Recorded Future, and Palo Alto Cortex).
* **Color Hierarchy**:
  * Base canvas: Deep Charcoal Slate (`#0B0F17` / `#0E131F`).
  * Surface layers: Layered flat panels (`#131A29`, `#182235`, `#1E2B42`) with 1px razor-sharp borders (`#223048` / `#2D3F5E`) and zero muddy gradients.
  * Accents & Threat Telemetry:
    * `CRITICAL`: Neon Crimson (`#FF2A55` / `#FF3B30`)
    * `HIGH`: High-Vis Amber-Orange (`#FF8C00` / `#FF9F0A`)
    * `MEDIUM`: Electric Gold (`#FFCC00` / `#FFD60A`)
    * `LOW / NOMINAL`: Cyan Glow (`#00E5FF` / `#30D158`)
    * `CLEAN`: Emerald Green (`#00E676` / `#34C759`)
* **Typography System**:
  * Primary Interface: `IBM Plex Sans` (clean, compact weights: 400, 500, 600).
  * Monospace Telemetry: `JetBrains Mono` with `tabular-nums` enabled for all hashes, IP addresses, hop counts, latencies, dates, and severity tags.
  * Minimum UI font size standardized to `11px` (eliminating unreadable 9px text).

### Workstation Layout & Interaction Patterns
* **Full-Width Multi-Pane Command Center**: Maximize screen utility with responsive collapsible panels and split-pane dividers for simultaneous header, body, graph, and trace inspection.
* **Global Command Palette (`Ctrl+K`)**: Rapid keyboard navigation across envelopes, cases, IOCs, and routes.
* **Tactical Defanging & Indicator Controls**: Built-in defanging toggles, indicator tag clouds, and 1-click pivot buttons.
* **Unified Single Source of Truth**: Centralized utility helper for risk-score classification, badge rendering, and verdict calculations across all views.
