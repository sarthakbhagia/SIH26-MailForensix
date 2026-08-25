# MailForensix — Tech Stack & Classification Engine

> **For teammates:** This document explains what the project is built on, how the codebase is structured, and — most importantly — exactly how an email gets classified as legitimate, suspicious, phishing, or fraud.

---

## 1. Tech Stack

### Frontend Framework
| Layer | Technology |
|---|---|
| Framework | **TanStack Start** (React 19 + TanStack Router 1.x) |
| Build tool | **Vite 8** |
| Language | **TypeScript 5.8** |
| Styling | **Tailwind CSS v4** (via `@tailwindcss/vite`) + custom CSS tokens |
| UI Components | **shadcn/ui** (Radix UI primitives) |
| Icons | **lucide-react** |
| Charts | **Recharts** |
| Form handling | **react-hook-form** + **Zod** |
| Package manager | **npm** |

### Key source files
```
src/
├── routes/
│   └── index.tsx          # Main UI: EML upload, paste input, results dashboard
├── lib/
│   └── email-forensics.ts # Core analysis engine (all logic lives here)
├── components/
│   └── forensics/
│       ├── RiskGauge.tsx  # Circular risk score visualisation
│       └── TraceMap.tsx   # SMTP relay path map
└── styles.css             # Design system tokens (dark "forensic console" theme)
```

### Deployment
- Target: **Cloudflare Workers** (via Nitro preset `cloudflare-module`)
- Production build: `npm run build` → `.output/` directory
- Dev server: `npm run dev` → `http://localhost:8081/`

### Privacy model
> **Everything runs 100% client-side.** No email content, headers, or analysis results are ever sent to a server. The `FileReader` API reads uploaded `.eml` files locally in the browser.

---

## 2. Classification Engine — How It Works

The engine is a **deterministic, weighted rule-based scoring system**. There is **no ML model**. Instead, it applies a structured set of forensic rules drawn from email security standards (RFC 7208 / SPF, RFC 6376 / DKIM, RFC 7489 / DMARC) and threat-intelligence heuristics.

The entry point is:
```ts
analyzeEmail(rawEmailText: string): Analysis
```

### Step 1 — Parsing
The raw RFC-822 message is parsed into:
- **Headers** — unfolded key/value pairs (`From`, `Received`, `Authentication-Results`, etc.)
- **Body** — everything after the first blank line
- **SMTP relay hops** — each `Received:` header becomes a `Hop` object with: originating host, by host, IP address, protocol, timestamp

---

### Step 2 — Authentication Checks
Inspects `Authentication-Results`, `Received-SPF`, `DKIM-Signature`, and ARC headers.

| Protocol | Possible results |
|---|---|
| SPF | `pass`, `fail`, `softfail`, `neutral`, `none`, `unknown` |
| DKIM | `pass`, `fail`, `none`, `unknown` |
| DMARC | `pass`, `fail`, `none`, `unknown` |
| Alignment | Whether the DKIM `d=` domain matches the `From:` domain |

---

### Step 3 — Signal Detection (Findings)

Each finding adds a **risk weight** to the total score.

#### Authentication
| Signal | Severity | Weight |
|---|---|---|
| SPF `fail` | Critical | +22 |
| SPF `softfail` | High | +14 |
| SPF absent (`none`) | Medium | +8 |
| DKIM signature verification failed | Critical | +20 |
| No DKIM signature present | Medium | +9 |
| DMARC alignment failure | Critical | +24 |
| DKIM `d=` domain misaligned with `From` | High | +14 |

#### Identity
| Signal | Severity | Weight |
|---|---|---|
| Return-Path differs from From (cross-domain) | High | +13 |
| Return-Path differs from From (same domain) | Low | +3 |
| Reply-To redirected to a different address | High | +16 |
| Display name contains a conflicting email address | Critical | +20 |
| Display name invokes a known brand but sending domain doesn't match | High | +17 |
| Executive impersonation in display name (CEO/CFO/etc.) | High | +12 |

#### Infrastructure
| Signal | Severity | Weight |
|---|---|---|
| Sender domain uses a high-abuse TLD (`.top`, `.xyz`, `.tk`, `.gq`, etc.) | Medium | +10 |
| Lookalike/typosquat domain (Levenshtein distance ≤ 2 from known brand) | Critical | +22 |
| Domain contains digit runs, double hyphens, or punycode | Medium | +8 |
| Origin IP resolves to anonymizing infrastructure (Tor/VPN/bulletproof hosting) | High | +15 |
| Origin IP is a residential/broadband allocation | Medium | +11 |

#### Routing
| Signal | Severity | Weight |
|---|---|---|
| No `Received:` headers at all | High | +15 |
| Only one `Received:` header (direct-to-MX injection) | Medium | +9 |
| HELO/EHLO identity mismatch in relay | Medium | +7 |
| Message-ID domain doesn't match sender domain | Medium | +9 |
| Message-ID completely absent | Medium | +10 |

#### Content
| Signal | Severity | Weight |
|---|---|---|
| Urgency/pressure language ("final warning", "act now", etc.) | High/Medium | +5 to +14 |
| Credential-harvesting phrasing ("verify your account", etc.) | High | +16 |
| BEC financial-instruction language ("wire transfer", "change of bank details", etc.) | Critical | +18 |
| Generic salutation ("Dear Customer", "Dear User") | Low | +4 |
| Hyperlink points to a raw IP address | High | +14 |
| URL shortener used (bit.ly, tinyurl, etc.) | High | +12 |
| Visible link text differs from actual href target | Critical | +20 |
| Dangerous attachment type (`.exe`, `.scr`, `.vbs`, `.js`, `.docm`, etc.) | Critical | +18 |
| Double-extension file (e.g. `Invoice.pdf.exe`) | Critical | +18 |

---

### Step 4 — Score Calculation

```
raw_score = sum of all triggered finding weights
score     = min(100, round(raw_score))

# Bonus: if SPF + DKIM + DMARC all pass, subtract 18 points
if (spf == pass && dkim == pass && dmarc == pass):
    score = max(0, score - 18)
```

---

### Step 5 — Verdict Thresholds

| Score range | Verdict |
|---|---|
| 0 – 21 | ✅ **Legitimate** |
| 22 – 41 | ⚠️ **Suspicious** |
| 42 – 57 | 🟠 **Impersonation** |
| 58 – 77 | 🔴 **Phishing** |
| 78 – 100 | 🚨 **Fraud / BEC** |

---

### Step 6 — Geolocation & Origin Estimation

The earliest **public IP** in the `Received:` chain is matched against two look-up tables:

1. **`NET_MAP`** — IP prefix ranges → provider / country / infrastructure type  
   e.g. `34.x` → Google Cloud / Iowa, `185.220.x` → Tor exit relay / Frankfurt
2. **`HOST_HINTS`** — Reverse-hostname regex patterns  
   e.g. `amazonaws.com` → AWS cloud, `tor-exit` → anonymized

A **confidence score** (10–92%) is produced, penalised for:
- Long relay chains (> 4 public hops)
- Anonymizing infrastructure detected

Infrastructure types: `cloud`, `residential`, `hosting`, `corporate`, `anonymized`, `unknown`

---

### Step 7 — Attribution Assessment

A narrative scenario is generated based on the combination of findings:

| Condition | Scenario |
|---|---|
| Origin is anonymized infrastructure | "Actor operating behind anonymized infrastructure" |
| Auth passes but content suspicious (score ≥ 42) | "Likely compromised legitimate mailbox" |
| SPF/DMARC fail or lookalike domain | "Domain spoofing / lookalike infrastructure operated by the actor" |
| Score 22–41, no authentication forgery | "Opportunistic bulk sender or low-sophistication phishing" |
| Score < 22 | "No adversarial attribution indicated" |

---

### Step 8 — IOC Extraction

Extracted Indicators of Compromise (IOCs) from the email body:

| IOC type | Risk basis |
|---|---|
| **URLs** | IP literals, URL shorteners, suspicious TLDs, or link host mismatch with sender domain |
| **Attachments** | Dangerous extensions (`.exe`, `.scr`, etc.) or double-extension tricks |
| **IP addresses** | The originating public IP from the relay chain |
| **Domains** | The sender's `From` domain |
| **Emails** | Reply-To address (if diverted to a different address) |

---

## 3. Input Methods (current build)

| Method | How it works |
|---|---|
| **Upload EML file** | Drag-and-drop or click to select a `.eml` / RFC-822 file. `FileReader` reads it as text; analysis runs immediately and automatically. |
| **Paste raw text** | Paste full email source (headers + body) into textarea, then click "Analyse message". |
| **Load sample case** | Loads a pre-built phishing email (HDFC Bank BEC) to demonstrate the tool. |

---

## 4. Output Tabs

| Tab | Contents |
|---|---|
| **Overview** | SPF/DKIM/DMARC status pills, key header metrics, all findings with severity and weight |
| **Relay trace** | Reconstructed SMTP hop-by-hop path with anomaly notes |
| **Geolocation** | Origin IP, provider, estimated country/region, confidence basis |
| **IOCs** | Table of all extracted indicators with risk ratings |
| **Headers** | Parsed raw header key/value pairs |
| **Report** | Downloadable/copyable plain-text forensic report |

---

## 5. What is NOT implemented yet (future work)

- [ ] Real-time DNS lookups (SPF/DKIM record resolution) — currently regex/header-only
- [ ] VirusTotal / AbuseIPDB API integration for live IOC reputation scoring
- [ ] Actual machine-learning model for natural language content classification
- [ ] Multi-email batch processing
- [ ] User authentication / persistent case management
- [ ] Export as PDF

---

*Source of truth: `src/lib/email-forensics.ts` — all scoring, thresholds, and look-up tables are defined there.*
