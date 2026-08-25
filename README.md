# Welcome to your Lovable project

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Open your project in the [Lovable editor](https://lovable.dev) and keep building.

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: connect the project to GitHub and every change made in Lovable is committed straight to your repository.
- **Full ownership**: this code is yours. Push to your repository and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```

## Built with

- TanStack Start
- TypeScript
- React
- Tailwind CSS

---

## Live Enrichment

MailForensix optionally performs four live network lookups to strengthen its findings.
All lookups run **entirely in the browser** — no server component is involved and no message
content (headers, body, subject) is ever transmitted.

### What is sent and to whom

| Feature | External service | Data transmitted | Never transmitted |
|---|---|---|---|
| SPF DNS | `cloudflare-dns.com/dns-query` | Sender domain (e.g. `example.com`) | Email content |
| DKIM DNS | `cloudflare-dns.com/dns-query` | `<selector>._domainkey.<domain>` | Email content |
| Domain age | `rdap.org/domain/<domain>` | Sender domain | Email content |
| IP geo/ASN | `ipapi.co/<ip>/json/` | Originating public IP | Email content |

### Fallback behaviour

Every lookup is wrapped in `try/catch`.  If a request fails (network offline, CORS policy,
API rate-limited, or timeout) the lookup is **silently skipped** and the analysis falls back
to the existing static heuristics (`NET_MAP` / `HOST_HINTS` for geo, header-based auth
results for SPF/DKIM).  The tool is fully usable in air-gapped and offline-demo environments.

### Disabling live geo lookup

Pass `{ liveGeoEnabled: false }` to `analyzeEmailAsync()` to disable the `ipapi.co` call
(the Cloudflare DoH and RDAP calls still run):

```ts
import { analyzeEmailAsync } from "@/lib/email-forensics";
const result = await analyzeEmailAsync(rawEmail, { liveGeoEnabled: false });
```

### New findings added by live enrichment

| Finding ID | Severity | Weight | Trigger |
|---|---|---|---|
| `dns-spf-disagree` | Critical | +20 | Live SPF TXT contradicts `Authentication-Results` header |
| `dns-dkim-disagree` | Critical | +20 | Live DKIM TXT absent/present when header says opposite |
| `domain-age-new` | High | +15 | Sender domain registered < 30 days ago |
| `domain-age-young` | Medium | +8 | Sender domain registered < 365 days ago |

### PDF export

The **Download PDF** button in the Report tab uses [jsPDF](https://github.com/parallax/jsPDF)
(already bundled) to render a formatted A4 forensic report entirely client-side.
No server round-trip is required.
