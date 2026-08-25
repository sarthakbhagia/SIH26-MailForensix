/**
 * Deterministic email forensics engine.
 * Parses raw RFC-822 messages: headers, auth results, relay path, IOCs,
 * heuristic social-engineering scoring, and origin/geo estimation.
 * Runs fully client-side — no message content leaves the browser.
 *
 * Live enrichment (optional, network-dependent):
 *   • DNS-over-HTTPS (Cloudflare) for SPF TXT and DKIM selector TXT records.
 *   • RDAP (rdap.org) for domain registration age.
 *   • ipapi.co for IP-to-ASN/geo lookup (free tier, 1 000 req/day).
 * All three are wrapped in try/catch and fall back gracefully to static
 * analysis when the network is unavailable or the API is blocked.
 */

export type Verdict = "legitimate" | "suspicious" | "impersonation" | "phishing" | "fraud";

export interface Hop {
  index: number;
  from: string | null;
  by: string | null;
  ip: string | null;
  ipClass: IpClass;
  protocol: string | null;
  timestamp: string | null;
  raw: string;
  notes: string[];
}

export type IpClass = "public" | "private" | "loopback" | "unknown";

export interface Finding {
  id: string;
  title: string;
  detail: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: "authentication" | "routing" | "content" | "infrastructure" | "identity";
  weight: number;
}

export interface OriginEstimate {
  ip: string | null;
  ipClass: IpClass;
  reverseHost: string | null;
  country: string | null;
  region: string | null;
  provider: string | null;
  infrastructure: "cloud" | "residential" | "hosting" | "corporate" | "anonymized" | "unknown";
  latitude: number | null;
  longitude: number | null;
  confidence: number;
  basis: string[];
}

export interface AuthResult {
  spf: "pass" | "fail" | "softfail" | "neutral" | "none" | "unknown";
  dkim: "pass" | "fail" | "none" | "unknown";
  dmarc: "pass" | "fail" | "none" | "unknown";
  dkimDomain: string | null;
  aligned: boolean;
}

export interface Ioc {
  type: "url" | "domain" | "ip" | "email" | "attachment";
  value: string;
  risk: "high" | "medium" | "low";
  note: string;
}

export interface LiveEnrichment {
  /** Raw SPF TXT record retrieved from DNS-over-HTTPS, or null if lookup failed. */
  spfDnsRecord: string | null;
  /** Raw DKIM TXT record for the selector found in the DKIM-Signature header, or null. */
  dkimDnsRecord: string | null;
  /** ISO-8601 registration date from RDAP, or null if lookup failed. */
  domainRegisteredAt: string | null;
  /** Age of the sender domain in days at analysis time, or null. */
  domainAgeDays: number | null;
  /** Live geo/ASN data from ipapi.co, or null if lookup failed. */
  liveGeo: {
    country: string;
    region: string;
    org: string;
    lat: number;
    lon: number;
  } | null;
}

export interface Analysis {
  id: string;
  analyzedAt: string;
  headers: Array<{ name: string; value: string }>;
  subject: string;
  fromDisplay: string | null;
  fromAddress: string | null;
  fromDomain: string | null;
  replyTo: string | null;
  returnPath: string | null;
  messageId: string | null;
  to: string | null;
  date: string | null;
  body: string;
  hops: Hop[];
  auth: AuthResult;
  findings: Finding[];
  iocs: Ioc[];
  origin: OriginEstimate;
  score: number;
  verdict: Verdict;
  attribution: {
    scenario: string;
    confidence: number;
    rationale: string[];
  };
  /** Populated only by analyzeEmailAsync(); undefined when using analyzeEmail(). */
  liveEnrichment?: LiveEnrichment;
}

/* ------------------------------- parsing ------------------------------- */

function unfold(raw: string): string[] {
  const headerBlock = raw.replace(/\r\n/g, "\n").split(/\n\n/)[0] ?? "";
  const lines = headerBlock.split("\n");
  const out: string[] = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && out.length) out[out.length - 1] += " " + line.trim();
    else if (line.trim()) out.push(line);
  }
  return out;
}

function parseHeaders(raw: string) {
  return unfold(raw)
    .map((line) => {
      const i = line.indexOf(":");
      if (i < 0) return null;
      return { name: line.slice(0, i).trim(), value: line.slice(i + 1).trim() };
    })
    .filter((h): h is { name: string; value: string } => !!h);
}

function pick(headers: Array<{ name: string; value: string }>, name: string) {
  return headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value ?? null;
}
function pickAll(headers: Array<{ name: string; value: string }>, name: string) {
  return headers.filter((h) => h.name.toLowerCase() === name.toLowerCase()).map((h) => h.value);
}

function extractAddress(value: string | null) {
  if (!value) return { display: null, address: null };
  const angle = value.match(/<([^>]+)>/);
  const address =
    (angle ? angle[1] : (value.match(/[\w.+-]+@[\w.-]+/)?.[0] ?? null))?.trim() ?? null;
  let display = angle ? value.slice(0, value.indexOf("<")).trim() : "";
  display = display.replace(/^["']|["']$/g, "").trim();
  return { display: display || null, address };
}

function classifyIp(ip: string | null): IpClass {
  if (!ip) return "unknown";
  if (/^127\./.test(ip) || ip === "::1") return "loopback";
  if (/^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip))
    return "private";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return "public";
  return ip.includes(":") ? "public" : "unknown";
}

/* --------------------------- relay path trace --------------------------- */

function parseReceived(raw: string, index: number): Hop {
  const from = raw.match(/from\s+([^\s;()]+)/i)?.[1] ?? null;
  const by = raw.match(/\bby\s+([^\s;()]+)/i)?.[1] ?? null;
  const ip =
    raw.match(/\[((?:\d{1,3}\.){3}\d{1,3})\]/)?.[1] ??
    raw.match(/\(((?:\d{1,3}\.){3}\d{1,3})\)/)?.[1] ??
    raw.match(/(?:\d{1,3}\.){3}\d{1,3}/)?.[0] ??
    null;
  const protocol = raw.match(/\bwith\s+([A-Za-z0-9]+)/i)?.[1] ?? null;
  const timestamp = raw.split(";").slice(1).join(";").trim() || null;
  const notes: string[] = [];
  if (/helo=|ehlo=/i.test(raw) && from) {
    const helo = raw.match(/(?:helo|ehlo)=([^\s)\];]+)/i)?.[1];
    if (helo && from && !from.includes(helo) && !helo.includes(from))
      notes.push(`HELO identity "${helo}" does not match announced host "${from}"`);
  }
  if (protocol && /^smtp$/i.test(protocol)) notes.push("Unauthenticated SMTP submission");
  if (/localhost|unknown/i.test(from ?? "")) notes.push("Obfuscated or unresolvable sending host");
  return { index, from, by, ip, ipClass: classifyIp(ip), protocol, timestamp, raw, notes };
}

/* --------------------------- geo / infra heuristics -------------------- */

const NET_MAP: Array<{
  test: RegExp;
  provider: string;
  country: string;
  region: string;
  infra: OriginEstimate["infrastructure"];
  lat: number;
  lon: number;
}> = [
  {
    test: /^13\.|^20\.|^40\.|^52\.1[0-9][0-9]\./,
    provider: "Microsoft Azure / Outlook",
    country: "United States",
    region: "Virginia",
    infra: "cloud",
    lat: 38.95,
    lon: -77.45,
  },
  {
    test: /^3\.|^18\.|^34\.2|^54\./,
    provider: "Amazon AWS EC2",
    country: "United States",
    region: "Oregon",
    infra: "cloud",
    lat: 45.84,
    lon: -119.7,
  },
  {
    test: /^34\.|^35\.|^142\.250\./,
    provider: "Google Cloud / Google Mail",
    country: "United States",
    region: "Iowa",
    infra: "cloud",
    lat: 41.26,
    lon: -95.86,
  },
  {
    test: /^159\.89\.|^165\.227\.|^167\.99\./,
    provider: "DigitalOcean LLC",
    country: "Netherlands",
    region: "Amsterdam",
    infra: "hosting",
    lat: 52.37,
    lon: 4.9,
  },
  {
    test: /^45\.(1[0-9][0-9]|2[0-9][0-9])\./,
    provider: "Bulk hosting / bulletproof range",
    country: "Unknown (bulk allocation)",
    region: "Unknown",
    infra: "anonymized",
    lat: 47.0,
    lon: 8.0,
  },
  {
    test: /^185\.220\./,
    provider: "Tor exit relay operator",
    country: "Germany",
    region: "Frankfurt",
    infra: "anonymized",
    lat: 50.11,
    lon: 8.68,
  },
  {
    test: /^103\.(2[0-9]|3[0-9])\./,
    provider: "APNIC regional allocation",
    country: "India",
    region: "Maharashtra",
    infra: "hosting",
    lat: 19.08,
    lon: 72.88,
  },
  {
    test: /^41\.|^102\./,
    provider: "AFRINIC regional allocation",
    country: "Nigeria",
    region: "Lagos",
    infra: "residential",
    lat: 6.52,
    lon: 3.37,
  },
  {
    test: /^196\./,
    provider: "AFRINIC regional allocation",
    country: "South Africa",
    region: "Gauteng",
    infra: "residential",
    lat: -26.2,
    lon: 28.04,
  },
  {
    test: /^5\.|^31\.|^37\.|^95\./,
    provider: "RIPE NCC regional allocation",
    country: "Russia",
    region: "Moscow",
    infra: "hosting",
    lat: 55.75,
    lon: 37.62,
  },
  {
    test: /^1\.|^14\.|^27\.|^49\.|^61\./,
    provider: "APNIC regional allocation",
    country: "China",
    region: "Guangdong",
    infra: "residential",
    lat: 23.13,
    lon: 113.26,
  },
];

const HOST_HINTS: Array<{
  test: RegExp;
  provider: string;
  infra: OriginEstimate["infrastructure"];
}> = [
  { test: /amazonaws\.com$/i, provider: "Amazon AWS EC2", infra: "cloud" },
  {
    test: /outlook\.com|protection\.outlook\.com$/i,
    provider: "Microsoft 365 (Exchange Online)",
    infra: "cloud",
  },
  { test: /google\.com|gmail\.com$/i, provider: "Google Workspace", infra: "cloud" },
  {
    test: /sendgrid\.net|mailgun|amazonses|sparkpost/i,
    provider: "Bulk ESP relay",
    infra: "cloud",
  },
  {
    test: /digitalocean|vultr|hetzner|ovh|contabo|linode/i,
    provider: "Low-cost VPS provider",
    infra: "hosting",
  },
  { test: /tor-exit|torservers|relay/i, provider: "Anonymizing relay", infra: "anonymized" },
  {
    test: /dynamic|dsl|broadband|cable|pppoe|res\./i,
    provider: "Consumer broadband allocation",
    infra: "residential",
  },
];

function estimateOrigin(hops: Hop[]): OriginEstimate {
  const basis: string[] = [];
  const earliest = [...hops].reverse().find((h) => h.ipClass === "public");
  const ip = earliest?.ip ?? null;
  const host = earliest?.from ?? null;
  let country: string | null = null;
  let region: string | null = null;
  let provider: string | null = null;
  let infrastructure: OriginEstimate["infrastructure"] = "unknown";
  let latitude: number | null = null;
  let longitude: number | null = null;
  let confidence = 20;

  if (!ip) {
    basis.push("No public IP address present in the Received chain — origin cannot be established");
    return {
      ip: null,
      ipClass: "unknown",
      reverseHost: host,
      country,
      region,
      provider,
      infrastructure,
      latitude,
      longitude,
      confidence: 10,
      basis,
    };
  }

  basis.push(`Earliest reliable sending node identified at hop ${earliest!.index + 1} (${ip})`);
  const net = NET_MAP.find((n) => n.test.test(ip));
  if (net) {
    country = net.country;
    region = net.region;
    provider = net.provider;
    infrastructure = net.infra;
    latitude = net.lat;
    longitude = net.lon;
    confidence = 62;
    basis.push(`IP block matches ${net.provider} allocation (${net.country})`);
  }

  if (host) {
    const hint = HOST_HINTS.find((h) => h.test.test(host));
    if (hint) {
      provider = provider ?? hint.provider;
      infrastructure =
        hint.infra === "anonymized"
          ? "anonymized"
          : infrastructure === "unknown"
            ? hint.infra
            : infrastructure;
      confidence += 12;
      basis.push(`Reverse hostname fingerprint indicates ${hint.provider}`);
    }
    const cc = host.match(/\.([a-z]{2})$/i)?.[1]?.toLowerCase();
    const ccMap: Record<string, string> = {
      in: "India",
      ru: "Russia",
      cn: "China",
      ng: "Nigeria",
      ua: "Ukraine",
      br: "Brazil",
      de: "Germany",
      nl: "Netherlands",
      uk: "United Kingdom",
      vn: "Vietnam",
    };
    if (cc && ccMap[cc]) {
      country = country ?? ccMap[cc];
      confidence += 8;
      basis.push(`ccTLD in relay hostname corroborates ${ccMap[cc]}`);
    }
  }

  const publicHops = hops.filter((h) => h.ipClass === "public").length;
  if (publicHops > 4) {
    confidence -= 10;
    basis.push(`${publicHops} public relay hops present — long chain reduces origin certainty`);
  }
  if (infrastructure === "anonymized") {
    confidence -= 15;
    basis.push(
      "Anonymizing infrastructure detected — geolocation reflects exit node, not the actor",
    );
  }

  return {
    ip,
    ipClass: earliest!.ipClass,
    reverseHost: host,
    country,
    region,
    provider,
    infrastructure,
    latitude,
    longitude,
    confidence: Math.max(8, Math.min(92, confidence)),
    basis,
  };
}

/* ------------------------------ auth results ---------------------------- */

function parseAuth(
  headers: Array<{ name: string; value: string }>,
  fromDomain: string | null,
): AuthResult {
  const blob = [
    ...pickAll(headers, "authentication-results"),
    ...pickAll(headers, "received-spf"),
    ...pickAll(headers, "arc-authentication-results"),
    ...pickAll(headers, "x-ms-exchange-authentication-results"),
  ]
    .join(" ")
    .toLowerCase();

  const grab = (k: string) => blob.match(new RegExp(`${k}\\s*=\\s*([a-z]+)`))?.[1] ?? null;
  const spfRaw =
    grab("spf") ?? pick(headers, "received-spf")?.toLowerCase().trim().split(/\s/)[0] ?? null;
  const dkimRaw = grab("dkim");
  const dmarcRaw = grab("dmarc");
  const dkimHeader = pick(headers, "dkim-signature");
  const dkimDomain = dkimHeader?.match(/d=([^;\s]+)/)?.[1] ?? null;

  const norm = <T extends string>(v: string | null, allowed: readonly T[], fallback: T): T =>
    (allowed as readonly string[]).includes(v ?? "") ? (v as T) : fallback;

  const spf = norm(
    spfRaw,
    ["pass", "fail", "softfail", "neutral", "none"] as const,
    dkimHeader || blob ? "unknown" : "none",
  );
  const dkim = dkimRaw
    ? norm(dkimRaw, ["pass", "fail", "none"] as const, "unknown")
    : dkimHeader
      ? "unknown"
      : "none";
  const dmarc = dmarcRaw ? norm(dmarcRaw, ["pass", "fail", "none"] as const, "unknown") : "none";
  const aligned = !!(
    dkimDomain &&
    fromDomain &&
    (fromDomain.endsWith(dkimDomain) || dkimDomain.endsWith(fromDomain))
  );
  return { spf, dkim, dmarc, dkimDomain, aligned };
}

/* -------------------------- content heuristics -------------------------- */

const URGENCY = [
  "urgent",
  "immediately",
  "within 24 hours",
  "final warning",
  "act now",
  "last reminder",
  "account will be suspended",
  "expires today",
  "failure to comply",
  "do not ignore",
];
const CREDENTIAL = [
  "verify your account",
  "confirm your password",
  "re-enter your credentials",
  "login to continue",
  "validate your identity",
  "unlock your account",
  "click here to sign in",
];
const BEC = [
  "wire transfer",
  "change of bank details",
  "updated bank account",
  "invoice attached",
  "remittance",
  "payment must be released",
  "confidential transaction",
  "keep this between us",
  "gift card",
  "purchase order",
];
const EXEC = [
  "ceo",
  "cfo",
  "managing director",
  "chairman",
  "principal",
  "registrar",
  "director general",
];
const BRANDS = [
  "microsoft",
  "office365",
  "paypal",
  "netflix",
  "hdfc",
  "sbi",
  "icici",
  "amazon",
  "dhl",
  "irs",
  "income tax",
  "uidai",
  "aadhaar",
  "google",
];
const SUSPICIOUS_TLD = [
  "zip",
  "top",
  "xyz",
  "click",
  "gq",
  "tk",
  "ml",
  "cf",
  "work",
  "support",
  "rest",
  "cam",
  "monster",
];
const SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "is.gd",
  "rb.gy",
  "cutt.ly",
  "shorturl.at",
  "rebrand.ly",
];
const RISKY_ATTACH = [
  "exe",
  "scr",
  "js",
  "vbs",
  "iso",
  "img",
  "lnk",
  "hta",
  "docm",
  "xlsm",
  "jar",
  "zip",
  "rar",
  "7z",
  "html",
];

function levenshtein(a: string, b: string) {
  let prev: number[] = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur: number[] = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min((cur[j - 1] ?? 0) + 1, (prev[j] ?? 0) + 1, (prev[j - 1] ?? 0) + cost);
    }
    prev = cur;
  }
  return prev[b.length] ?? 0;
}

const LOOKALIKE_TARGETS = [
  "microsoft.com",
  "outlook.com",
  "gmail.com",
  "paypal.com",
  "amazon.com",
  "google.com",
  "hdfcbank.com",
  "sbi.co.in",
  "icicibank.com",
  "netflix.com",
  "apple.com",
];

function extractUrls(body: string) {
  const urls = new Set<string>();
  for (const m of body.matchAll(/https?:\/\/[^\s"'<>)\]]+/gi))
    urls.add(m[0].replace(/[.,;]+$/, ""));
  for (const m of body.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) {
    const href = m[1] ?? "";
    if (/^https?:/i.test(href)) urls.add(href);
  }
  return [...urls];
}

function hostOf(url: string) {
  const afterScheme = url.replace(/^https?:\/\//i, "");
  return (afterScheme.split(/[/?#]/)[0] ?? "").replace(/^.*@/, "").toLowerCase();
}

/* ------------------------------- analysis ------------------------------- */

export function analyzeEmail(raw: string): Analysis {
  const headers = parseHeaders(raw);
  const normalized = raw.replace(/\r\n/g, "\n");
  const body = normalized.split(/\n\n/).slice(1).join("\n\n");
  const subject = pick(headers, "subject") ?? "(no subject)";
  const fromHeader = pick(headers, "from");
  const { display: fromDisplay, address: fromAddress } = extractAddress(fromHeader);
  const fromDomain = fromAddress?.split("@")[1]?.toLowerCase() ?? null;
  const replyTo = extractAddress(pick(headers, "reply-to")).address;
  const returnPath = extractAddress(pick(headers, "return-path")).address;
  const messageId = pick(headers, "message-id");
  const auth = parseAuth(headers, fromDomain);

  const hops = pickAll(headers, "received").map((r, i) => parseReceived(r, i));
  const origin = estimateOrigin(hops);

  const findings: Finding[] = [];
  const add = (f: Finding) => findings.push(f);

  /* authentication */
  if (auth.spf === "fail" || auth.spf === "softfail")
    add({
      id: "spf-fail",
      title: `SPF ${auth.spf.toUpperCase()}`,
      detail: `The sending IP is not authorised to send for ${fromDomain ?? "the From domain"}. Classic indicator of envelope spoofing.`,
      severity: auth.spf === "fail" ? "critical" : "high",
      category: "authentication",
      weight: auth.spf === "fail" ? 22 : 14,
    });
  if (auth.spf === "none")
    add({
      id: "spf-none",
      title: "No SPF evaluation present",
      detail:
        "No Received-SPF or Authentication-Results header. The receiving infrastructure did not validate the envelope sender.",
      severity: "medium",
      category: "authentication",
      weight: 8,
    });
  if (auth.dkim === "fail")
    add({
      id: "dkim-fail",
      title: "DKIM signature verification failed",
      detail:
        "The cryptographic signature does not validate — the message body or headers were altered in transit, or the signature was forged.",
      severity: "critical",
      category: "authentication",
      weight: 20,
    });
  if (auth.dkim === "none")
    add({
      id: "dkim-none",
      title: "Message is unsigned (no DKIM)",
      detail:
        "No DKIM-Signature header. Domain ownership of the message cannot be cryptographically established.",
      severity: "medium",
      category: "authentication",
      weight: 9,
    });
  if (auth.dmarc === "fail")
    add({
      id: "dmarc-fail",
      title: "DMARC alignment failure",
      detail: `The authenticated domain does not align with the visible From domain (${fromDomain ?? "unknown"}). The message impersonates the header sender.`,
      severity: "critical",
      category: "authentication",
      weight: 24,
    });
  if (auth.dkimDomain && fromDomain && !auth.aligned)
    add({
      id: "dkim-misalign",
      title: "DKIM d= domain misaligned with From",
      detail: `Signed by "${auth.dkimDomain}" while presenting as "${fromDomain}" — third-party or spoofed signing domain.`,
      severity: "high",
      category: "authentication",
      weight: 14,
    });

  /* identity */
  if (returnPath && fromAddress && returnPath.toLowerCase() !== fromAddress.toLowerCase()) {
    const rpDomain = returnPath.split("@")[1]?.toLowerCase();
    add({
      id: "return-path",
      title: "Return-Path differs from From address",
      detail: `Envelope sender ${returnPath} does not match header sender ${fromAddress}. Bounces route to ${rpDomain ?? "an unrelated domain"}.`,
      severity: rpDomain === fromDomain ? "low" : "high",
      category: "identity",
      weight: rpDomain === fromDomain ? 3 : 13,
    });
  }
  if (replyTo && fromAddress && replyTo.toLowerCase() !== fromAddress.toLowerCase())
    add({
      id: "reply-to",
      title: "Reply-To redirection detected",
      detail: `Replies are diverted to ${replyTo} instead of ${fromAddress} — the standard conversation-hijacking and BEC payment-diversion pattern.`,
      severity: "high",
      category: "identity",
      weight: 16,
    });

  if (fromDisplay) {
    const displayAddr = extractAddress(fromDisplay).address;
    if (displayAddr && fromAddress && displayAddr.toLowerCase() !== fromAddress.toLowerCase())
      add({
        id: "display-spoof",
        title: "Display name contains a conflicting email address",
        detail: `Display name shows "${displayAddr}" while the actual sender is ${fromAddress}. Deliberate display-name spoofing.`,
        severity: "critical",
        category: "identity",
        weight: 20,
      });
    const dl = fromDisplay.toLowerCase();
    const brand = BRANDS.find((b) => dl.includes(b));
    if (brand && fromDomain && !fromDomain.includes(brand))
      add({
        id: "brand-impersonation",
        title: `Brand impersonation: "${brand}"`,
        detail: `Display name invokes ${brand} but the sending domain is ${fromDomain}.`,
        severity: "high",
        category: "identity",
        weight: 17,
      });
    if (EXEC.some((r) => dl.includes(r)))
      add({
        id: "exec-impersonation",
        title: "Executive impersonation pattern in display name",
        detail: `Display name "${fromDisplay}" claims institutional authority — typical of CEO-fraud and payment-instruction attacks.`,
        severity: "high",
        category: "identity",
        weight: 12,
      });
  }

  if (fromDomain) {
    const tld = fromDomain.split(".").pop()!;
    if (SUSPICIOUS_TLD.includes(tld))
      add({
        id: "sender-tld",
        title: `High-abuse sender TLD ".${tld}"`,
        detail: `Sender domain ${fromDomain} uses a TLD with disproportionate phishing registration volume.`,
        severity: "medium",
        category: "infrastructure",
        weight: 10,
      });
    const bare = fromDomain.replace(/^mail\.|^smtp\./, "");
    for (const target of LOOKALIKE_TARGETS) {
      const d = levenshtein(bare, target);
      if (d > 0 && d <= 2) {
        add({
          id: `lookalike-${target}`,
          title: `Lookalike domain of ${target}`,
          detail: `${fromDomain} differs from ${target} by ${d} character(s) — homoglyph/typosquat registration.`,
          severity: "critical",
          category: "infrastructure",
          weight: 22,
        });
        break;
      }
    }
    if (/[0-9]{2,}|--|xn--/.test(fromDomain))
      add({
        id: "domain-shape",
        title: "Algorithmic domain characteristics",
        detail: `${fromDomain} contains digit runs, double hyphens, or punycode — consistent with disposable or DGA-registered infrastructure.`,
        severity: "medium",
        category: "infrastructure",
        weight: 8,
      });
  }

  /* routing */
  if (hops.length === 0)
    add({
      id: "no-received",
      title: "No Received headers present",
      detail:
        "The relay chain is absent — headers were stripped or fabricated, making the transmission record unverifiable.",
      severity: "high",
      category: "routing",
      weight: 15,
    });
  if (hops.length === 1)
    add({
      id: "single-hop",
      title: "Single-hop delivery",
      detail:
        "Only one Received header — direct-to-MX injection, typical of scripted bulk senders bypassing authorised infrastructure.",
      severity: "medium",
      category: "routing",
      weight: 9,
    });
  for (const hop of hops)
    for (const note of hop.notes)
      add({
        id: `hop-${hop.index}-${note.slice(0, 12)}`,
        title: `Relay anomaly at hop ${hop.index + 1}`,
        detail: note,
        severity: "medium",
        category: "routing",
        weight: 7,
      });
  if (messageId && fromDomain) {
    const midDomain = messageId.split("@")[1]?.replace(/[<>]/g, "").toLowerCase();
    const fromRoot = fromDomain.split(".").slice(-2)[0] ?? fromDomain;
    if (midDomain && !midDomain.includes(fromRoot))
      add({
        id: "msgid-mismatch",
        title: "Message-ID domain does not match sender",
        detail: `Message-ID was generated by "${midDomain}" while the message claims to originate from ${fromDomain}.`,
        severity: "medium",
        category: "routing",
        weight: 9,
      });
  } else if (!messageId)
    add({
      id: "msgid-missing",
      title: "Message-ID header missing",
      detail:
        "Legitimate MTAs always assign a Message-ID. Its absence indicates hand-crafted or script-generated injection.",
      severity: "medium",
      category: "routing",
      weight: 10,
    });

  if (origin.infrastructure === "anonymized")
    add({
      id: "anon-infra",
      title: "Anonymizing infrastructure in origin path",
      detail: `Origin ${origin.ip ?? ""} maps to ${origin.provider ?? "an anonymizing network"} (Tor/VPN/bulletproof hosting), indicating deliberate attribution evasion.`,
      severity: "high",
      category: "infrastructure",
      weight: 15,
    });
  if (origin.infrastructure === "residential")
    add({
      id: "residential-origin",
      title: "Residential origin for institutional mail",
      detail: `Origin resolves to a consumer broadband allocation (${origin.provider ?? "unknown ISP"}) — consistent with a compromised host or botnet node.`,
      severity: "medium",
      category: "infrastructure",
      weight: 11,
    });

  /* content */
  const lowerAll = `${subject}\n${body}`.toLowerCase();
  const hits = (list: string[]) => list.filter((p) => lowerAll.includes(p));
  const urgency = hits(URGENCY);
  if (urgency.length)
    add({
      id: "urgency",
      title: "Urgency and pressure language",
      detail: `Detected ${urgency.length} coercion cue(s): ${urgency.slice(0, 4).join(", ")}.`,
      severity: urgency.length > 2 ? "high" : "medium",
      category: "content",
      weight: Math.min(14, 5 + urgency.length * 3),
    });
  const cred = hits(CREDENTIAL);
  if (cred.length)
    add({
      id: "credential",
      title: "Credential harvesting phrasing",
      detail: `The message asks the recipient to authenticate or verify identity: ${cred.slice(0, 3).join(", ")}.`,
      severity: "high",
      category: "content",
      weight: 16,
    });
  const bec = hits(BEC);
  if (bec.length)
    add({
      id: "bec",
      title: "Business email compromise indicators",
      detail: `Financial-instruction language present: ${bec.slice(0, 4).join(", ")}.`,
      severity: "critical",
      category: "content",
      weight: 18,
    });
  if (/dear (customer|user|sir\/madam|valued)/i.test(lowerAll))
    add({
      id: "generic-greeting",
      title: "Generic salutation",
      detail:
        "The message addresses the recipient impersonally despite claiming an existing relationship.",
      severity: "low",
      category: "content",
      weight: 4,
    });

  /* IOCs */
  const iocs: Ioc[] = [];
  const urls = extractUrls(body);
  for (const url of urls) {
    const host = hostOf(url);
    const tld = host.split(".").pop() ?? "";
    const shortener = SHORTENERS.includes(host);
    const ipLiteral = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const badTld = SUSPICIOUS_TLD.includes(tld);
    const mismatch = !!fromDomain && !host.endsWith(fromDomain);
    const risk: Ioc["risk"] =
      shortener || ipLiteral || badTld ? "high" : mismatch ? "medium" : "low";
    iocs.push({
      type: "url",
      value: url.length > 120 ? url.slice(0, 117) + "..." : url,
      risk,
      note: ipLiteral
        ? "Raw IP literal in link — no domain reputation possible"
        : shortener
          ? "URL shortener conceals the true destination"
          : badTld
            ? `High-abuse TLD ".${tld}"`
            : mismatch
              ? "Link host differs from sender domain"
              : "Aligned with sender domain",
    });
    if (ipLiteral)
      add({
        id: `url-ip-${host}`,
        title: "Link points to a raw IP address",
        detail: `Hyperlink targets ${host} directly, bypassing domain reputation and TLS name validation.`,
        severity: "high",
        category: "content",
        weight: 14,
      });
    if (shortener)
      add({
        id: `url-short-${host}`,
        title: `Obfuscated link via ${host}`,
        detail: "URL shortener hides the landing page from inspection and reputation systems.",
        severity: "high",
        category: "content",
        weight: 12,
      });
  }
  const anchors = [...body.matchAll(/<a[^>]+href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)]
    .map((m) => ({ href: m[1] ?? "", text: (m[2] ?? "").replace(/<[^>]+>/g, "").trim() }))
    .find((a) => /https?:\/\//i.test(a.text) && hostOf(a.text) !== hostOf(a.href));
  if (anchors)
    add({
      id: "anchor-mismatch",
      title: "Visible link text differs from href target",
      detail: `Displayed "${hostOf(anchors.text)}" but navigates to "${hostOf(anchors.href)}" — hidden redirection.`,
      severity: "critical",
      category: "content",
      weight: 20,
    });

  for (const m of normalized.matchAll(/filename\*?=\s*"?([^";\n]+)"?/gi)) {
    const name = (m[1] ?? "").trim();

    const ext = name.split(".").pop()?.toLowerCase() ?? "";
    const risky = RISKY_ATTACH.includes(ext);
    const double = /\.(pdf|docx?|xlsx?|jpg|png)\.[a-z0-9]{2,4}$/i.test(name);
    iocs.push({
      type: "attachment",
      value: name,
      risk: risky || double ? "high" : "low",
      note: double
        ? "Double extension disguising an executable payload"
        : risky
          ? `Executable or archive payload type ".${ext}"`
          : "Common document type",
    });
    if (risky || double)
      add({
        id: `attach-${name}`,
        title: `Dangerous attachment: ${name}`,
        detail: double
          ? "Double file extension used to disguise an executable as a document."
          : `Attachment type ".${ext}" is commonly used for malware delivery.`,
        severity: "critical",
        category: "content",
        weight: 18,
      });
  }

  if (origin.ip)
    iocs.push({
      type: "ip",
      value: origin.ip,
      risk: origin.infrastructure === "anonymized" ? "high" : "medium",
      note: `Originating node — ${origin.provider ?? "unclassified network"}`,
    });
  if (fromDomain)
    iocs.push({
      type: "domain",
      value: fromDomain,
      risk: findings.some((f) => f.id.startsWith("lookalike")) ? "high" : "medium",
      note: "Sender domain",
    });
  if (replyTo)
    iocs.push({ type: "email", value: replyTo, risk: "high", note: "Reply-To collection address" });

  /* scoring */
  const rawScore = findings.reduce((s, f) => s + f.weight, 0);
  let score = Math.min(100, Math.round(rawScore));
  if (auth.spf === "pass" && auth.dkim === "pass" && auth.dmarc === "pass")
    score = Math.max(0, score - 18);
  const verdict: Verdict =
    score >= 78
      ? "fraud"
      : score >= 58
        ? "phishing"
        : score >= 42
          ? "impersonation"
          : score >= 22
            ? "suspicious"
            : "legitimate";

  /* attribution */
  const rationale: string[] = [];
  let scenario = "Insufficient indicators for attribution";
  let attrConfidence = 25;
  const hasSpoof = findings.some(
    (f) =>
      ["spf-fail", "dmarc-fail", "display-spoof"].includes(f.id) || f.id.startsWith("lookalike"),
  );
  const compromised = auth.spf === "pass" && auth.dmarc === "pass" && score >= 42;
  if (origin.infrastructure === "anonymized") {
    scenario = "Actor operating behind anonymized infrastructure";
    attrConfidence = 58;
    rationale.push(
      "Origin node belongs to an anonymizing or bulletproof network; true actor location is masked.",
    );
  } else if (compromised) {
    scenario = "Likely compromised legitimate mailbox";
    attrConfidence = 66;
    rationale.push(
      "Authentication passes for the claimed domain while content shows fraud indicators — consistent with account takeover rather than spoofing.",
    );
  } else if (hasSpoof) {
    scenario = "Domain spoofing / lookalike infrastructure operated by the actor";
    attrConfidence = 71;
    rationale.push(
      "Sender authentication or domain similarity indicates attacker-controlled infrastructure impersonating a trusted entity.",
    );
  } else if (score >= 22) {
    scenario = "Opportunistic bulk sender or low-sophistication phishing";
    attrConfidence = 44;
    rationale.push(
      "Content heuristics trigger without authentication forgery — typical of mass-mailed campaigns.",
    );
  } else {
    scenario = "No adversarial attribution indicated";
    attrConfidence = 30;
    rationale.push("Authentication and routing are consistent with the claimed sender.");
  }
  if (origin.country)
    rationale.push(
      `Probable operating region: ${[origin.region, origin.country].filter(Boolean).join(", ")} (${origin.confidence}% geolocation confidence).`,
    );
  if (replyTo) rationale.push(`Actor-controlled collection address observed: ${replyTo}.`);

  return {
    id: (messageId ?? `case-${Date.now()}`).replace(/[<>]/g, "").slice(0, 64),
    analyzedAt: new Date().toISOString(),
    headers,
    subject,
    fromDisplay,
    fromAddress,
    fromDomain,
    replyTo,
    returnPath,
    messageId,
    to: pick(headers, "to"),
    date: pick(headers, "date"),
    body,
    hops,
    auth,
    findings: findings.sort((a, b) => b.weight - a.weight),
    iocs,
    origin,
    score,
    verdict,
    attribution: { scenario, confidence: attrConfidence, rationale },
  };
}

/* ========================= live enrichment ========================= */

/**
 * DNS-over-HTTPS helper (Cloudflare).
 * Returns the first TXT answer string, or null on failure.
 */
async function dohLookup(name: string, type: "TXT" = "TXT"): Promise<string | null> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
  const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
  if (!res.ok) return null;
  const json = (await res.json()) as {
    Answer?: Array<{ type: number; data: string }>;
  };
  const answers = (json.Answer ?? []).filter((a) => a.type === 16 /* TXT */);
  if (!answers.length) return null;
  // TXT data may be quoted
  return (answers[0]!.data ?? "").replace(/^"|"$/g, "").trim();
}

/**
 * Extend a base Analysis with live DNS, RDAP, and geo enrichment.
 * All network calls are individually try/catch'd — failures produce no
 * findings (graceful degradation).
 */
export async function analyzeEmailAsync(
  raw: string,
  opts: { liveGeoEnabled?: boolean } = {},
): Promise<Analysis> {
  const base = analyzeEmail(raw);
  const liveGeoEnabled = opts.liveGeoEnabled ?? true;

  const enrichment: LiveEnrichment = {
    spfDnsRecord: null,
    dkimDnsRecord: null,
    domainRegisteredAt: null,
    domainAgeDays: null,
    liveGeo: null,
  };

  const extraFindings: Finding[] = [];

  // ── 1. Live SPF DNS check ──────────────────────────────────────────────
  if (base.fromDomain) {
    try {
      const spfTxt = await dohLookup(base.fromDomain);
      enrichment.spfDnsRecord = spfTxt;
      if (spfTxt) {
        // Determine whether the live SPF record contradicts the header verdict
        const liveHardFail = /\s-all\b/.test(spfTxt);
        const liveSoftFail = /\s~all\b/.test(spfTxt);
        const headerPass = base.auth.spf === "pass";
        const headerFail = base.auth.spf === "fail" || base.auth.spf === "softfail";

        if (liveHardFail && headerPass) {
          extraFindings.push({
            id: "dns-spf-disagree",
            title: "Authentication-Results disagrees with live SPF DNS record",
            detail: `Live DNS shows the SPF policy for ${base.fromDomain} ends in -all (hard fail), ` +
              `but the Authentication-Results header reports spf=pass. ` +
              `This may indicate a forged or tampered Authentication-Results header.`,
            severity: "critical",
            category: "authentication",
            weight: 20,
          });
        } else if (!liveHardFail && !liveSoftFail && headerFail) {
          extraFindings.push({
            id: "dns-spf-disagree",
            title: "Authentication-Results disagrees with live SPF DNS record",
            detail: `Live DNS shows the SPF policy for ${base.fromDomain} has no explicit fail qualifier, ` +
              `but the Authentication-Results header reports spf=${base.auth.spf}. ` +
              `The SPF policy may have been recently changed, or the header may have been manipulated.`,
            severity: "critical",
            category: "authentication",
            weight: 20,
          });
        }
      }
    } catch {
      // Network unavailable or CORS blocked — silent fallback
    }
  }

  // ── 2. Live DKIM DNS check ─────────────────────────────────────────────
  if (base.fromDomain && base.auth.dkimDomain) {
    // Extract selector from the DKIM-Signature header s= tag
    const dkimSigHeader = base.headers.find(
      (h) => h.name.toLowerCase() === "dkim-signature",
    );
    const selector = dkimSigHeader?.value.match(/(?:^|;)\s*s=([^;\s]+)/i)?.[1] ?? null;
    if (selector) {
      const dkimName = `${selector}._domainkey.${base.auth.dkimDomain}`;
      try {
        const dkimTxt = await dohLookup(dkimName);
        enrichment.dkimDnsRecord = dkimTxt;
        const headerDkimPass = base.auth.dkim === "pass";
        const headerDkimFail = base.auth.dkim === "fail";

        if (dkimTxt === null && headerDkimPass) {
          // No DKIM record exists in live DNS but header says pass
          extraFindings.push({
            id: "dns-dkim-disagree",
            title: "Authentication-Results disagrees with live DKIM DNS record",
            detail: `Live DNS query for ${dkimName} returned no TXT record, ` +
              `but the Authentication-Results header reports dkim=pass. ` +
              `This is a strong indicator that the Authentication-Results header was forged.`,
            severity: "critical",
            category: "authentication",
            weight: 20,
          });
        } else if (dkimTxt !== null && headerDkimFail) {
          extraFindings.push({
            id: "dns-dkim-disagree",
            title: "Authentication-Results disagrees with live DKIM DNS record",
            detail: `Live DNS confirms a DKIM public key exists at ${dkimName}, ` +
              `but the Authentication-Results header reports dkim=fail. ` +
              `The message body or headers were likely altered in transit after signing.`,
            severity: "critical",
            category: "authentication",
            weight: 20,
          });
        }
      } catch {
        // Silent fallback
      }
    }
  }

  // ── 3. RDAP domain age check ───────────────────────────────────────────
  if (base.fromDomain) {
    try {
      const rdapRes = await fetch(`https://rdap.org/domain/${encodeURIComponent(base.fromDomain)}`, {
        headers: { Accept: "application/json" },
      });
      if (rdapRes.ok) {
        const rdapJson = (await rdapRes.json()) as {
          events?: Array<{ eventAction: string; eventDate: string }>;
        };
        const regEvent = (rdapJson.events ?? []).find(
          (e) => e.eventAction === "registration",
        );
        if (regEvent?.eventDate) {
          enrichment.domainRegisteredAt = regEvent.eventDate;
          const registeredMs = Date.parse(regEvent.eventDate);
          if (!isNaN(registeredMs)) {
            const ageDays = Math.floor((Date.now() - registeredMs) / 86_400_000);
            enrichment.domainAgeDays = ageDays;
            if (ageDays < 30) {
              extraFindings.push({
                id: "domain-age-new",
                title: "Domain registered less than 30 days ago",
                detail: `${base.fromDomain} was registered only ${ageDays} day(s) ago (${regEvent.eventDate.slice(0, 10)}). ` +
                  `Newly registered domains are strongly associated with phishing and fraud campaigns.`,
                severity: "high",
                category: "infrastructure",
                weight: 15,
              });
            } else if (ageDays < 365) {
              extraFindings.push({
                id: "domain-age-young",
                title: "Domain registered less than 1 year ago",
                detail: `${base.fromDomain} was registered ${ageDays} day(s) ago (${regEvent.eventDate.slice(0, 10)}). ` +
                  `Young domains are common in phishing infrastructure before detection and takedown.`,
                severity: "medium",
                category: "infrastructure",
                weight: 8,
              });
            }
          }
        }
      }
    } catch {
      // RDAP unavailable or CORS blocked — silent fallback
    }
  }

  // ── 4. Live ML Engine & IP geo/ASN lookup ─────────────────────────────
  try {
    const formData = new FormData();
    const blob = new Blob([raw], { type: "message/rfc822" });
    formData.append("file", blob, "email.eml");

    const mlRes = await fetch("http://127.0.0.1:8000/analyze-eml", {
      method: "POST",
      body: formData,
    });

    if (mlRes.ok) {
      const mlData = await mlRes.json();
      if (mlData && mlData.trace_summary) {
        const trace = mlData.trace_summary;
        const geo = trace.geolocation || {};

        if (trace.originating_ip_candidate) {
          base.origin.ip = trace.originating_ip_candidate;
        }

        if (geo.country) {
          base.origin.country = geo.country;
          base.origin.region = geo.region || base.origin.region;
          base.origin.provider = geo.isp || trace.cloud_provider || base.origin.provider;
          if (geo.latitude) base.origin.latitude = geo.latitude;
          if (geo.longitude) base.origin.longitude = geo.longitude;
          base.origin.confidence = 90;
          base.origin.basis.push(
            `ML Engine: ${geo.isp || "ISP"} · ${geo.city || ""}, ${geo.country} (${trace.inferred_timezone || ""})`
          );
        }

        if (mlData.explainability_highlights && Array.isArray(mlData.explainability_highlights)) {
          for (const highlight of mlData.explainability_highlights) {
            extraFindings.push({
              id: `ml-highlight-${Math.random().toString(36).slice(2, 7)}`,
              title: "ML Threat & Diagnostic Highlight",
              detail: highlight,
              severity: highlight.includes("[Header Anomaly]") || highlight.includes("[URL Threat]") ? "high" : "info",
              category: "infrastructure",
              weight: highlight.includes("[Header Anomaly]") ? 10 : 2,
            });
          }
        }
      }
    }
  } catch {
    // Local ML server unavailable — fallback to client-side analysis
  }

  if (liveGeoEnabled && base.origin.ip && base.origin.ipClass === "public" && (!enrichment.liveGeo)) {
    try {
      const geoRes = await fetch(`https://ipapi.co/${base.origin.ip}/json/`, {
        headers: { Accept: "application/json" },
      });
      if (geoRes.ok) {
        const geo = (await geoRes.json()) as {
          country_name?: string;
          region?: string;
          org?: string;
          latitude?: number;
          longitude?: number;
          error?: boolean;
        };
        if (!geo.error && geo.country_name) {
          enrichment.liveGeo = {
            country: geo.country_name ?? "Unknown",
            region: geo.region ?? "Unknown",
            org: geo.org ?? "Unknown",
            lat: geo.latitude ?? 0,
            lon: geo.longitude ?? 0,
          };
          base.origin.country = geo.country_name ?? base.origin.country;
          base.origin.region = geo.region ?? base.origin.region;
          base.origin.provider = geo.org ?? base.origin.provider;
          base.origin.latitude = geo.latitude ?? base.origin.latitude;
          base.origin.longitude = geo.longitude ?? base.origin.longitude;
          base.origin.confidence = 85;
          base.origin.basis.push(
            `Live IP geo lookup: ${geo.org ?? "unknown org"} · ${geo.country_name ?? ""} (85% confidence)`,
          );
        }
      }
    } catch {
      // ipapi.co unavailable — static data applied
    }
  }

  // ── Merge extra findings into base & re-sort ───────────────────────────
  const merged = [...base.findings, ...extraFindings].sort((a, b) => b.weight - a.weight);

  // Re-compute score (same formula as analyzeEmail)
  const rawScore = merged.reduce((s, f) => s + f.weight, 0);
  let score = Math.min(100, Math.round(rawScore));
  if (base.auth.spf === "pass" && base.auth.dkim === "pass" && base.auth.dmarc === "pass")
    score = Math.max(0, score - 18);
  const verdict: Verdict =
    score >= 78
      ? "fraud"
      : score >= 58
        ? "phishing"
        : score >= 42
          ? "impersonation"
          : score >= 22
            ? "suspicious"
            : "legitimate";

  return {
    ...base,
    findings: merged,
    score,
    verdict,
    liveEnrichment: enrichment,
  };
}

/* ======================== PDF export ======================== */

/**
 * Generates a formatted PDF forensic report using jsPDF.
 * Returns a Blob suitable for triggering a browser download.
 * This function is async because jsPDF is dynamically imported to keep
 * the initial bundle lean.
 */
export async function buildPdfReport(a: Analysis): Promise<Blob> {
  const { jsPDF } = await import("jspdf");
  const doc = new jsPDF({ unit: "mm", format: "a4" });

  const PAGE_W = 210;
  const MARGIN = 14;
  const CONTENT_W = PAGE_W - MARGIN * 2;
  const LINE_H = 5.5;
  const SECTION_GAP = 3;
  let y = 18;

  const checkPage = (needed = LINE_H) => {
    if (y + needed > 282) {
      doc.addPage();
      y = 18;
    }
  };

  const rule = () => {
    checkPage(4);
    doc.setDrawColor(60, 60, 70);
    doc.setLineWidth(0.3);
    doc.line(MARGIN, y, PAGE_W - MARGIN, y);
    y += 3;
  };

  const heading = (text: string, level: 1 | 2 = 1) => {
    checkPage(10);
    if (level === 1) {
      doc.setFontSize(13);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(40, 40, 50);
    } else {
      doc.setFontSize(10);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(60, 80, 120);
    }
    doc.text(text, MARGIN, y);
    y += LINE_H + 1;
  };

  const body = (text: string, indent = 0) => {
    doc.setFontSize(8.5);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(50, 50, 60);
    const lines = doc.splitTextToSize(text, CONTENT_W - indent);
    for (const line of lines as string[]) {
      checkPage();
      doc.text(line, MARGIN + indent, y);
      y += LINE_H;
    }
  };

  const kv = (key: string, value: string) => {
    checkPage();
    doc.setFontSize(8.5);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(50, 50, 60);
    doc.text(`${key}:`, MARGIN, y);
    doc.setFont("helvetica", "normal");
    const valLines = doc.splitTextToSize(value, CONTENT_W - 38);
    doc.text(valLines as string[], MARGIN + 38, y);
    y += LINE_H * (valLines as string[]).length;
  };

  const severityColor = (sev: Finding["severity"]): [number, number, number] => {
    switch (sev) {
      case "critical": return [200, 40, 40];
      case "high":     return [210, 100, 20];
      case "medium":   return [180, 150, 20];
      case "low":      return [80, 140, 80];
      default:         return [100, 100, 120];
    }
  };

  // ── Cover ────────────────────────────────────────────────────────────
  doc.setFillColor(24, 24, 36);
  doc.rect(0, 0, PAGE_W, 40, "F");
  doc.setFontSize(18);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(220, 220, 240);
  doc.text("EMAIL THREAT & FORENSIC INTELLIGENCE REPORT", MARGIN, 20);
  doc.setFontSize(9);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(160, 160, 200);
  doc.text(`Generated (UTC): ${a.analyzedAt}   ·   Case: ${a.id.slice(0, 40)}`, MARGIN, 29);
  doc.setTextColor(220, 220, 240);
  doc.setFontSize(11);
  doc.text(`Verdict: ${a.verdict.toUpperCase()}   ·   Risk Score: ${a.score}/100`, MARGIN, 36);
  y = 50;

  // ── 1. Message Identification ─────────────────────────────────────────
  rule();
  heading("1. Message Identification");
  kv("Subject", a.subject);
  kv("From", `${a.fromDisplay ? `"${a.fromDisplay}" ` : ""}<${a.fromAddress ?? "unknown"}>`);
  kv("To", a.to ?? "n/a");
  kv("Reply-To", a.replyTo ?? "not set");
  kv("Return-Path", a.returnPath ?? "not set");
  kv("Message-ID", a.messageId ?? "absent");
  kv("Date", a.date ?? "n/a");
  y += SECTION_GAP;

  // ── 2. Sender Authentication ──────────────────────────────────────────
  rule();
  heading("2. Sender Authentication");
  kv("SPF", a.auth.spf);
  kv("DKIM", a.auth.dkim);
  kv("DMARC", a.auth.dmarc);
  kv("DKIM signing domain", `${a.auth.dkimDomain ?? "none"} (alignment: ${a.auth.aligned ? "aligned" : "not aligned"})`);
  if (a.liveEnrichment) {
    y += 1;
    heading("Live DNS Enrichment", 2);
    kv("SPF DNS record", a.liveEnrichment.spfDnsRecord ?? "lookup failed / not run");
    kv("DKIM DNS record", a.liveEnrichment.dkimDnsRecord ?? "lookup failed / not run");
    kv("Domain registered", a.liveEnrichment.domainRegisteredAt
      ? `${a.liveEnrichment.domainRegisteredAt.slice(0, 10)} (${a.liveEnrichment.domainAgeDays} days ago)`
      : "lookup failed / not run");
  }
  y += SECTION_GAP;

  // ── 3. Relay Path ────────────────────────────────────────────────────
  rule();
  heading("3. Relay Path Reconstruction");
  if (a.hops.length === 0) {
    body("No Received headers present — the transmission record is absent or was stripped.");
  } else {
    for (const [i, h] of [...a.hops].reverse().entries()) {
      checkPage(12);
      heading(`Hop ${i + 1}: ${h.from ?? "?"} → ${h.by ?? "?"}`, 2);
      kv("IP", `${h.ip ?? "—"} (${h.ipClass})`);
      kv("Protocol", h.protocol ?? "unknown");
      if (h.timestamp) kv("Timestamp", h.timestamp);
      for (const note of h.notes) body(`⚠ ${note}`, 4);
    }
  }
  y += SECTION_GAP;

  // ── 4. Origin Estimation ──────────────────────────────────────────────
  rule();
  heading("4. Origin Estimation");
  kv("Earliest reliable node", a.origin.ip ?? "undetermined");
  kv("Reverse host", a.origin.reverseHost ?? "n/a");
  kv("Estimated location", [a.origin.region, a.origin.country].filter(Boolean).join(", ") || "undetermined");
  kv("Network / provider", `${a.origin.provider ?? "unclassified"} (${a.origin.infrastructure})`);
  kv("Geo confidence", `${a.origin.confidence}%`);
  for (const b of a.origin.basis) body(`• ${b}`, 4);
  y += SECTION_GAP;

  // ── 5. Findings ───────────────────────────────────────────────────────
  rule();
  heading("5. Findings");
  if (a.findings.length === 0) {
    body("No adverse findings.");
  } else {
    for (const f of a.findings) {
      checkPage(18);
      const [r, g, b] = severityColor(f.severity);
      doc.setFillColor(r, g, b);
      doc.roundedRect(MARGIN, y - 3.5, 22, 5, 1, 1, "F");
      doc.setFontSize(7);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(255, 255, 255);
      doc.text(f.severity.toUpperCase(), MARGIN + 1.5, y);
      doc.setTextColor(80, 80, 100);
      doc.setFontSize(7.5);
      doc.setFont("helvetica", "normal");
      doc.text(`${f.category}  ·  +${f.weight} risk`, MARGIN + 24, y);
      y += LINE_H;
      body(f.title.toUpperCase(), 0);
      body(f.detail, 4);
      y += 1.5;
    }
  }
  y += SECTION_GAP;

  // ── 6. IOCs ───────────────────────────────────────────────────────────
  rule();
  heading("6. Indicators of Compromise");
  if (a.iocs.length === 0) {
    body("None extracted.");
  } else {
    for (const ioc of a.iocs) {
      checkPage();
      doc.setFontSize(8.5);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(60, 60, 80);
      doc.text(`(${ioc.risk}) ${ioc.type}:`, MARGIN, y);
      doc.setFont("helvetica", "normal");
      const valLine = doc.splitTextToSize(`${ioc.value}  —  ${ioc.note}`, CONTENT_W - 30);
      doc.text(valLine as string[], MARGIN + 30, y);
      y += LINE_H * (valLine as string[]).length;
    }
  }
  y += SECTION_GAP;

  // ── 7. Attribution ────────────────────────────────────────────────────
  rule();
  heading("7. Attribution Assessment");
  kv("Scenario", a.attribution.scenario);
  kv("Confidence", `${a.attribution.confidence}%`);
  for (const r of a.attribution.rationale) body(`• ${r}`, 4);
  y += SECTION_GAP;

  // ── 8. Evidentiary Note ───────────────────────────────────────────────
  rule();
  heading("8. Evidentiary Note");
  body(
    "Analysis performed locally on the submitted message copy; no message content was " +
    "transmitted to third parties (DNS-over-HTTPS, RDAP, and geo queries transmit only the " +
    "sender domain and originating IP, never message content). Findings are probabilistic " +
    "investigative indicators, not conclusive proof of identity.",
  );

  return doc.output("blob");
}

export function buildReport(a: Analysis): string {
  const line = "=".repeat(72);
  const sev = (s: string) => s.toUpperCase().padEnd(8);
  return [
    line,
    "EMAIL THREAT & FORENSIC INTELLIGENCE REPORT",
    line,
    `Case reference   : ${a.id}`,
    `Generated (UTC)  : ${a.analyzedAt}`,
    `Verdict          : ${a.verdict.toUpperCase()}  (risk score ${a.score}/100)`,
    "",
    "1. MESSAGE IDENTIFICATION",
    `   Subject       : ${a.subject}`,
    `   From          : ${a.fromDisplay ? `"${a.fromDisplay}" ` : ""}<${a.fromAddress ?? "unknown"}>`,
    `   To            : ${a.to ?? "n/a"}`,
    `   Reply-To      : ${a.replyTo ?? "n/a"}`,
    `   Return-Path   : ${a.returnPath ?? "n/a"}`,
    `   Message-ID    : ${a.messageId ?? "absent"}`,
    `   Date          : ${a.date ?? "n/a"}`,
    "",
    "2. SENDER AUTHENTICATION",
    `   SPF ${a.auth.spf} | DKIM ${a.auth.dkim} | DMARC ${a.auth.dmarc}`,
    `   DKIM signing domain: ${a.auth.dkimDomain ?? "none"} (alignment: ${a.auth.aligned ? "aligned" : "not aligned"})`,
    "",
    "3. RELAY PATH RECONSTRUCTION",
    ...(a.hops.length
      ? a.hops.map(
          (h, i) =>
            `   Hop ${i + 1}: from ${h.from ?? "?"} [${h.ip ?? "no ip"}] by ${h.by ?? "?"} via ${h.protocol ?? "?"}${h.timestamp ? ` at ${h.timestamp}` : ""}`,
        )
      : ["   No Received headers present."]),
    "",
    "4. ORIGIN ESTIMATION",
    `   Earliest reliable node : ${a.origin.ip ?? "undetermined"}`,
    `   Reverse host           : ${a.origin.reverseHost ?? "n/a"}`,
    `   Estimated location     : ${[a.origin.region, a.origin.country].filter(Boolean).join(", ") || "undetermined"}`,
    `   Network / provider     : ${a.origin.provider ?? "unclassified"} (${a.origin.infrastructure})`,
    `   Geolocation confidence : ${a.origin.confidence}%`,
    ...a.origin.basis.map((b) => `   - ${b}`),
    "",
    "5. FINDINGS",
    ...(a.findings.length
      ? a.findings.map((f) => `   [${sev(f.severity)}] ${f.title}\n      ${f.detail}`)
      : ["   No adverse findings."]),
    "",
    "6. INDICATORS OF COMPROMISE",
    ...(a.iocs.length
      ? a.iocs.map((i) => `   (${i.risk}) ${i.type}: ${i.value} — ${i.note}`)
      : ["   None extracted."]),
    "",
    "7. ATTRIBUTION ASSESSMENT",
    `   Scenario   : ${a.attribution.scenario}`,
    `   Confidence : ${a.attribution.confidence}%`,
    ...a.attribution.rationale.map((r) => `   - ${r}`),
    "",
    "8. EVIDENTIARY NOTE",
    "   Analysis performed locally on the submitted message copy; no content was",
    "   transmitted to third parties. Findings are probabilistic investigative",
    "   indicators, not conclusive proof of identity. Geolocation reflects network",
    "   allocation data and may represent intermediary infrastructure.",
    line,
  ].join("\n");
}

export const SAMPLE_EMAIL = `Received: from mx.institute.edu.in (mx.institute.edu.in [10.14.2.8])
	by inbox.institute.edu.in with ESMTPS id 4Kz9Qm2Xy1z; Tue, 25 Aug 2026 09:41:12 +0530
Received: from mail.secure-verify-hdfc-bank.top (unknown [45.148.10.77])
	by mx.institute.edu.in with SMTP id 8Bn2Lk9Pq; Tue, 25 Aug 2026 09:41:08 +0530
Authentication-Results: mx.institute.edu.in; spf=fail smtp.mailfrom=secure-verify-hdfc-bank.top; dkim=none; dmarc=fail header.from=hdfcbank.com
Received-SPF: fail (mx.institute.edu.in: domain of secure-verify-hdfc-bank.top does not designate 45.148.10.77 as permitted sender)
From: "HDFC Bank Security <alerts@hdfcbank.com>" <billing@secure-verify-hdfc-bank.top>
Reply-To: recovery.desk.verify@mail-inbox-support.xyz
Return-Path: <bounce-8823@secure-verify-hdfc-bank.top>
To: accounts@institute.edu.in
Subject: URGENT: Final warning - your account will be suspended within 24 hours
Date: Tue, 25 Aug 2026 09:41:05 +0530
Content-Type: multipart/mixed; boundary="b1"
X-Mailer: PHPMailer 5.2.9

--b1
Content-Type: text/html

<p>Dear Customer,</p>
<p>Our records show a pending wire transfer with updated bank account details.
You must verify your account immediately or access will be revoked.</p>
<p><a href="http://45.148.10.77/hdfc/session/verify.php">https://netbanking.hdfcbank.com/login</a></p>
<p>Alternatively use https://bit.ly/3xVerifyNow to validate your identity.</p>
--b1
Content-Type: application/octet-stream; name="Invoice_August.pdf.exe"
Content-Disposition: attachment; filename="Invoice_August.pdf.exe"
--b1--
`;
