/**
 * MailForensix — Centralized Severity & Risk Classification System
 * Single source of truth for threat tiers, verdict labels, forensic color tokens,
 * authentication badges, infrastructure tagging, and defanging utilities.
 */

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'info';

export type RiskTier = 'critical' | 'high' | 'medium' | 'low' | 'clean';

export type AuthStatus = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unavailable';

export interface SeverityStyleTokens {
  level: SeverityLevel;
  label: string;
  colorVar: string;
  hex: string;
  textColor: string;
  bgColor: string;
  borderColor: string;
  badgeClass: string;
  dotClass: string;
}

/**
 * Standardized Risk Tier classification by composite score (0 - 100)
 */
export function getRiskTier(score: number | null | undefined): RiskTier {
  if (score === null || score === undefined || isNaN(score)) return 'clean';
  const s = Math.max(0, Math.min(100, Math.round(score)));
  if (s >= 75) return 'critical';
  if (s >= 50) return 'high';
  if (s >= 25) return 'medium';
  if (s > 0) return 'low';
  return 'clean';
}

/**
 * Standardized Verdict Category by composite risk score
 */
export function getVerdictForScore(score: number | null | undefined): string {
  if (score === null || score === undefined || isNaN(score)) return 'Legitimate';
  const s = Math.max(0, Math.min(100, Math.round(score)));
  if (s >= 80) return 'Fraud / BEC';
  if (s >= 60) return 'Phishing';
  if (s >= 40) return 'Impersonation';
  if (s >= 20) return 'Suspicious';
  return 'Legitimate';
}

/**
 * Normalize string or numeric severity / category input to canonical SeverityLevel
 */
export function normalizeSeverity(input: string | number | null | undefined): SeverityLevel {
  if (typeof input === 'number') {
    return getRiskTier(input);
  }
  if (!input) return 'info';

  const s = String(input).toLowerCase().trim();

  if (s.includes('critical') || s.includes('fraud') || s.includes('bec') || s.includes('malware')) {
    return 'critical';
  }
  if (s.includes('high') || s.includes('phishing')) {
    return 'high';
  }
  if (s.includes('medium') || s.includes('impersonation') || s.includes('suspicious') || s.includes('warning')) {
    return 'medium';
  }
  if (s.includes('low') || s.includes('nominal')) {
    return 'low';
  }
  if (s.includes('clean') || s.includes('legitimate') || s.includes('pass') || s.includes('aligned') || s.includes('true')) {
    return 'clean';
  }

  return 'info';
}

/**
 * Static lookup table for consistent semantic severity tokens
 */
const SEVERITY_REGISTRY: Record<SeverityLevel, Omit<SeverityStyleTokens, 'level' | 'label'>> = {
  critical: {
    colorVar: 'var(--critical)',
    hex: '#ff2a55',
    textColor: 'text-critical',
    bgColor: 'bg-critical/15',
    borderColor: 'border-critical/35',
    badgeClass: 'bg-critical/15 text-critical border-critical/35',
    dotClass: 'bg-critical',
  },
  high: {
    colorVar: 'var(--high)',
    hex: '#ff8c00',
    textColor: 'text-high',
    bgColor: 'bg-high/15',
    borderColor: 'border-high/35',
    badgeClass: 'bg-high/15 text-high border-high/35',
    dotClass: 'bg-high',
  },
  medium: {
    colorVar: 'var(--medium)',
    hex: '#ffcc00',
    textColor: 'text-medium',
    bgColor: 'bg-medium/15',
    borderColor: 'border-medium/35',
    badgeClass: 'bg-medium/15 text-medium border-medium/35',
    dotClass: 'bg-medium',
  },
  low: {
    colorVar: 'var(--low)',
    hex: '#38bdf8',
    textColor: 'text-low',
    bgColor: 'bg-low/15',
    borderColor: 'border-low/30',
    badgeClass: 'bg-low/15 text-low border-low/30',
    dotClass: 'bg-low',
  },
  clean: {
    colorVar: 'var(--clean)',
    hex: '#00e676',
    textColor: 'text-clean',
    bgColor: 'bg-clean/15',
    borderColor: 'border-clean/35',
    badgeClass: 'bg-clean/15 text-clean border-clean/35',
    dotClass: 'bg-clean',
  },
  info: {
    colorVar: 'var(--muted-foreground)',
    hex: '#8b9bb4',
    textColor: 'text-muted-foreground',
    bgColor: 'bg-surface-2',
    borderColor: 'border-border',
    badgeClass: 'bg-surface-2 text-muted-foreground border-border',
    dotClass: 'bg-muted-foreground',
  },
};

/**
 * Returns comprehensive styling tokens for any severity level or risk score
 */
export function getSeverityTokens(severityOrScore: string | number | null | undefined, customLabel?: string): SeverityStyleTokens {
  const level = normalizeSeverity(severityOrScore);
  const base = SEVERITY_REGISTRY[level];
  const label = customLabel || (typeof severityOrScore === 'string' ? severityOrScore : level.toUpperCase());

  return {
    level,
    label,
    ...base,
  };
}

/**
 * CSS Color variable string helper (compatible with legacy callers)
 */
export function getSeverityColorVar(severityOrScore: string | number | null | undefined): string {
  return getSeverityTokens(severityOrScore).colorVar;
}

/**
 * Hex color code helper (for Canvas/WebGL/SVG engines like ForceGraph & MapLibre)
 */
export function getSeverityHex(severityOrScore: string | number | null | undefined): string {
  return getSeverityTokens(severityOrScore).hex;
}

/**
 * Authentication status tokens (SPF, DKIM, DMARC, Alignment)
 */
export function getAuthStatusTokens(status: string | null | undefined): {
  status: AuthStatus;
  label: string;
  isPositive: boolean;
  tokens: SeverityStyleTokens;
} {
  const s = String(status || 'unavailable').toLowerCase().trim();

  let authStatus: AuthStatus = 'unavailable';
  let severity: SeverityLevel = 'info';

  if (s === 'pass' || s === 'aligned' || s === 'true' || s === 'verified') {
    authStatus = 'pass';
    severity = 'clean';
  } else if (s === 'fail' || s === 'false' || s === 'disagrees') {
    authStatus = 'fail';
    severity = 'critical';
  } else if (s === 'softfail') {
    authStatus = 'softfail';
    severity = 'high';
  } else if (s === 'neutral') {
    authStatus = 'neutral';
    severity = 'medium';
  } else if (s === 'none') {
    authStatus = 'none';
    severity = 'info';
  }

  return {
    status: authStatus,
    label: s.toUpperCase(),
    isPositive: authStatus === 'pass',
    tokens: getSeverityTokens(severity, s.toUpperCase()),
  };
}

/**
 * Infrastructure anomaly tokens (Tor, VPN, Hosting Cloud, Residential, Private)
 */
export function getInfrastructureTokens(infraType: string | null | undefined, flags?: { vpn?: boolean; tor?: boolean; hosting?: boolean }): {
  label: string;
  category: 'tor' | 'vpn' | 'hosting' | 'residential' | 'private' | 'unknown';
  tokens: SeverityStyleTokens;
} {
  const type = String(infraType || '').toLowerCase().trim();
  const isTor = flags?.tor || type.includes('tor');
  const isVpn = flags?.vpn || type.includes('vpn') || type.includes('proxy');
  const isHosting = flags?.hosting || type.includes('hosting') || type.includes('cloud') || type.includes('aws') || type.includes('gcp') || type.includes('azure');
  const isPrivate = type.includes('private') || type.includes('lan') || type.includes('loopback');

  if (isTor) {
    return {
      label: 'Tor Exit Node',
      category: 'tor',
      tokens: getSeverityTokens('critical', 'TOR'),
    };
  }
  if (isVpn) {
    return {
      label: 'VPN / Proxy',
      category: 'vpn',
      tokens: getSeverityTokens('high', 'VPN'),
    };
  }
  if (isHosting) {
    return {
      label: 'Cloud / Hosting',
      category: 'hosting',
      tokens: getSeverityTokens('medium', 'HOSTING'),
    };
  }
  if (isPrivate) {
    return {
      label: 'Private Network',
      category: 'private',
      tokens: getSeverityTokens('info', 'PRIVATE'),
    };
  }

  return {
    label: 'Public Transit',
    category: 'residential',
    tokens: getSeverityTokens('low', 'PUBLIC'),
  };
}

/**
 * DFIR Safety: Defang potentially malicious URLs to prevent accidental clicks
 * Example: "https://evil.com/payload.exe" -> "hxxps[://]evil[.]com/payload.exe"
 */
export function defangUrl(url: string | null | undefined): string {
  if (!url) return '';
  return url
    .replace(/^https?:\/\//i, (match) => match.toLowerCase().startsWith('https') ? 'hxxps[://]' : 'hxxp[://]')
    .replace(/\./g, '[.]');
}

/**
 * DFIR Safety: Defang IP addresses for investigative reports
 * Example: "192.168.1.1" -> "192.168.1[.]1"
 */
export function defangIp(ip: string | null | undefined): string {
  if (!ip) return '';
  const lastDotIdx = ip.lastIndexOf('.');
  if (lastDotIdx === -1) return ip;
  return ip.substring(0, lastDotIdx) + '[.]' + ip.substring(lastDotIdx + 1);
}

/**
 * Format bytes into human-readable forensic evidence sizes
 */
export function formatBytes(bytes: number, decimals: number = 1): string {
  if (!bytes || bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
}
