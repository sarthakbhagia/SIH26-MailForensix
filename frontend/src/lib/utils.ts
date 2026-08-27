import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getSeverityColor(severity: string | number) {
  if (typeof severity === 'number') {
    if (severity >= 76) return 'text-critical';
    if (severity >= 51) return 'text-high';
    if (severity >= 26) return 'text-medium';
    return 'text-clean';
  }
  
  switch (severity?.toLowerCase()) {
    case 'critical':
    case 'fraud':
      return 'text-critical';
    case 'high':
    case 'phishing':
      return 'text-high';
    case 'medium':
    case 'impersonation':
      return 'text-medium';
    case 'low':
    case 'suspicious':
      return 'text-low';
    case 'clean':
    case 'legitimate':
      return 'text-clean';
    default:
      return 'text-muted-foreground';
  }
}

export function getSeverityBg(severity: string | number) {
  if (typeof severity === 'number') {
    if (severity >= 76) return 'bg-critical/15 text-critical border-critical/30';
    if (severity >= 51) return 'bg-high/15 text-high border-high/30';
    if (severity >= 26) return 'bg-medium/15 text-medium border-medium/30';
    return 'bg-clean/15 text-clean border-clean/30';
  }
  
  switch (severity?.toLowerCase()) {
    case 'critical':
    case 'fraud':
      return 'bg-critical/15 text-critical border-critical/30';
    case 'high':
    case 'phishing':
      return 'bg-high/15 text-high border-high/30';
    case 'medium':
    case 'impersonation':
      return 'bg-medium/15 text-medium border-medium/30';
    case 'low':
    case 'suspicious':
      return 'bg-low/15 text-low border-low/30';
    case 'clean':
    case 'legitimate':
      return 'bg-clean/15 text-clean border-clean/30';
    default:
      return 'bg-muted/50 text-muted-foreground border-border';
  }
}

export function verdictColorVar(verdict: string): string {
  const v = verdict?.toLowerCase() || '';
  if (v.includes('fraud') || v.includes('critical') || v.includes('malware') || v.includes('bec')) {
    return 'var(--critical)';
  }
  if (v.includes('phishing') || v.includes('high')) {
    return 'var(--high)';
  }
  if (v.includes('impersonation') || v.includes('medium') || v.includes('suspicious')) {
    return 'var(--medium)';
  }
  if (v.includes('low')) {
    return 'var(--low)';
  }
  return 'var(--clean)';
}

export function formatDate(dateString: string) {
  try {
    return new Date(dateString).toLocaleString();
  } catch {
    return dateString;
  }
}

