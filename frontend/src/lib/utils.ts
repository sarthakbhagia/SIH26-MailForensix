import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getSeverityColor(severity: string | number) {
  if (typeof severity === 'number') {
    if (severity >= 76) return 'text-severity-critical';
    if (severity >= 51) return 'text-severity-high';
    if (severity >= 26) return 'text-severity-medium';
    return 'text-severity-low';
  }
  
  switch (severity?.toLowerCase()) {
    case 'critical': return 'text-severity-critical';
    case 'high': return 'text-severity-high';
    case 'medium': return 'text-severity-medium';
    case 'low': return 'text-severity-low';
    default: return 'text-muted-foreground';
  }
}

export function getSeverityBg(severity: string | number) {
  if (typeof severity === 'number') {
    if (severity >= 76) return 'bg-severity-critical';
    if (severity >= 51) return 'bg-severity-high';
    if (severity >= 26) return 'bg-severity-medium';
    return 'bg-severity-low';
  }
  
  switch (severity?.toLowerCase()) {
    case 'critical': return 'bg-severity-critical';
    case 'high': return 'bg-severity-high';
    case 'medium': return 'bg-severity-medium';
    case 'low': return 'bg-severity-low';
    default: return 'bg-muted';
  }
}

export function formatDate(dateString: string) {
  return new Date(dateString).toLocaleString();
}
