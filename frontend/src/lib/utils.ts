import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import {
  getSeverityTokens,
  getSeverityColorVar,
  getRiskTier,
  getVerdictForScore,
  normalizeSeverity,
  defangUrl,
  defangIp,
  formatBytes,
  type SeverityLevel,
  type RiskTier,
  type AuthStatus,
  type SeverityStyleTokens,
} from "./severity";
import {
  safeParseDate,
  safeToISOString,
  safeFormatDate,
  safeFormatDateOnly,
  safeFormatDistanceToNow,
} from "./dateUtils";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Backward-compatible helpers delegating to centralized single source of truth in severity.ts
export {
  getSeverityTokens,
  getSeverityColorVar,
  getRiskTier,
  getVerdictForScore,
  normalizeSeverity,
  defangUrl,
  defangIp,
  formatBytes,
  type SeverityLevel,
  type RiskTier,
  type AuthStatus,
  type SeverityStyleTokens,
};

export {
  safeParseDate,
  safeToISOString,
  safeFormatDate,
  safeFormatDateOnly,
  safeFormatDistanceToNow,
};

export function getSeverityColor(severity: string | number | null | undefined): string {
  return getSeverityTokens(severity).textColor;
}

export function getSeverityBg(severity: string | number | null | undefined): string {
  return getSeverityTokens(severity).badgeClass;
}

export function verdictColorVar(verdict: string): string {
  return getSeverityColorVar(verdict);
}

export function formatDate(dateString: string | null | undefined): string {
  return safeFormatDate(dateString);
}
