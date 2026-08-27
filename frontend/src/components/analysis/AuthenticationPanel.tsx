import { AuthPill, AuthStatus } from '@/components/forensics/AuthPill';

export interface SPFResult {
  status: AuthStatus;
  domain: string;
  ip?: string;
  record?: string;
  details?: string;
}

export interface DKIMResult {
  status: AuthStatus;
  domain: string;
  selector?: string;
  details?: string;
}

export interface DMARCResult {
  status: AuthStatus;
  policy: 'none' | 'quarantine' | 'reject' | string;
  domain: string;
  alignment_spf?: boolean;
  alignment_dkim?: boolean;
  record?: string;
  details?: string;
}

export interface AuthenticationPanelProps {
  spf: SPFResult;
  dkim: DKIMResult;
  dmarc: DMARCResult;
}

export function AuthenticationPanel({ spf, dkim, dmarc }: AuthenticationPanelProps) {
  const isAligned = Boolean(dmarc?.alignment_spf || dmarc?.alignment_dkim);
  const alignmentStatus = isAligned ? 'PASS' : (dmarc?.alignment_spf === false && dmarc?.alignment_dkim === false ? 'FAIL' : 'UNAVAILABLE');

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold tracking-tight text-foreground">Authentication Protocol Ledger</h3>
          <p className="label-mono text-[10px] mt-0.5">SPF · DKIM · DMARC · IDENTITY ALIGNMENT</p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {/* 1. SPF Pill */}
        <AuthPill
          protocol="SPF"
          status={spf?.status || 'none'}
          domain={spf?.domain || undefined}
          details={spf?.details || (spf?.ip ? `Validated sender IP ${spf.ip}` : undefined)}
          record={spf?.record || undefined}
        />

        {/* 2. DKIM Pill */}
        <AuthPill
          protocol="DKIM"
          status={dkim?.status || 'none'}
          domain={dkim?.domain || undefined}
          details={dkim?.details || (dkim?.selector ? `Selector: ${dkim.selector}` : undefined)}
        />

        {/* 3. DMARC Pill */}
        <AuthPill
          protocol="DMARC"
          status={dmarc?.status || 'none'}
          domain={dmarc?.domain || undefined}
          details={dmarc?.details || (dmarc?.policy ? `Policy enforcement: ${dmarc.policy.toUpperCase()}` : undefined)}
          record={dmarc?.record || undefined}
        />

        {/* 4. Alignment Pill */}
        <AuthPill
          protocol="ALIGNMENT"
          status={alignmentStatus}
          domain={dmarc?.domain || spf?.domain || undefined}
          details={`SPF Align: ${dmarc?.alignment_spf ? 'PASS' : 'FAIL'} · DKIM Align: ${dmarc?.alignment_dkim ? 'PASS' : 'FAIL'}`}
        />
      </div>
    </div>
  );
}

export default AuthenticationPanel;