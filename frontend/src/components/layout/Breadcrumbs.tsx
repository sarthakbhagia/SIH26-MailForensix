import React from 'react';
import { Link, useLocation, useSearchParams } from 'react-router-dom';
import { ChevronRight, Terminal } from 'lucide-react';
import { cn } from '@/lib/utils';

export function Breadcrumbs({ className }: { className?: string }) {
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const pathname = location.pathname;
  const emailIdParam = searchParams.get('emailId');

  const segments = pathname.split('/').filter(Boolean);

  const getBreadcrumbData = () => {
    if (segments.length === 0) {
      return [{ label: 'SOC DASHBOARD', path: '/', isTechnical: false }];
    }

    const first = segments[0].toLowerCase();

    if (first === 'ingest') {
      return [{ label: 'EVIDENCE INGESTION', path: '/ingest', isTechnical: false }];
    }

    if (first === 'emails') {
      const emailId = segments[1] || '';
      return [
        { label: 'EVIDENCE', path: '/ingest', isTechnical: false },
        { label: `ENVELOPE #${emailId.substring(0, 8)}`, path: pathname, isTechnical: true },
      ];
    }

    if (first === 'cases') {
      const caseId = segments[1] || '';
      if (caseId) {
        return [
          { label: 'CASES', path: '/cases', isTechnical: false },
          { label: `CASE #${caseId.substring(0, 8)}`, path: pathname, isTechnical: true },
        ];
      }
      return [{ label: 'CASE MANAGEMENT', path: '/cases', isTechnical: false }];
    }

    if (first === 'map') {
      const base = [{ label: 'MTA RELAY TRACE MAP', path: '/map', isTechnical: false }];
      if (emailIdParam) {
        base.push({ label: `ENVELOPE #${emailIdParam.substring(0, 8)}`, path: `/map?emailId=${emailIdParam}`, isTechnical: true });
      }
      return base;
    }

    if (first === 'graph') {
      const base = [{ label: 'ATTRIBUTION GRAPH', path: '/graph', isTechnical: false }];
      if (emailIdParam) {
        base.push({ label: `ENVELOPE #${emailIdParam.substring(0, 8)}`, path: `/graph?emailId=${emailIdParam}`, isTechnical: true });
      }
      return base;
    }

    if (first === 'reports') {
      const base = [{ label: 'FORENSIC DOSSIER REPORTS', path: '/reports', isTechnical: false }];
      if (emailIdParam) {
        base.push({ label: `ENVELOPE #${emailIdParam.substring(0, 8)}`, path: `/reports?emailId=${emailIdParam}`, isTechnical: true });
      }
      return base;
    }

    return segments.map((seg, idx) => ({
      label: seg.toUpperCase(),
      path: `/${segments.slice(0, idx + 1).join('/')}`,
      isTechnical: false,
    }));
  };

  const breadcrumbs = getBreadcrumbData();

  return (
    <nav aria-label="Breadcrumb" className={cn('flex items-center gap-1.5 text-xs select-none', className)}>
      <Link
        to="/"
        className="flex items-center gap-1 text-muted-foreground hover:text-foreground font-mono text-[11px] font-semibold tracking-wider transition-colors"
      >
        <Terminal className="size-3 text-primary" />
        <span className="hidden sm:inline">MAILFORENSIX</span>
      </Link>

      {breadcrumbs.map((crumb, idx) => {
        const isLast = idx === breadcrumbs.length - 1;
        return (
          <React.Fragment key={crumb.path + idx}>
            <ChevronRight className="size-3 text-muted-foreground/50 shrink-0" />
            {isLast ? (
              <span
                className={cn(
                  'font-semibold text-foreground truncate max-w-[200px] sm:max-w-[280px]',
                  crumb.isTechnical ? 'font-mono text-[11px] text-primary' : 'label-mono text-[11px]'
                )}
              >
                {crumb.label}
              </span>
            ) : (
              <Link
                to={crumb.path}
                className={cn(
                  'text-muted-foreground hover:text-foreground transition-colors truncate max-w-[140px]',
                  crumb.isTechnical ? 'font-mono text-[11px]' : 'label-mono text-[11px]'
                )}
              >
                {crumb.label}
              </Link>
            )}
          </React.Fragment>
        );
      })}
    </nav>
  );
}

export default Breadcrumbs;
