import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Inbox,
  Briefcase,
  Globe2,
  Share2,
  FileCheck2,
  Radar,
  PanelLeftClose,
  PanelLeftOpen,
  X,
} from 'lucide-react';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

interface NavItem {
  name: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
  shortcut?: string;
  description?: string;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'PRIMARY WORKFLOWS',
    items: [
      {
        name: 'Dashboard',
        path: '/',
        icon: LayoutDashboard,
        shortcut: '1',
        description: 'SOC overview & live alerts',
      },
      {
        name: 'Evidence Ingest',
        path: '/ingest',
        icon: Inbox,
        shortcut: '2',
        description: 'MIME raw email upload & ledger',
      },
      {
        name: 'Cases',
        path: '/cases',
        icon: Briefcase,
        shortcut: '3',
        description: 'Case management & audit notes',
      },
    ],
  },
  {
    label: 'INVESTIGATION TOOLS',
    items: [
      {
        name: 'MTA Trace Map',
        path: '/map',
        icon: Globe2,
        shortcut: '4',
        description: 'Multi-hop relay triangulation',
      },
      {
        name: 'Attribution Graph',
        path: '/graph',
        icon: Share2,
        shortcut: '5',
        description: 'Force-directed IOC attribution',
      },
    ],
  },
  {
    label: 'OUTPUT & REPORTING',
    items: [
      {
        name: 'Reports',
        path: '/reports',
        icon: FileCheck2,
        shortcut: '6',
        description: 'Cryptographic PDF/JSON dossiers',
      },
    ],
  },
];

export interface SidebarProps {
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
  onClose?: () => void;
  isMobile?: boolean;
}

export function Sidebar({
  isCollapsed = false,
  onToggleCollapse,
  onClose,
  isMobile = false,
}: SidebarProps) {
  const location = useLocation();

  const isRouteActive = (path: string) => {
    if (path === '/') {
      return location.pathname === '/';
    }
    return location.pathname === path || location.pathname.startsWith(path);
  };

  return (
    <TooltipProvider delayDuration={150}>
      <aside
        className={cn(
          'h-full border-r border-border bg-surface flex flex-col transition-all duration-200 select-none z-30',
          isMobile ? 'w-64' : isCollapsed ? 'w-14' : 'w-56'
        )}
      >
        {/* Brand & Workstation Banner */}
        <div
          className={cn(
            'h-14 border-b border-border flex items-center shrink-0 px-3',
            isCollapsed && !isMobile ? 'justify-center' : 'justify-between'
          )}
        >
          <Link
            to="/"
            onClick={onClose}
            className="flex items-center gap-2.5 group overflow-hidden"
            title="MailForensix Threat Intelligence Console"
          >
            <div className="flex size-7 items-center justify-center rounded bg-primary/15 text-primary border border-primary/30 shrink-0 group-hover:bg-primary/25 transition-colors">
              <Radar className="size-4" />
            </div>

            {(!isCollapsed || isMobile) && (
              <div className="min-w-0">
                <span className="font-mono text-xs font-bold tracking-tight text-foreground block truncate">
                  MailForensix
                </span>
              </div>
            )}
          </Link>

          {isMobile && onClose && (
            <button
              onClick={onClose}
              className="p-1 rounded text-muted-foreground hover:text-foreground hover:bg-surface-2 transition-colors"
              title="Close navigation drawer"
            >
              <X className="size-4" />
            </button>
          )}
        </div>

        {/* Navigation Group Sections */}
        <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-4">
          {NAV_GROUPS.map((group, groupIdx) => (
            <div key={groupIdx} className="space-y-1">
              {(!isCollapsed || isMobile) && (
                <div className="px-2 pb-1">
                  <span className="label-mono text-[10px] text-muted-foreground/70 font-bold tracking-wider">
                    {group.label}
                  </span>
                </div>
              )}

              <ul className="space-y-0.5">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const active = isRouteActive(item.path);

                  const linkContent = (
                    <Link
                      to={item.path}
                      onClick={onClose}
                      className={cn(
                        'flex items-center gap-2.5 rounded px-2.5 py-2 text-xs font-sans font-medium transition-all relative group',
                        isCollapsed && !isMobile ? 'justify-center px-0' : '',
                        active
                          ? 'bg-surface-2 text-foreground font-semibold border-l-2 border-l-primary border-t border-r border-b border-border/40'
                          : 'text-muted-foreground hover:text-foreground hover:bg-surface-2/60 border border-transparent'
                      )}
                    >
                      <Icon
                        className={cn(
                          'size-4 shrink-0 transition-colors',
                          active ? 'text-primary' : 'text-muted-foreground group-hover:text-foreground'
                        )}
                      />

                      {(!isCollapsed || isMobile) && (
                        <span className="truncate flex-1">{item.name}</span>
                      )}
                    </Link>
                  );

                  if (isCollapsed && !isMobile) {
                    return (
                      <li key={item.path}>
                        <Tooltip>
                          <TooltipTrigger asChild>{linkContent}</TooltipTrigger>
                          <TooltipContent side="right" className="flex flex-col gap-0.5 p-2 min-w-[140px]">
                            <span className="font-semibold text-xs text-foreground">{item.name}</span>
                            {item.description && (
                              <span className="text-[10px] text-muted-foreground">{item.description}</span>
                            )}
                          </TooltipContent>
                        </Tooltip>
                      </li>
                    );
                  }

                  return <li key={item.path}>{linkContent}</li>;
                })}
              </ul>
            </div>
          ))}
        </nav>

        {/* Rail Footer & Collapse Toggle */}
        <div className="p-2 border-t border-border bg-surface-2/40 flex items-center justify-between text-[11px] font-mono text-muted-foreground shrink-0">
          {(!isCollapsed || isMobile) && (
            <div className="px-1 truncate">
              <span className="label-mono text-[9px] text-muted-foreground/80">v2.4.0 · SOC NODE</span>
            </div>
          )}

          {!isMobile && onToggleCollapse && (
            <button
              onClick={onToggleCollapse}
              className={cn(
                'p-1.5 rounded hover:bg-surface-2 hover:text-foreground text-muted-foreground transition-colors border border-transparent hover:border-border',
                isCollapsed ? 'mx-auto' : ''
              )}
              title={isCollapsed ? 'Expand Navigation Rail ([)' : 'Collapse Navigation Rail ([)'}
            >
              {isCollapsed ? (
                <PanelLeftOpen className="size-3.5 text-primary" />
              ) : (
                <PanelLeftClose className="size-3.5" />
              )}
            </button>
          )}
        </div>
      </aside>
    </TooltipProvider>
  );
}

export default Sidebar;
