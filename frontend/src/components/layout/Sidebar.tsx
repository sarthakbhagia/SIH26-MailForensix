import { Link, useLocation } from 'react-router-dom';
import { Home, Upload, Map, Share2, Folder, FileText, Radar } from 'lucide-react';
import { cn } from '@/lib/utils';

const navItems = [
  { name: 'Dashboard', path: '/', icon: Home },
  { name: 'Email Ingest', path: '/ingest', icon: Upload },
  { name: 'Trace Map', path: '/map', icon: Map },
  { name: 'Attribution Graph', path: '/graph', icon: Share2 },
  { name: 'Cases', path: '/cases', icon: Folder },
  { name: 'Reports', path: '/reports', icon: FileText },
];

interface SidebarProps {
  onClose?: () => void;
}

export default function Sidebar({ onClose }: SidebarProps) {
  const location = useLocation();

  return (
    <div className="w-64 border-r border-border bg-surface/50 backdrop-blur-md flex flex-col h-full shadow-lg md:shadow-none">
      <div className="h-16 flex items-center justify-between px-5 border-b border-border">
        <div className="flex items-center gap-2.5">
          <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary border border-primary/20">
            <Radar className="size-4 animate-pulse" />
          </div>
          <div>
            <span className="text-base font-bold tracking-tight text-foreground font-mono">MailForensix</span>
            <p className="label-mono text-[9px] -mt-0.5">Forensic Console</p>
          </div>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto py-4">
        <ul className="space-y-1 px-3">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive =
              location.pathname === item.path ||
              (item.path !== '/' && location.pathname.startsWith(item.path));
            return (
              <li key={item.path}>
                <Link
                  to={item.path}
                  onClick={onClose}
                  className={cn(
                    'flex items-center gap-3 rounded px-3 py-2 text-xs tracking-wide transition-all font-mono',
                    isActive
                      ? 'bg-primary/10 text-primary border border-primary/30 font-bold shadow-sm'
                      : 'hover:bg-surface-2/60 text-muted-foreground hover:text-foreground border border-transparent'
                  )}
                >
                  <Icon className={cn('size-4 shrink-0', isActive ? 'text-primary' : 'text-muted-foreground')} />
                  <span>{item.name}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
      <div className="p-4 border-t border-border text-[10px] text-muted-foreground font-mono text-center">
        <span className="label-mono text-[9px]">v2.4.0 · FORENSIC INTEL</span>
      </div>
    </div>
  );
}
