import { Link, useLocation } from 'react-router-dom';
import { Home, Upload, Map, Share2, Folder, FileText } from 'lucide-react';
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
    <div className="w-64 border-r border-border/60 bg-card flex flex-col h-full shadow-lg md:shadow-none">
      <div className="h-16 flex items-center justify-between px-6 border-b border-border/60">
        <div className="flex items-center gap-2">
          <span className="text-xl font-black tracking-tight text-primary font-mono">ThreatLens</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/10 text-primary font-bold uppercase">SOC</span>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto py-4">
        <ul className="space-y-1.5 px-3">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path || (item.path !== '/' && location.pathname.startsWith(item.path));
            return (
              <li key={item.path}>
                <Link
                  to={item.path}
                  onClick={onClose}
                  className={cn(
                    'flex items-center gap-3 rounded-lg px-3.5 py-2.5 text-xs font-semibold tracking-wide transition-all',
                    isActive
                      ? 'bg-primary text-primary-foreground shadow-sm'
                      : 'hover:bg-muted/70 text-muted-foreground hover:text-foreground'
                  )}
                >
                  <Icon className={cn('h-4 w-4 shrink-0', isActive ? 'text-primary-foreground' : 'text-muted-foreground')} />
                  <span>{item.name}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
      <div className="p-4 border-t border-border/40 text-[11px] text-muted-foreground font-mono text-center">
        v2.4.0-SOC-Enterprise
      </div>
    </div>
  );
}
