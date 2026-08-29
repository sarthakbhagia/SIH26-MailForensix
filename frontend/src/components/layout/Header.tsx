import { useNavigate } from 'react-router-dom';
import {
  Bell,
  Menu,
  Search,
  Command,
  UserCheck,
  LogOut,
  ChevronDown,
  Shield,
  LayoutDashboard,
} from 'lucide-react';
import { Breadcrumbs } from './Breadcrumbs';
import { useAlerts } from '@/hooks/useAlerts';
import { useAuth } from '@/context/AuthContext';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';

export interface HeaderProps {
  onToggleSidebar?: () => void;
  onOpenCommandPalette?: () => void;
}

export function Header({ onToggleSidebar, onOpenCommandPalette }: HeaderProps) {
  const navigate = useNavigate();
  const { stats, liveAlerts, connectionStatus } = useAlerts({ autoConnect: true });
  const { user, logout } = useAuth();

  const unackCount = stats?.unacknowledged ?? liveAlerts.filter((a) => !a.acknowledged).length;

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const getStatusIndicator = () => {
    if (connectionStatus === 'connected') {
      return {
        label: 'TELEMETRY LIVE',
        dotColor: 'bg-clean',
        textColor: 'text-clean',
        title: 'Real-time WebSocket telemetry stream active',
      };
    }
    if (connectionStatus === 'connecting' || connectionStatus === 'reconnecting') {
      return {
        label: 'CONNECTING...',
        dotColor: 'bg-high animate-pulse',
        textColor: 'text-high',
        title: 'Attempting to establish WebSocket telemetry connection',
      };
    }
    return {
      label: 'OFFLINE',
      dotColor: 'bg-critical',
      textColor: 'text-critical',
      title: 'Telemetry stream offline',
    };
  };

  const status = getStatusIndicator();

  return (
    <header className="h-14 border-b border-border bg-surface flex items-center justify-between px-3 sm:px-4 shrink-0 z-20 select-none">
      {/* Left: Mobile Toggle & Page Context Breadcrumbs */}
      <div className="flex items-center gap-3 min-w-0">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="md:hidden p-1.5 rounded border border-border bg-surface-2 text-muted-foreground hover:text-foreground hover:border-border-strong transition-colors shrink-0"
            title="Toggle Navigation Menu"
          >
            <Menu className="size-4" />
          </button>
        )}

        {/* Dynamic Breadcrumbs */}
        <Breadcrumbs />
      </div>

      {/* Right: Quick Search, Telemetry Heartbeat, Alerts & Analyst Profile */}
      <div className="flex items-center gap-2 sm:gap-3 shrink-0">
        {/* Command Palette Trigger */}
        <button
          onClick={onOpenCommandPalette}
          className="flex items-center justify-between gap-3 h-8 w-44 sm:w-60 px-2.5 rounded border border-border bg-surface-2 hover:bg-surface-3 hover:border-border-strong text-muted-foreground hover:text-foreground transition-colors font-sans text-xs"
          title="Open Command Palette (Ctrl+K / ⌘K)"
        >
          <div className="flex items-center gap-2 min-w-0">
            <Search className="size-3.5 text-muted-foreground shrink-0" />
            <span className="truncate text-muted-foreground text-[11px]">Quick Jump / Search...</span>
          </div>

          <kbd className="hidden sm:inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-surface border border-border font-mono text-[9px] text-muted-foreground">
            <Command className="size-2.5" /> K
          </kbd>
        </button>

        {/* Telemetry Status Pill */}
        <div
          className="hidden lg:flex items-center gap-1.5 px-2 py-1 rounded border border-border bg-surface-2 font-mono text-[10px]"
          title={status.title}
        >
          <span className={cn('size-1.5 rounded-full shrink-0', status.dotColor)} />
          <span className={cn('font-bold tracking-wider', status.textColor)}>{status.label}</span>
        </div>

        {/* Unacknowledged Alerts Bell */}
        <button
          onClick={() => navigate('/')}
          className="relative p-2 rounded border border-border bg-surface-2 hover:bg-surface-3 hover:border-border-strong text-muted-foreground hover:text-foreground transition-colors"
          title={`${unackCount} Unacknowledged Incident Alerts`}
        >
          <Bell className="size-3.5" />
          {unackCount > 0 && (
            <span className="absolute -top-1 -right-1 flex items-center justify-center min-w-[16px] h-4 px-1 rounded-full bg-critical text-[9px] font-bold text-critical-foreground font-mono shadow-sm animate-pulse">
              {unackCount > 99 ? '99+' : unackCount}
            </span>
          )}
        </button>

        {/* Analyst Profile Dropdown */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-border bg-surface-2 hover:bg-surface-3 hover:border-border-strong text-muted-foreground hover:text-foreground transition-colors font-mono text-[10px] focus:outline-none"
              title="Analyst Profile & Session"
            >
              <UserCheck className="size-3 text-primary" />
              <span className="font-semibold text-foreground max-w-[120px] truncate hidden sm:inline-block">
                {user?.email ? user.email.split('@')[0] : 'ANALYST'}
              </span>
              <ChevronDown className="size-3 opacity-60 ml-0.5" />
            </button>
          </DropdownMenuTrigger>

          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel className="font-normal p-2.5 pb-2">
              <div className="flex flex-col space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-foreground font-mono truncate">
                    {user?.email || 'analyst@mailforensix.local'}
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-primary/10 border border-primary/30 text-primary font-mono text-[9px] font-bold uppercase">
                    <Shield className="size-2.5" />
                    {user?.role || 'analyst'}
                  </span>
                  <span className="label-mono text-[9px] text-clean font-bold">● ACTIVE</span>
                </div>
              </div>
            </DropdownMenuLabel>

            <DropdownMenuSeparator />

            <DropdownMenuItem
              onClick={() => navigate('/')}
              className="text-xs font-sans gap-2"
            >
              <LayoutDashboard className="size-3.5 text-muted-foreground" />
              <span>SOC Dashboard</span>
            </DropdownMenuItem>

            <DropdownMenuSeparator />

            <DropdownMenuItem
              onClick={handleLogout}
              className="text-xs font-sans gap-2 text-critical focus:text-critical focus:bg-critical/10"
            >
              <LogOut className="size-3.5 text-critical" />
              <span className="font-semibold">Sign Out & Lock</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}

export default Header;
