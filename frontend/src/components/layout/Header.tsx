import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, Menu, Search, Radar } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { useAlerts } from '@/hooks/useAlerts';

interface HeaderProps {
  onToggleSidebar?: () => void;
}

export default function Header({ onToggleSidebar }: HeaderProps) {
  const navigate = useNavigate();
  const { stats, liveAlerts, connectionStatus } = useAlerts({ autoConnect: true });
  const [searchTerm, setSearchTerm] = useState('');

  const unackCount = stats?.unacknowledged ?? liveAlerts.filter((a) => !a.acknowledged).length;

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchTerm.trim()) {
      navigate(`/cases?search=${encodeURIComponent(searchTerm.trim())}`);
    }
  };

  return (
    <header className="h-16 border-b border-border bg-surface/50 backdrop-blur-md flex items-center justify-between px-4 md:px-6 shrink-0 z-20">
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="md:hidden p-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            title="Toggle Navigation Menu"
          >
            <Menu className="h-5 w-5" />
          </button>
        )}
        <div className="flex items-center gap-2 cursor-pointer" onClick={() => navigate('/')}>
          <Radar className="h-5 w-5 text-primary animate-pulse" />
          <span className="font-semibold text-sm tracking-tight text-foreground hidden sm:inline-block">
            MailForensix SOC
          </span>
          <span className="label-mono hidden lg:inline-block text-[10px] text-muted-foreground px-2 py-0.5 rounded border border-border bg-background/50">
            {connectionStatus === 'connected' ? '● LIVE TELEMETRY' : '○ CONNECTING'}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-3 md:gap-4">
        <form onSubmit={handleSearchSubmit} className="relative w-56 lg:w-72 hidden sm:block">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder="Search cases, senders, IOCs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-8 h-8 text-xs bg-background/60 border-border focus-visible:ring-primary/40 font-mono"
          />
        </form>

        <button
          onClick={() => navigate('/')}
          className="relative p-2 rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
          title={`${unackCount} Unacknowledged Alerts`}
        >
          <Bell className="h-4 w-4" />
          {unackCount > 0 && (
            <span className="absolute top-1 right-1 flex items-center justify-center min-w-[14px] h-3.5 px-1 rounded-full bg-critical text-[9px] font-bold text-critical-foreground font-mono shadow-sm animate-pulse">
              {unackCount > 99 ? '99+' : unackCount}
            </span>
          )}
        </button>
      </div>
    </header>
  );
}
