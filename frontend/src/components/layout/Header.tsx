import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, Menu, Search, Shield } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { useAlerts } from '@/hooks/useAlerts';

interface HeaderProps {
  onToggleSidebar?: () => void;
}

export default function Header({ onToggleSidebar }: HeaderProps) {
  const navigate = useNavigate();
  const { stats, liveAlerts } = useAlerts({ autoConnect: true });
  const [searchTerm, setSearchTerm] = useState('');

  const unackCount = stats?.unacknowledged ?? liveAlerts.filter((a) => !a.acknowledged).length;

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchTerm.trim()) {
      navigate(`/cases?search=${encodeURIComponent(searchTerm.trim())}`);
    }
  };

  return (
    <header className="h-16 border-b border-border/60 bg-card/80 backdrop-blur-md flex items-center justify-between px-4 md:px-6 shrink-0 z-20">
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="md:hidden p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors"
            title="Toggle Navigation Menu"
          >
            <Menu className="h-5 w-5" />
          </button>
        )}
        <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => navigate('/')}>
          <Shield className="h-6 w-6 text-primary" />
          <span className="font-bold text-lg tracking-tight text-foreground hidden sm:block">ThreatLens SOC</span>
        </div>
      </div>

      <div className="flex items-center gap-3 md:gap-4">
        <form onSubmit={handleSearchSubmit} className="relative w-56 lg:w-72 hidden sm:block">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search cases, senders, IOCs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-9 h-9 text-xs bg-background/50 border-border/60 focus-visible:ring-primary/40"
          />
        </form>

        <button
          onClick={() => navigate('/')}
          className="relative p-2 rounded-full hover:bg-muted/60 text-muted-foreground hover:text-foreground transition-colors"
          title={`${unackCount} Unacknowledged Alerts`}
        >
          <Bell className="h-5 w-5" />
          {unackCount > 0 && (
            <span className="absolute top-1 right-1 flex items-center justify-center min-w-[16px] h-4 px-1 rounded-full bg-red-500 text-[10px] font-bold text-white font-mono shadow-sm animate-pulse">
              {unackCount > 99 ? '99+' : unackCount}
            </span>
          )}
        </button>
      </div>
    </header>
  );
}
