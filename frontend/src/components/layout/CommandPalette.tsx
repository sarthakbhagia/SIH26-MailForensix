import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Inbox,
  Briefcase,
  Globe2,
  Share2,
  FileCheck2,
  Search,
  ArrowRight,
  PanelLeft,
  FolderSearch,
  LogOut,
} from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useAuth } from '@/context/AuthContext';
import { cn } from '@/lib/utils';

export interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onToggleSidebar?: () => void;
}

interface NavCommand {
  id: string;
  category: 'NAVIGATION' | 'ACTIONS';
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  action: () => void;
  shortcut?: string;
}

export function CommandPalette({ isOpen, onClose, onToggleSidebar }: CommandPaletteProps) {
  const navigate = useNavigate();
  const { logout } = useAuth();
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);

  const commands: NavCommand[] = [
    {
      id: 'nav-dashboard',
      category: 'NAVIGATION',
      title: 'SOC Dashboard',
      description: 'Threat distribution telemetry & live incident stream',
      icon: LayoutDashboard,
      shortcut: 'G D',
      action: () => {
        navigate('/');
        onClose();
      },
    },
    {
      id: 'nav-ingest',
      category: 'NAVIGATION',
      title: 'Ingest Raw Email Evidence',
      description: 'Upload .eml / .msg files and view evidence ledger',
      icon: Inbox,
      shortcut: 'G E',
      action: () => {
        navigate('/ingest');
        onClose();
      },
    },
    {
      id: 'nav-cases',
      category: 'NAVIGATION',
      title: 'Case Management',
      description: 'Investigator ledger, notes, and audit timelines',
      icon: Briefcase,
      shortcut: 'G C',
      action: () => {
        navigate('/cases');
        onClose();
      },
    },
    {
      id: 'nav-map',
      category: 'NAVIGATION',
      title: 'MTA Relay Trace Map',
      description: 'Multi-hop transmission triangulation and IP geolocation',
      icon: Globe2,
      shortcut: 'G M',
      action: () => {
        navigate('/map');
        onClose();
      },
    },
    {
      id: 'nav-graph',
      category: 'NAVIGATION',
      title: 'Campaign Attribution Graph',
      description: 'Force-directed IOC clustering and campaign actor links',
      icon: Share2,
      shortcut: 'G A',
      action: () => {
        navigate('/graph');
        onClose();
      },
    },
    {
      id: 'nav-reports',
      category: 'NAVIGATION',
      title: 'Forensic Dossier Reports',
      description: 'Generate, sign, and export PDF/JSON evidence dossiers',
      icon: FileCheck2,
      shortcut: 'G R',
      action: () => {
        navigate('/reports');
        onClose();
      },
    },
    {
      id: 'act-search-cases',
      category: 'ACTIONS',
      title: 'Search Investigation Cases',
      description: query ? `Search cases for "${query}"` : 'Jump to case search',
      icon: FolderSearch,
      shortcut: '↵',
      action: () => {
        navigate(query ? `/cases?search=${encodeURIComponent(query.trim())}` : '/cases');
        onClose();
      },
    },
    {
      id: 'act-logout',
      category: 'ACTIONS',
      title: 'Sign Out / Lock Workstation',
      description: 'Terminate active SOC analyst session and clear credentials',
      icon: LogOut,
      shortcut: '⇧ Q',
      action: () => {
        logout();
        navigate('/login');
        onClose();
      },
    },
  ];

  if (onToggleSidebar) {
    commands.push({
      id: 'act-toggle-sidebar',
      category: 'ACTIONS',
      title: 'Toggle Navigation Rail',
      description: 'Expand or collapse the sidebar tool rail',
      icon: PanelLeft,
      shortcut: '[',
      action: () => {
        onToggleSidebar();
        onClose();
      },
    });
  }

  const filteredCommands = commands.filter((cmd) => {
    if (!query) return true;
    const q = query.toLowerCase();
    return (
      cmd.title.toLowerCase().includes(q) ||
      cmd.description.toLowerCase().includes(q) ||
      cmd.category.toLowerCase().includes(q)
    );
  });

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  // Keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % Math.max(1, filteredCommands.length));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filteredCommands.length) % Math.max(1, filteredCommands.length));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredCommands[selectedIndex]) {
        filteredCommands[selectedIndex].action();
      }
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-xl p-0 gap-0 overflow-hidden border border-border bg-surface shadow-2xl rounded-md">
        <DialogHeader className="sr-only">
          <DialogTitle>Command Palette</DialogTitle>
        </DialogHeader>

        {/* Input Bar */}
        <div className="flex items-center gap-2.5 px-3.5 py-3 border-b border-border bg-surface-2/60">
          <Search className="size-4 text-muted-foreground shrink-0" />
          <input
            autoFocus
            type="text"
            placeholder="Type a command or search cases..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="w-full bg-transparent text-sm text-foreground placeholder:text-muted-foreground focus:outline-none font-sans"
          />
          <kbd className="px-1.5 py-0.5 rounded bg-surface border border-border text-[10px] font-mono text-muted-foreground shadow-sm">
            ESC
          </kbd>
        </div>

        {/* Results List */}
        <div className="max-h-[340px] overflow-y-auto p-2 space-y-1">
          {filteredCommands.length === 0 ? (
            <div className="py-8 text-center text-xs text-muted-foreground font-mono">
              No matching commands or routes for "{query}"
            </div>
          ) : (
            filteredCommands.map((cmd, idx) => {
              const isSelected = idx === selectedIndex;
              const Icon = cmd.icon;

              return (
                <div
                  key={cmd.id}
                  onClick={() => cmd.action()}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={cn(
                    'flex items-center justify-between gap-3 px-3 py-2 rounded text-xs transition-colors cursor-pointer select-none',
                    isSelected
                      ? 'bg-primary/15 text-foreground border border-primary/30'
                      : 'hover:bg-surface-2 text-foreground/80 border border-transparent'
                  )}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div
                      className={cn(
                        'p-1.5 rounded border shrink-0',
                        isSelected
                          ? 'bg-primary/20 text-primary border-primary/40'
                          : 'bg-surface-2 text-muted-foreground border-border'
                      )}
                    >
                      <Icon className="size-3.5" />
                    </div>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-foreground truncate">{cmd.title}</span>
                        <span className="label-mono text-[9px] text-muted-foreground/60">{cmd.category}</span>
                      </div>
                      <p className="text-[11px] text-muted-foreground truncate">{cmd.description}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    {cmd.shortcut && (
                      <kbd className="px-1.5 py-0.5 rounded bg-surface-2 border border-border font-mono text-[10px] text-muted-foreground">
                        {cmd.shortcut}
                      </kbd>
                    )}
                    {isSelected && <ArrowRight className="size-3 text-primary" />}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Palette Footer */}
        <div className="px-3.5 py-2 border-t border-border/50 bg-surface-2/40 flex items-center justify-between text-[11px] font-mono text-muted-foreground">
          <div className="flex items-center gap-3">
            <span>↑↓ Navigate</span>
            <span>↵ Select</span>
            <span>ESC Close</span>
          </div>
          <span>MailForensix SOC Console</span>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default CommandPalette;
