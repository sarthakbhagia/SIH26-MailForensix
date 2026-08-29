import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Loader2,
  AlertTriangle,
  Mail,
  Lock,
  Eye,
  EyeOff,
  Radar,
  Shield,
  KeyRound,
  Terminal,
  Activity,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useAuth } from '@/context/AuthContext';

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, isLoading: authLoading, isAuthenticated } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const from =
    (location.state as any)?.from?.pathname ||
    (typeof window !== 'undefined' ? sessionStorage.getItem('auth_redirect') : null) ||
    '/';

  useEffect(() => {
    if (!authLoading && isAuthenticated) {
      if (typeof window !== 'undefined') {
        sessionStorage.removeItem('auth_redirect');
      }
      navigate(from, { replace: true });
    }
  }, [authLoading, isAuthenticated, navigate, from]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setError('Please provide both username/email and password.');
      return;
    }

    setError(null);
    setIsSubmitting(true);

    try {
      await login({ email: email.trim(), password });
      if (typeof window !== 'undefined') {
        sessionStorage.removeItem('auth_redirect');
      }
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Invalid security credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const fillDefaultCredentials = () => {
    setEmail('admin@mailforensix.local');
    setPassword('admin123');
  };

  if (authLoading) {
    return (
      <div className="flex min-h-screen w-full items-center justify-center bg-background select-none">
        <div className="panel p-6 sm:p-8 max-w-sm w-full mx-4 flex flex-col items-center gap-4 text-center border border-border shadow-2xl">
          <div className="relative flex items-center justify-center size-12 rounded bg-primary/10 border border-primary/30">
            <Radar className="size-6 text-primary animate-pulse" />
            <Loader2 className="size-10 text-primary/40 animate-spin absolute" />
          </div>
          <div className="space-y-1">
            <h3 className="font-mono text-xs font-bold tracking-tight text-foreground uppercase">
              Initializing SOC Terminal
            </h3>
            <p className="label-mono text-[10px] text-muted-foreground">
              Establishing cryptographic channel...
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen w-full flex flex-col justify-between bg-background grid-bg text-foreground selection:bg-primary/30 select-none p-4 sm:p-6 lg:p-8">
      {/* Top Bar: Security Node Header */}
      <header className="flex items-center justify-between w-full max-w-5xl mx-auto py-2">
        <div className="flex items-center gap-2">
          <div className="flex size-7 items-center justify-center rounded bg-primary/15 text-primary border border-primary/30">
            <Radar className="size-4" />
          </div>
          <div>
            <span className="font-mono text-xs font-bold tracking-tight text-foreground block">
              MailForensix SOC
            </span>
            <span className="label-mono text-[9px] text-muted-foreground block -mt-0.5">
              DFIR WORKSTATION v2.4.0
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border border-border bg-surface-2 font-mono text-[10px] text-muted-foreground">
            <span className="size-1.5 rounded-full bg-clean animate-pulse" />
            NODE ONLINE
          </span>
        </div>
      </header>

      {/* Main Container: Workstation Login Card */}
      <main className="flex items-center justify-center my-auto py-6">
        <div className="panel max-w-md w-full p-6 sm:p-8 space-y-6 border border-border shadow-2xl bg-surface relative overflow-hidden">
          {/* Subtle Top Accent Glow Line */}
          <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-primary to-transparent" />

          {/* Station Badge & Heading */}
          <div className="text-center space-y-2">
            <div className="mx-auto flex size-12 items-center justify-center rounded bg-primary/15 text-primary border border-primary/30">
              <Shield className="size-6 text-primary" />
            </div>
            <div>
              <h1 className="text-lg sm:text-xl font-mono font-bold tracking-tight text-foreground">
                Workstation Authentication
              </h1>
              <p className="label-mono text-[10px] text-muted-foreground mt-0.5">
                RESTRICTED THREAT INTELLIGENCE ACCESS
              </p>
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="flex items-start gap-2 text-xs text-critical bg-critical/10 border border-critical/30 rounded p-3 font-mono leading-relaxed animate-in fade-in-50">
                <AlertTriangle className="size-4 shrink-0 mt-0.5" />
                <span className="flex-1 break-words">{error}</span>
              </div>
            )}

            <div className="space-y-1.5">
              <label htmlFor="email" className="label-mono text-[10px] flex items-center justify-between">
                <span>ANALYST IDENTITY (EMAIL / USERNAME)</span>
                <Terminal className="size-3 text-muted-foreground" />
              </label>
              <div className="relative">
                <Mail className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
                <Input
                  id="email"
                  type="text"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@mailforensix.local"
                  className="pl-8 h-9 text-xs font-mono bg-surface-2 border-border focus-visible:border-primary"
                  required
                  autoFocus
                  autoComplete="username"
                  disabled={isSubmitting}
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="password" className="label-mono text-[10px] flex items-center justify-between">
                <span>SECURITY PASSPHRASE</span>
                <KeyRound className="size-3 text-muted-foreground" />
              </label>
              <div className="relative">
                <Lock className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="pl-8 pr-9 h-9 text-xs font-mono bg-surface-2 border-border focus-visible:border-primary"
                  required
                  autoComplete="current-password"
                  disabled={isSubmitting}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors p-1"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                </button>
              </div>
            </div>

            <Button
              type="submit"
              className="w-full h-9 text-xs font-mono font-bold gap-2 uppercase tracking-wider"
              disabled={isSubmitting}
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="size-3.5 animate-spin" />
                  AUTHENTICATING SESSION...
                </>
              ) : (
                <>
                  <Shield className="size-3.5" />
                  ACCESS SOC CONSOLE
                </>
              )}
            </Button>
          </form>

          {/* Quick Demo Credentials Assistant */}
          <div className="pt-3 border-t border-border/50 space-y-2">
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-muted-foreground">Default Access:</span>
              <button
                type="button"
                onClick={fillDefaultCredentials}
                className="text-primary hover:underline font-semibold focus:outline-none"
                title="Fill demo credentials"
              >
                Auto-fill Demo Credentials
              </button>
            </div>
            <div className="p-2.5 rounded bg-surface-2/60 border border-border/70 font-mono text-[10px] text-muted-foreground space-y-0.5">
              <div className="flex justify-between">
                <span>User:</span>
                <span className="text-foreground font-semibold">admin@mailforensix.local</span>
              </div>
              <div className="flex justify-between">
                <span>Pass:</span>
                <span className="text-foreground font-semibold">admin123</span>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer Bar: System Telemetry */}
      <footer className="w-full max-w-5xl mx-auto py-2 flex flex-col sm:flex-row items-center justify-between text-[10px] font-mono text-muted-foreground/70 gap-2">
        <div className="flex items-center gap-2">
          <Activity className="size-3 text-primary" />
          <span>CRYPTOGRAPHIC EVIDENCE AUDITING PLATFORM</span>
        </div>
        <div className="flex items-center gap-3">
          <span>TLS 1.3 / AES-256</span>
          <span>·</span>
          <span>ROLE-BASED ACCESS CONTROL ENABLED</span>
        </div>
      </footer>
    </div>
  );
}
