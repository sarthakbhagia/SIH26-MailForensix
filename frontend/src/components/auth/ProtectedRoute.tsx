import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Loader2, Radar, ShieldCheck } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';

interface ProtectedRouteProps {
  children: React.ReactNode;
  allowedRoles?: string[];
}

export default function ProtectedRoute({ children, allowedRoles }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, user } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-background select-none">
        <div className="panel p-6 sm:p-8 max-w-sm w-full mx-4 flex flex-col items-center gap-4 text-center border border-border shadow-2xl">
          <div className="relative flex items-center justify-center size-12 rounded bg-primary/10 border border-primary/30">
            <Radar className="size-6 text-primary animate-pulse" />
            <Loader2 className="size-10 text-primary/40 animate-spin absolute" />
          </div>

          <div className="space-y-1">
            <h3 className="font-mono text-xs font-bold tracking-tight text-foreground uppercase">
              Verifying Security Credentials
            </h3>
            <p className="label-mono text-[10px] text-muted-foreground">
              Authenticating session with DFIR node...
            </p>
          </div>

          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-surface-2 border border-border text-[10px] font-mono text-muted-foreground">
            <ShieldCheck className="size-3 text-primary" />
            <span>SESSION VALIDATION IN PROGRESS</span>
          </div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (allowedRoles && user && !allowedRoles.includes(user.role)) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}
