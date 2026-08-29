import { useAuth } from '@/context/AuthContext';

export function useRole() {
  const { user } = useAuth();
  const role = user?.role;

  const isAdmin = role === 'admin';
  const isInvestigator = role === 'investigator';
  const isAnalyst = role === 'analyst';
  const isViewer = role === 'viewer';

  const canManageUsers = isAdmin;
  const canEditWatchlist = isAdmin || isInvestigator;
  const canExportStix = isAdmin || isInvestigator;
  const canDeleteCases = isAdmin || isInvestigator;
  const canEditCases = isAdmin || isInvestigator || isAnalyst;
  const canViewCases = isAdmin || isInvestigator || isAnalyst || isViewer;

  return {
    role,
    isAdmin,
    isInvestigator,
    isAnalyst,
    isViewer,
    canManageUsers,
    canEditWatchlist,
    canExportStix,
    canDeleteCases,
    canEditCases,
    canViewCases,
  };
}

export function useAllowedRoles(...allowedRoles: string[]) {
  const { role } = useAuth();
  return allowedRoles.includes(role || '');
}
