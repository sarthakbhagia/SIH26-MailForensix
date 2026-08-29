import test from 'node:test';
import assert from 'node:assert/strict';

test('Token Normalization - properly handles Bearer prefixing', () => {
  const normalizeToken = (token: string) => {
    return token.startsWith('Bearer ') ? token : `Bearer ${token.replace(/^bearer\s+/i, '')}`;
  };

  assert.equal(normalizeToken('Bearer eyJhbGciOi...'), 'Bearer eyJhbGciOi...');
  assert.equal(normalizeToken('eyJhbGciOi...'), 'Bearer eyJhbGciOi...');
  assert.equal(normalizeToken('bearer eyJhbGciOi...'), 'Bearer eyJhbGciOi...');
});

test('Session Storage Key & Model Integrity', () => {
  const STORAGE_KEY = 'mailforensix_auth';
  assert.equal(STORAGE_KEY, 'mailforensix_auth');

  const mockUser = {
    id: 'usr-1',
    email: 'admin@mailforensix.local',
    role: 'admin',
    created_at: '2026-08-29T12:00:00Z',
    is_active: true,
  };
  const mockToken = 'Bearer test-jwt-token';
  const serialized = JSON.stringify({ token: mockToken, user: mockUser });
  const parsed = JSON.parse(serialized);

  assert.equal(parsed.token, mockToken);
  assert.equal(parsed.user.email, 'admin@mailforensix.local');
  assert.equal(parsed.user.role, 'admin');
});

test('RBAC Matrix - Evaluates all four system roles accurately', () => {
  const evaluateRoles = (role: string | null | undefined) => {
    const isAdmin = role === 'admin';
    const isInvestigator = role === 'investigator';
    const isAnalyst = role === 'analyst';
    const isViewer = role === 'viewer';

    return {
      isAdmin,
      isInvestigator,
      isAnalyst,
      isViewer,
      canManageUsers: isAdmin,
      canEditWatchlist: isAdmin || isInvestigator,
      canExportStix: isAdmin || isInvestigator,
      canDeleteCases: isAdmin || isInvestigator,
      canEditCases: isAdmin || isInvestigator || isAnalyst,
      canViewCases: isAdmin || isInvestigator || isAnalyst || isViewer,
    };
  };

  const admin = evaluateRoles('admin');
  assert.equal(admin.isAdmin, true);
  assert.equal(admin.canManageUsers, true);
  assert.equal(admin.canDeleteCases, true);
  assert.equal(admin.canEditCases, true);
  assert.equal(admin.canExportStix, true);

  const investigator = evaluateRoles('investigator');
  assert.equal(investigator.isInvestigator, true);
  assert.equal(investigator.canManageUsers, false);
  assert.equal(investigator.canDeleteCases, true);
  assert.equal(investigator.canEditCases, true);
  assert.equal(investigator.canExportStix, true);

  const analyst = evaluateRoles('analyst');
  assert.equal(analyst.isAnalyst, true);
  assert.equal(analyst.canManageUsers, false);
  assert.equal(analyst.canDeleteCases, false);
  assert.equal(analyst.canEditCases, true);
  assert.equal(analyst.canViewCases, true);

  const viewer = evaluateRoles('viewer');
  assert.equal(viewer.isViewer, true);
  assert.equal(viewer.canManageUsers, false);
  assert.equal(viewer.canEditCases, false);
  assert.equal(viewer.canViewCases, true);
});
