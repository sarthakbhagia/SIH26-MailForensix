# AUTH_MIGRATION_PLAN.md

## Authentication Migration Plan: MailForensix SOC DFIR Workstation

This plan details the migration of authentication functionality from the previous frontend (`C:\Advait\projects\SIH\Sarthak\SIH26-MailForensix\frontend`) into the redesigned **UI/UX Pro Max** frontend (`C:\Advait\projects\SIH\Trial\SIH26-MailForensix_expt\frontend`). 

---

## 1. Authentication Functionality in the OLD Frontend

The old frontend implements full JWT-based authentication and role-based access control (RBAC):
- **Types (`src/types/auth.ts`)**: Defines `User` (id, email, role, org_id, created_at, is_active), `AuthState`, `LoginCredentials`, `LoginResponse`. Roles supported: `admin`, `analyst`, `investigator`, `viewer`.
- **State & Context (`src/context/AuthContext.tsx`)**:
  - `AuthProvider` wraps the application router.
  - Hydrates state synchronously on load from `localStorage['mailforensix_auth']`.
  - Normalizes Bearer token prefixes (`Bearer <token>`).
  - Calls `api.getCurrentUser()` on startup to validate token against `/api/auth/me`.
  - Exposes `login({ email, password })`, `logout()`, `refreshUser()`, `isAuthenticated`, `isLoading`, `user`, `role`.
- **Role Hooks (`src/hooks/useRole.ts`)**:
  - `useRole()` evaluates `isAdmin`, `isInvestigator`, `isAnalyst`, `isViewer`, `canManageUsers`, `canEditCases`, `canDeleteCases`, `canExportStix`, `canViewCases`.
  - `useAllowedRoles(...roles)` checks if active user matches specific roles.
- **API Interceptors & Endpoints (`src/lib/api.ts`)**:
  - Maintains `authToken` in memory with `setAuthToken()`.
  - Axios request interceptor attaches `Authorization: Bearer <token>`.
  - Axios response interceptor intercepts `401 Unauthorized`: clears `localStorage['mailforensix_auth']`, stores current URL in `sessionStorage['auth_redirect']`, and redirects to `/login`.
  - Methods: `api.login` (sends FormData with `username`, `password`), `api.getCurrentUser` (`GET /api/auth/me`).
- **Route Guard (`src/components/auth/ProtectedRoute.tsx`)**:
  - Wraps application routes. Shows loading indicator while verifying authentication.
  - Redirects unauthenticated users to `/login` with `state: { from: location }`.
  - Supports `allowedRoles` enforcement (redirects unauthorized users to `/`).
- **User Interface (`src/pages/LoginPage.tsx` & `src/components/layout/Header.tsx`)**:
  - Legacy login form with email, password, toggle visibility, and error banner.
  - Header profile dropdown displays user email and role with Sign Out trigger.

---

## 2. Authentication Functionality Currently in the NEW Frontend

The current UI/UX Pro Max frontend is a clean modern redesign of the DFIR workstation:
- **Routing (`src/App.tsx`)**: Uses React Router v6 `<Routes>` with `<Route path="/" element={<DashboardLayout />}>`. All routes are currently public without protection. No `/login` route exists.
- **API Client (`src/lib/api.ts`)**: Axios instance pointing to `/api` without authorization headers or 401 interceptors. No login or current user methods exist.
- **State Management**: Uses `@tanstack/react-query` for query caching. No auth state or context exists.
- **Header (`src/components/layout/Header.tsx`)**: Displays a static non-interactive chip labeled `"SOC ANALYST"`. No user profile dropdown or logout exists.
- **Command Palette (`src/components/layout/CommandPalette.tsx`)**: Full keyboard navigation palette without sign-out or session locking commands.

---

## 3. Files to Migrate and Create

The following files will be added to the current frontend:
1. `src/types/auth.ts`: TypeScript models for User, AuthState, LoginCredentials, LoginResponse.
2. `src/context/AuthContext.tsx`: Context provider and `useAuth` hook with token persistence and normalization.
3. `src/hooks/useRole.ts`: RBAC permission evaluation hook.
4. `src/components/auth/ProtectedRoute.tsx`: Route guard with UI/UX Pro Max styled loading screen.
5. `src/components/ui/dropdown-menu.tsx`: Radix UI dropdown primitive styled with workstation design tokens.
6. `src/pages/LoginPage.tsx`: Brand new login page designed natively in UI/UX Pro Max aesthetic (dark workstation theme, radar glow, JetBrains Mono labels, input icons, error banner, loading states).

---

## 4. Existing Files to Modify

1. **`src/lib/api.ts`**:
   - Add `authToken` memory cache and `setAuthToken(token)`.
   - Add Axios Request Interceptor for Bearer token injection.
   - Add Axios Response Interceptor for 401 handling, redirect storage, and login redirect.
   - Add `api.login` and `api.getCurrentUser`.
2. **`src/App.tsx`**:
   - Wrap application in `<AuthProvider>`.
   - Add `/login` route.
   - Wrap `<DashboardLayout />` in `<ProtectedRoute>`.
   - Add catch-all wildcard redirect to `/`.
3. **`src/components/layout/Header.tsx`**:
   - Upgrade static `SOC ANALYST` chip into an interactive Radix dropdown menu displaying `user.email`, `user.role`, and "Sign Out" button.
4. **`src/components/layout/CommandPalette.tsx`**:
   - Add "Sign Out / Lock Console" command.

---

## 5. Old Files Intentionally NOT Copied

- **Old `LoginPage.tsx` visual markup**: Legacy UI styling is rejected; we create a bespoke UI/UX Pro Max login interface matching the DFIR Workstation design system.
- **Old `DashboardLayout.tsx` / `Sidebar.tsx`**: Current navigation rail, breadcrumbs, and command palette are preserved intact.

---

## 6. Backend Authentication Connection

- **Login**: `POST /api/auth/login` (Content-Type: `application/x-www-form-urlencoded` / `multipart/form-data` with fields `username` and `password`).
- **Response**: `{ "access_token": "<jwt>", "token_type": "bearer" }`.
- **Current User**: `GET /api/auth/me` (Header: `Authorization: Bearer <jwt>`).
- **Response**: `{ "id": "...", "email": "...", "role": "admin", "org_id": null, "created_at": "...", "is_active": true }`.
- **Proxy**: Vite proxies `/api` requests to `http://localhost:8000`.

---

## 7. Token and Session Management

- **Storage**: Tokens and user data are persisted in `localStorage` under key `mailforensix_auth`.
- **Format**: `{"token": "Bearer <access_token>", "user": {...}}`.
- **Hydration**: Synced on boot before render to prevent auth flash.
- **Validation**: Background call to `/api/auth/me` on startup.
- **Expiration**: 401 response triggers `clearAuth()`, sets `sessionStorage['auth_redirect']`, and redirects to `/login`.

---

## 8. Protected Routes in the New Architecture

```tsx
<AuthProvider>
  <Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route element={<ProtectedRoute><DashboardLayout /></ProtectedRoute>}>
      <Route index element={<DashboardPage />} />
      <Route path="ingest" element={<EmailIngestPage />} />
      <Route path="emails/:emailId" element={<EmailAnalysisPage />} />
      <Route path="map" element={<TraceMapPage />} />
      <Route path="graph" element={<AttributionGraphPage />} />
      <Route path="cases" element={<CasesPage />} />
      <Route path="cases/:caseId" element={<CasesPage />} />
      <Route path="reports" element={<ReportsPage />} />
    </Route>
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>
</AuthProvider>
```

---

## 9. Logout Workflow

1. User clicks "Sign Out" from the Header profile dropdown or executes "Sign Out / Lock Workstation" in Command Palette.
2. `logout()` is invoked from `useAuth()`.
3. `localStorage.removeItem('mailforensix_auth')` is called and `setAuthToken(null)` resets the Axios Authorization header.
4. React state is updated to `{ user: null, token: null, isAuthenticated: false }`.
5. User is redirected to `/login`.

---

## 10. Potential Architectural Conflicts & Mitigations

| Potential Conflict | Mitigation |
| :--- | :--- |
| **Token prefix inconsistency** (raw JWT vs `Bearer JWT`) | `AuthContext` normalizes any token to ensure `Bearer ` prefix is reliably maintained. |
| **Flicker on refresh** (brief redirect to login before localStorage loads) | State is synchronously initialized from `localStorage` in `useState` initializer before async re-validation. |
| **UI/UX mismatch** | All new auth UI elements strictly use CSS variables (`--surface`, `--border`, `--primary`), `IBM Plex Sans`, and `JetBrains Mono` without introducing arbitrary or legacy styling. |
| **Dropdown component missing in UI folder** | Add `src/components/ui/dropdown-menu.tsx` built on Radix UI to provide accessible, theme-consistent dropdown menus. |

---

## 11. Exact Implementation Order

1. **Step 1: Auth Types & Primitives**: Create `src/types/auth.ts` and `src/components/ui/dropdown-menu.tsx`.
2. **Step 2: API Client Upgrade**: Update `src/lib/api.ts` with token handling, interceptors, and auth endpoints.
3. **Step 3: Auth Context & Role Hooks**: Create `src/context/AuthContext.tsx` and `src/hooks/useRole.ts`.
4. **Step 4: Route Guards**: Create `src/components/auth/ProtectedRoute.tsx`.
5. **Step 5: UI/UX Pro Max Login Page**: Create `src/pages/LoginPage.tsx`.
6. **Step 6: Workstation Shell Integration**: Update `src/App.tsx`, `src/components/layout/Header.tsx`, and `src/components/layout/CommandPalette.tsx`.
7. **Step 7: Verification**: Type check, build check, and regression testing.
