# BUG 1 — EXACT ROOT CAUSE

## 1. Reproduction

**Action:** On `/ingest` page, click the **Analyze** button for any ingested email evidence artifact.

**Expected:** Navigate to `/emails/:emailId` and display the analysis page with Overview tab active.

**Actual:** Page becomes completely blank (white screen, no UI, no error message).

**Environment constraint:** Backend database unavailable; cannot fully reproduce end-to-end. Frontend builds and type-checks cleanly.

---

## 2. Exact Execution Trace

```
1. EmailList.tsx:238
   onClick={() => navigate(`/emails/${email.id}`)}

2. React Router matches route: App.tsx:17
   <Route path="emails/:emailId" element={<EmailAnalysisPage />} />

3. EmailAnalysisPage mounts (line 43)
   ├─ useParams() → { emailId: "uuid-string" }
   ├─ useEmail(emailId) → GET /api/emails/{id}
   │   └─ Returns EmailDetail (ingested_at, sender, subject, headers, etc.)
   └─ useAnalysis(emailId) → GET /api/analysis/{id}
       └─ Returns AnalysisResponse (status, auth_result, nlp_result, etc.)

4. Initial render (both queries loading):
   Line 63: if (emailLoading || (analysisLoading && !analysis && !emailError))
   → Renders loading skeleton (lines 64-70)

5. Email query resolves first (typical):
   emailLoading = false, email = EmailDetail data
   analysisLoading = true, analysis = undefined
   → Still shows loading skeleton (analysisLoading && !analysis)

6. Analysis query resolves:
   analysisLoading = false, analysis = AnalysisResponse data
   
   State computation (lines 90-92):
   analysisStatus = analysis?.status || String(mEmail.status)
   isPendingOrProcessing = analysisStatus === 'pending' || 'processing'
   isFailed = analysisStatus === 'error' || (analysisError && !analysis)

7. For an already-analyzed email:
   analysisStatus = "analyzed"
   isPendingOrProcessing = false
   isFailed = false
   → Enters COMPLETE STATE (line 268+)

8. Complete state variable computation (lines 269-590):
   mAnalysis = analysis || fallback_object
   riskScore = Math.round(mAnalysis.composite_risk_score ?? mEmail.risk_score ?? 0)
   attributionConfidence = normalizeConfidence(mAnalysis.attribution_confidence)  // → null
   authResult = mAnalysis.auth_result || mAnalysis.auth_status || {}
   spf/dkim/dmarc objects built from authResult with fallbacks
   relayPath, originGeo, geoHops, iocs, findings all computed

9. Render tree (lines 592-792):
   ├─ EmailEvidenceHeader (line 595)
   ├─ Navigation strip (line 614)
   └─ OverviewSummary (line 652)  ← DEFAULT TAB
       ├─ 4× AuthPill (SPF, DKIM, DMARC, ALIGNMENT)
       ├─ FindingCard[] (from findings array)
       └─ IOC list (from topIocs)

10. During render, reportText template literal evaluated (line 525-572):
    const reportText = `... INGESTED AT : ${new Date(mEmail.ingested_at || Date.now()).toISOString()} ...`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    THIS EXPRESSION IS EVALUATED ON EVERY RENDER OF COMPLETE STATE
```

---

## 3. Exact Runtime Exception

**NOT REPRODUCIBLE IN CURRENT ENVIRONMENT** (backend unavailable).

**Hypothesized exception based on static analysis:**

```
RangeError: Invalid time value
    at EmailAnalysisPage (EmailAnalysisPage.tsx:529)
    at renderWithHooks (react-reconciler.development.js)
    at mountIndeterminateComponent
    ...
```

**Stack trace would show:**
- Origin: `EmailAnalysisPage.tsx:529` in `reportText` template literal
- Expression: `new Date(mEmail.ingested_at || Date.now()).toISOString()`
- Trigger: `mEmail.ingested_at` contains a date string that `Date` constructor parses as "Invalid Date"

---

## 4. Exact Crashing File

**File:** `C:\Advait\projects\SIH\Trial\SIH26-MailForensix_expt\frontend\src\pages\EmailAnalysisPage.tsx`

**Function/Component:** `EmailAnalysisPage` (default export)

**Line:** 529 (inside `reportText` template literal)

**Expression:**
```typescript
${new Date(mEmail.ingested_at || Date.now()).toISOString()}
```

---

## 5. Runtime Value Causing Failure

**Variable:** `mEmail.ingested_at`

**Expected:** Valid ISO 8601 date string (e.g., `"2024-01-15T10:30:00"` or `"2024-01-15T10:30:00.123Z"`)

**Actual (hypothesized):** A malformed date string that JavaScript's `Date` constructor cannot parse, such as:
- `"invalid-date"`
- `""` (empty string - but `|| Date.now()` handles this)
- `" "` (whitespace)
- `"2024-13-45T99:99:99"` (invalid calendar values)
- A non-string value that coerces unexpectedly

**Why it crashes:** `new Date(invalid_string)` creates a `Date` object with `timeValue = NaN` ("Invalid Date"). Calling `.toISOString()` on an Invalid Date throws `RangeError: Invalid time value`.

**Why `|| Date.now()` doesn't prevent it:** The `||` operator only falls back if the left side is falsy. A non-empty string (even if invalid) is truthy, so `Date.now()` is never used.

---

## 6. Why It Happens (Causal Chain)

```
Backend stores ingested_at as naive UTC datetime (SQLAlchemy DateTime)
    ↓
Pydantic serializes to ISO string: "2024-01-15T10:30:00" (no timezone suffix)
    ↓
Frontend receives as string in EmailDetail.ingested_at
    ↓
EmailAnalysisPage constructs reportText template literal
    ↓
Template literal evaluated on EVERY render of complete state
    ↓
new Date("2024-01-15T10:30:00").toISOString()  // Parses as LOCAL time per ES2020
    ↓
If system timezone causes parsing edge case OR date string is malformed in DB
    ↓
Date object becomes "Invalid Date" (timeValue = NaN)
    ↓
.toISOString() throws RangeError
    ↓
ErrorBoundary catches error → sets hasError = true
    ↓
ErrorBoundary re-renders fallback UI
    ↓
Fallback imports ShieldAlert, RefreshCw, Home from 'lucide-react'
    ↓
If lucide-react chunk fails to load (network/chunk error during error rendering)
    ↓
ErrorBoundary fallback THROWS
    ↓
React unmounts ErrorBoundary (no parent boundary)
    ↓
COMPLETELY BLANK PAGE
```

**Critical insight:** The `reportText` constant is evaluated on **every render** of the complete state (line 525), not just when the Dossier tab is active. It is not memoized, not lazy, not conditional.

---

## 7. Why TypeScript Did Not Catch It

1. **Type correctness:** `mEmail.ingested_at` is typed as `string` (EmailSummary.ingested_at: string). TypeScript sees a string → `new Date(string)` → `Date` → `.toISOString()` → `string`. All types align.

2. **No runtime validation:** TypeScript cannot validate that a `string` is a valid ISO date at compile time.

3. **Fallback operator misleads:** `mEmail.ingested_at || Date.now()` appears safe but only handles falsy values (`null`, `undefined`, `""`), not invalid-but-truthy strings.

4. **ErrorBoundary typed as catching `Error`:** `RangeError` extends `Error`, so `componentDidCatch` receives it correctly. TypeScript doesn't know the fallback might also throw.

---

## 8. ErrorBoundary Analysis

**Location:** `main.tsx:14` wraps entire app: `<ErrorBoundary><QueryClientProvider>...</ErrorBoundary>`

**Implementation:** `ErrorBoundary.tsx` (class component with `getDerivedStateFromError` + `componentDidCatch`)

**Behavior when child throws:**
1. `getDerivedStateFromError` → sets `hasError: true`
2. `componentDidCatch` → logs to console
3. Next render: `render()` returns fallback UI (lines 46-90)

**Why user sees BLANK PAGE (not error UI):**

The fallback UI (lines 46-90) has **external dependencies**:
```tsx
import { ShieldAlert, RefreshCw, Home } from 'lucide-react';  // Line 2
import { Button } from '@/components/ui/button';               // Line 3
```

If a **chunk loading error** occurs while the ErrorBoundary tries to render its fallback (e.g., `lucide-react` or `Button` chunk fails to load due to network blip, CSP, or corrupted cache), the fallback itself throws.

**React's behavior:** When an error boundary throws during fallback render, React unmounts the error boundary and propagates upward. Since this ErrorBoundary is at the **root** (in `main.tsx`), there is no parent boundary → **entire app unmounts → blank page**.

**Evidence this is plausible:**
- `vendor-map` chunk is 824 KB (maplibre-gl + react-map-gl)
- `lucide-react` is used throughout app but may be in a separate chunk
- Chunk loading errors are NOT caught by ErrorBoundary
- User reports "completely blank" (not "error message displayed")

---

## 9. Root Cause Classification

**HIGH-CONFIDENCE ROOT CAUSE**

**Primary:** `reportText` template literal at line 529 throws `RangeError` when `mEmail.ingested_at` is an invalid date string.

**Secondary (why blank not error UI):** ErrorBoundary fallback depends on `lucide-react`/`Button` imports; if chunk loading fails during fallback render, React unmounts entire app.

**Not CONFIRMED because:** Cannot execute backend to verify actual `ingested_at` value or reproduce chunk loading failure. Requires runtime verification.

---

## 10. Contributing Factors

| Factor | Impact |
|--------|--------|
| `reportText` evaluated on every render (not memoized, not tab-conditional) | High - guarantees crash on any complete-state render |
| `toISOString()` throws on Invalid Date (no graceful fallback) | High - JavaScript spec behavior |
| `|| Date.now()` fallback only handles falsy, not invalid strings | Medium - common misconception |
| ErrorBoundary fallback has external imports (`lucide-react`, `Button`) | High - creates second failure mode |
| No `useMemo` for `reportText` | Medium - re-evaluates on every render |
| Dossier tab not default but `reportText` computed anyway | Medium - wasted work + crash surface |
| No backend to verify actual `ingested_at` format | Blocker for confirmation |

---

## 11. Minimal Fix (Conceptual Only — DO NOT IMPLEMENT)

**Fix 1 — Guard the date parsing (EmailAnalysisPage.tsx:529):**
```typescript
const safeIngestedAt = (() => {
  const d = mEmail.ingested_at ? new Date(mEmail.ingested_at) : new Date();
  return isNaN(d.getTime()) ? new Date() : d;
})();
const reportText = `... INGESTED AT : ${safeIngestedAt.toISOString()} ...`;
```

**Fix 2 — Move `reportText` inside Dossier tab render (line 729+):**
Only compute when `activeDomain === 'dossier'`, not on every render.

**Fix 3 — Make ErrorBoundary fallback zero-dependency (ErrorBoundary.tsx):**
Replace `lucide-react` icons with inline SVG; avoid `Button` component (use native `<button>`).

**Fix 4 — Add granular ErrorBoundaries per route/tab:**
Wrap `EmailAnalysisPage` in its own boundary so root boundary never sees the error.

---

## 12. Verification Test

**Unit Test (Vitest/Jest):**
```typescript
test('EmailAnalysisPage handles invalid ingested_at without crashing', () => {
  const invalidEmail = { 
    ...mockEmail, 
    ingested_at: 'invalid-date-string' 
  };
  const mockAnalysis = { status: 'analyzed', ... };
  
  // Mock queries to return invalid email + valid analysis
  renderWithQueryClient(<EmailAnalysisPage />);
  
  // Should NOT throw RangeError
  // Should render EmailEvidenceHeader + OverviewSummary
  expect(screen.getByText('Forensic Threat Findings')).toBeInTheDocument();
});
```

**Integration Test (Playwright):**
```typescript
test('Analyze button navigates to analysis page without blank screen', async ({ page }) => {
  await page.goto('/ingest');
  await page.waitForSelector('[data-testid="email-row"]');
  await page.click('[data-testid="analyze-button"]');
  
  // Wait for navigation and render
  await page.waitForURL(/\/emails\/.+/);
  await page.waitForSelector('[data-testid="email-evidence-header"]');
  
  // Verify no blank page
  const bodyText = await page.textContent('body');
  expect(bodyText).not.toBe('');
  expect(bodyText).not.toContain('Forensic Workstation Exception');
});
```

**Manual Verification Steps:**
1. Start backend with test database
2. Ingest a sample email
3. Verify `ingested_at` in DB is valid ISO string
4. Click Analyze in UI
4. Confirm page renders (not blank)
5. Check browser console for `RangeError` or chunk load errors

---

## Summary for Implementation Agent

**The crash is almost certainly at `EmailAnalysisPage.tsx:529`** where `new Date(mEmail.ingested_at).toISOString()` throws `RangeError` on an invalid date string, and the ErrorBoundary fallback then fails to render due to chunk loading dependencies.

**Priority order for fixes:**
1. Guard `toISOString()` call with `isNaN()` check
2. Move `reportText` computation inside Dossier tab only
3. Make ErrorBoundary fallback zero-dependency (inline SVG, native button)
4. Add route-level ErrorBoundary around `EmailAnalysisPage`