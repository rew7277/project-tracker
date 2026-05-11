# V21 Ops Center + Cache Fix

## Root cause
Production serves `template.html` as the active SPA bundle. Previous Ops Center patches were applied to `main.js`/`frontend.js`, but `template.html` still did not include `ops` in `VALID_VIEWS` and did not render `OpsCommandCenter`. That is why the sidebar/header showed Ops Center but the content area stayed blank.

## Fixed
- Added `ops` to `template.html` valid route list.
- Added `OpsCommandCenter` rendering to the production template.
- Added role helper `hasOpsAccess()` to the template.
- Restricted Ops Center to Admin/Owner/Manager/Project Manager/Team Lead/Super Admin.
- Removed Ops Center from regular user sidebar.
- Changed served HTML/JS/CSS cache headers to `no-cache, no-store` so deployed UI fixes do not stay hidden behind old browser/CDN cache.

## Validation
- `python3 -m py_compile app.py`
- `node --check main.js`
- `node --check frontend.js`
