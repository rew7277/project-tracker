# Runtime fixes applied

- Fixed Postgres TLS handling for self-signed/internal CA deployments. The app now defaults to encrypted `sslmode=require` behavior and supports strict verification with `DB_SSL_VERIFY=true` and optional `DB_SSL_CA_FILE`.
- Added `/manifest.json`, `/sw.js`, and `/favicon.ico` routes to stop browser 404 noise.
- Added JSON API error handlers so `/api/*` failures return JSON instead of raw HTML error pages.
- Sanitized frontend API error messages so users do not see full HTML error documents in the login/dashboard UI.

The attached logs showed `SSLCertVerificationError: certificate verify failed: self-signed certificate in certificate chain`, which was the direct cause of the 500s on `/api/auth/me` and `/api/auth/login`.
