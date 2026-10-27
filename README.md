# Engineering Technology Portal

This is the Cloudflare Pages deployment package for the portal. The passkey is
not stored in this repository; Cloudflare checks it in a Pages Function and
issues a short-lived, signed, `HttpOnly` session cookie. The Pages middleware
protects the HTML pages and their assets before serving them.

## Deploy with Cloudflare Pages

1. Push this folder's contents to a new GitHub repository, then create a
   Cloudflare Pages project connected to that repository.
2. Leave the build command empty and set the build output directory to `.`.
   The included `wrangler.toml` identifies the Pages output directory.
3. In the Pages project's **Settings → Variables and Secrets**, add production
   secrets named `SITE_PASSKEY` and `AUTH_SECRET`. Set `SITE_PASSKEY` to the
   passkey you want to retain. Set `AUTH_SECRET` to a newly generated random
   value of at least 32 bytes; for example, generate one locally with
   `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`.
   Do not commit either value or paste it into a public chat.
4. Deploy the project. Set the same secrets for Preview deployments if those
   deployments should allow sign-in.

The passkey screen is a login gate, not user-specific authorization. Anyone
with the passkey can access the portal. Use a strong passkey, and configure a
Cloudflare rate-limiting rule for `POST /api/auth` before sharing the site
widely.

The site must be deployed through Cloudflare Pages for the Functions and
middleware to protect its content. A static-only host such as GitHub Pages
will not execute these access checks.
