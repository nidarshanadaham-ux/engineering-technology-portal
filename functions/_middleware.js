import { hasValidSession } from "./_auth.js";

export async function onRequest({ request, env, next }) {
  const url = new URL(request.url);
  const isEntry = url.pathname === "/" || url.pathname === "/index.html";

  if (url.pathname === "/api/auth") return next();

  if (await hasValidSession(request, env.AUTH_SECRET)) {
    if (isEntry) return Response.redirect(new URL("/Final.html", url), 302);
    return next();
  }

  if (isEntry) return next();
  if (url.pathname.startsWith("/api/")) {
    return Response.json(
      { error: "Authentication required." },
      { status: 401, headers: { "Cache-Control": "no-store" } }
    );
  }
  return Response.redirect(new URL("/", url), 302);
}
