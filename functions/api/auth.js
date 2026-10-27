import {
  constantTimeEqual,
  createSessionCookie,
  hasValidSession
} from "../_auth.js";

const noStore = { "Cache-Control": "no-store" };

function response(status, message) {
  return Response.json({ message }, { status, headers: noStore });
}

function hasRequiredSecrets(env) {
  const valid = Boolean(
    env.SITE_PASSKEY &&
    env.AUTH_SECRET &&
    new TextEncoder().encode(env.AUTH_SECRET).length >= 32
  );
  if (!valid) console.error("Set SITE_PASSKEY and a 32-byte-or-longer AUTH_SECRET in Cloudflare.");
  return valid;
}

export async function onRequestGet({ request, env }) {
  if (!hasRequiredSecrets(env)) return response(503, "Login service is not configured.");
  return new Response(null, {
    status: (await hasValidSession(request, env.AUTH_SECRET)) ? 204 : 401,
    headers: noStore
  });
}

export async function onRequestPost({ request, env }) {
  if (!hasRequiredSecrets(env)) return response(503, "Login service is not configured.");

  const origin = request.headers.get("Origin");
  if (origin && origin !== new URL(request.url).origin) {
    return response(403, "Request origin is not allowed.");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return response(400, "Invalid request.");
  }

  if (typeof body?.passkey !== "string" || body.passkey.length > 256) {
    return response(400, "Invalid request.");
  }
  if (!constantTimeEqual(body.passkey.trim(), env.SITE_PASSKEY)) {
    return response(401, "Incorrect passkey.");
  }

  return new Response(null, {
    status: 204,
    headers: {
      ...noStore,
      "Set-Cookie": await createSessionCookie(env.AUTH_SECRET)
    }
  });
}

export async function onRequestDelete({ env }) {
  if (!hasRequiredSecrets(env)) return response(503, "Login service is not configured.");
  return new Response(null, {
    status: 204,
    headers: {
      ...noStore,
      "Set-Cookie": "__Host-et_portal=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
    }
  });
}
