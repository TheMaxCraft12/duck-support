const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" }
  });

const encoder = new TextEncoder();

function randomHex(length = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: encoder.encode(salt),
    iterations: 100000,
    hash: "SHA-256"
  }, key, 256);

  return [...new Uint8Array(bits)]
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hashToken(token) {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(token));
  return [...new Uint8Array(hash)]
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

async function getSession(request, env) {
  const token = request.headers.get("Authorization")?.replace("Bearer ", "");
  if (!token) return null;

  const tokenHash = await hashToken(token);
  const session = await env.DB.prepare(
    "SELECT user_id, role FROM sessions WHERE token_hash = ? AND expires_at > datetime('now')"
  ).bind(tokenHash).first();

  return session ? { ...session, tokenHash } : null;
}

async function createSession(env, userId, role) {
  const token = randomHex(32);
  const tokenHash = await hashToken(token);

  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, role, expires_at) VALUES (?, ?, ?, datetime('now', '+8 hours'))"
  ).bind(tokenHash, userId, role).run();

  return token;
}

async function handle(request, env) {
  if (request.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS });
  }

  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "GET" && path === "/") {
    return json({ ok: true, service: "Ducky Support API" });
  }

  if (request.method !== "GET" && request.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  let body = {};
  if (request.method === "POST") {
    try {
      body = await request.json();
    } catch {
      return json({ error: "Ungültige JSON-Daten" }, 400);
    }
  }

  if (path === "/api/register" && request.method === "POST") {
    const name = String(body.name || "").trim();
    const password = String(body.password || "");

    if (name.length < 3 || name.length > 24 || password.length < 8) {
      return json({ error: "Name oder Passwort ungültig" }, 400);
    }

    const salt = randomHex(16);
    const passwordHash = await hashPassword(password, salt);

    try {
      const result = await env.DB.prepare(
        "INSERT INTO users (name, password_hash, password_salt) VALUES (?, ?, ?)"
      ).bind(name, passwordHash, salt).run();

      const token = await createSession(env, result.meta.last_row_id, "user");
      return json({ ok: true, token });
    } catch {
      return json({ error: "Benutzername ist bereits vergeben" }, 409);
    }
  }

  if (path === "/api/login" && request.method === "POST") {
    const name = String(body.name || "").trim();
    const password = String(body.password || "");

    const user = await env.DB.prepare(
      "SELECT id, password_hash, password_salt FROM users WHERE name = ?"
    ).bind(name).first();

    if (!user) return json({ error: "Anmeldedaten falsch" }, 401);

    const hash = await hashPassword(password, user.password_salt);
    if (hash !== user.password_hash) {
      return json({ error: "Anmeldedaten falsch" }, 401);
    }

    const token = await createSession(env, user.id, "user");
    return json({ ok: true, token });
  }

  if (path === "/api/admin/login" && request.method === "POST") {
    if (!env.ADMIN_PASSWORD) {
      return json({ error: "Admin-Passwort ist nicht eingerichtet" }, 500);
    }

    if (String(body.password || "") !== env.ADMIN_PASSWORD) {
      return json({ error: "Admin-Passwort falsch" }, 401);
    }

    const token = await createSession(env, null, "admin");
    return json({ ok: true, token });
  }

  const session = await getSession(request, env);

  if (path === "/api/logout" && request.method === "POST") {
    if (session) {
      await env.DB.prepare(
        "DELETE FROM sessions WHERE token_hash = ?"
      ).bind(session.tokenHash).run();
    }
    return json({ ok: true });
  }

  if (path === "/api/me" && request.method === "GET") {
    if (!session) return json({ error: "Nicht angemeldet" }, 401);
    if (session.role === "admin") return json({ ok: true, role: "admin" });

    const user = await env.DB.prepare(
      "SELECT id, name, coins FROM users WHERE id = ?"
    ).bind(session.user_id).first();

    return json({ ok: true, role: "user", user });
  }

  if (path === "/api/messages" && request.method === "GET") {
    if (!session || session.role !== "user") {
      return json({ error: "Nicht angemeldet" }, 401);
    }

    const result = await env.DB.prepare(
      "SELECT id, sender_role, text, created_at FROM messages WHERE user_id = ? ORDER BY id"
    ).bind(session.user_id).all();

    return json({ ok: true, messages: result.results });
  }

  if (path === "/api/messages" && request.method === "POST") {
    if (!session || session.role !== "user") {
      return json({ error: "Nicht angemeldet" }, 401);
    }

    const message = String(body.text || "").trim();
    if (!message || message.length > 2000) {
      return json({ error: "Nachricht ungültig" }, 400);
    }

    await env.DB.prepare(
      "INSERT INTO messages (user_id, sender_role, text) VALUES (?, 'user', ?)"
    ).bind(session.user_id, message).run();

    return json({ ok: true });
  }

  if (path === "/api/admin/messages" && request.method === "GET") {
    if (!session || session.role !== "admin") {
      return json({ error: "Keine Admin-Berechtigung" }, 403);
    }

    const result = await env.DB.prepare(`
      SELECT messages.id, messages.user_id, users.name,
             messages.sender_role, messages.text, messages.created_at
      FROM messages
      JOIN users ON users.id = messages.user_id
      ORDER BY messages.id
    `).all();

    return json({ ok: true, messages: result.results });
  }

  if (path === "/api/admin/reply" && request.method === "POST") {
    if (!session || session.role !== "admin") {
      return json({ error: "Keine Admin-Berechtigung" }, 403);
    }

    const userId = Number(body.userId);
    const message = String(body.text || "").trim();

    if (!Number.isInteger(userId) || userId < 1 || !message || message.length > 2000) {
      return json({ error: "Nachricht ungültig" }, 400);
    }

    await env.DB.prepare(
      "INSERT INTO messages (user_id, sender_role, text) VALUES (?, 'admin', ?)"
    ).bind(userId, message).run();

    return json({ ok: true });
  }

  return json({ error: "Nicht gefunden" }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (error) {
      return json({ error: "Serverfehler", details: error.message }, 500);
    }
  }
};
