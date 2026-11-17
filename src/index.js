const ACCOUNTS = {
  "kuromy1968@gmail.com": "user",
  "asukasa462@gmail.com": "admin"
};
const GOAL = 30000;
const AMOUNT = 100;
const MAX_COUNT = GOAL / AMOUNT;

function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function reply(env, body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders(env) }
  });
}

function parseJst(value) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) return null;
  const date = new Date(value + ":00+09:00");
  if (Number.isNaN(date.getTime())) return null;
  return { date, day: value.slice(0, 10) };
}

function todayJst() {
  return new Date(Date.now() + 9 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

const SESSION_DAYS = 365;
const encoder = new TextEncoder();

function toB64Url(bytes) {
  let bin = "";
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64Url(text) {
  const pad = "=".repeat((4 - (text.length % 4)) % 4);
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function hmacKey(env) {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(env.SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function issueSession(email, env) {
  const exp = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  const payload = toB64Url(encoder.encode(JSON.stringify({ email, exp })));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env), encoder.encode(payload));
  return payload + "." + toB64Url(sig);
}

async function verifySession(token, env) {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  try {
    const ok = await crypto.subtle.verify(
      "HMAC",
      await hmacKey(env),
      fromB64Url(parts[1]),
      encoder.encode(parts[0])
    );
    if (!ok) return null;
    const data = JSON.parse(new TextDecoder().decode(fromB64Url(parts[0])));
    if (!data.email || !(data.exp > Date.now())) return null;
    return String(data.email).toLowerCase();
  } catch (e) {
    return null;
  }
}

function bearer(request) {
  const header = request.headers.get("Authorization") || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

async function verifyGoogle(request, env) {
  const token = bearer(request);
  if (!token) return { error: 401, reason: "no_token" };

  const res = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(token));
  if (!res.ok) return { error: 401, reason: "tokeninfo_" + res.status };

  const info = await res.json();
  if (!env.GOOGLE_CLIENT_ID) return { error: 401, reason: "env_client_id_missing" };
  if (info.aud !== env.GOOGLE_CLIENT_ID) return { error: 401, reason: "aud_mismatch" };
  if (String(info.email_verified) !== "true") return { error: 401, reason: "email_not_verified" };

  const email = String(info.email || "").toLowerCase();
  const role = ACCOUNTS[email];
  if (!role) return { error: 403, reason: "not_allowed" };

  return { email, role };
}

async function authenticate(request, env) {
  const token = bearer(request);
  if (!token) return { error: 401 };

  const email = await verifySession(token, env);
  if (!email) return { error: 401 };

  const role = ACCOUNTS[email];
  if (!role) return { error: 403 };

  return { email, role };
}

async function summary(env) {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM savings").first();
  const count = row.n;
  const total = count * AMOUNT;
  return { count, total, remaining: Math.max(0, GOAL - total), goal: GOAL, amount: AMOUNT };
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (!path.startsWith("/api/")) {
      return reply(env, { error: "not_found" }, 404);
    }

    if (!env.SESSION_SECRET) {
      return reply(env, { error: "missing_session_secret" }, 500);
    }

    if (path === "/api/login" && request.method === "POST") {
      const result = await verifyGoogle(request, env);
      if (result.error) {
        return reply(env, { error: result.error === 403 ? "forbidden" : "unauthorized", reason: result.reason }, result.error);
      }
      const session = await issueSession(result.email, env);
      return reply(env, { token: session, email: result.email, role: result.role });
    }

    const auth = await authenticate(request, env);
    if (auth.error) {
      return reply(env, { error: auth.error === 403 ? "forbidden" : "unauthorized" }, auth.error);
    }

    if (path === "/api/status" && request.method === "GET") {
      const data = await summary(env);
      const today = todayJst();
      const done = await env.DB.prepare("SELECT 1 FROM savings WHERE day = ?").bind(today).first();
      const body = { ...data, email: auth.email, role: auth.role, savedToday: Boolean(done) };

      const saved = await env.DB
        .prepare("SELECT id, day, saved_at, saved_by FROM savings ORDER BY saved_at DESC")
        .all();
      body.records = saved.results.map((r) => ({
        id: r.id,
        day: r.day,
        saved_at: r.saved_at,
        by: ACCOUNTS[String(r.saved_by).toLowerCase()] || "user"
      }));

      if (auth.role === "admin") {
        const pending = await env.DB
          .prepare("SELECT id, day, target_at, requested_by FROM requests WHERE status = 'pending' ORDER BY target_at ASC")
          .all();
        body.pending = pending.results;
      } else {
        const mine = await env.DB
          .prepare("SELECT id, day, target_at, status FROM requests ORDER BY id DESC LIMIT 10")
          .all();
        body.requests = mine.results;
      }
      return reply(env, body);
    }

    if (path === "/api/save" && request.method === "POST") {
      if (auth.role !== "user") return reply(env, { error: "forbidden" }, 403);

      const data = await summary(env);
      if (data.count >= MAX_COUNT) return reply(env, { error: "goal_reached" }, 400);

      const today = todayJst();
      try {
        await env.DB
          .prepare("INSERT INTO savings (day, saved_at, saved_by) VALUES (?, ?, ?)")
          .bind(today, new Date().toISOString(), auth.email)
          .run();
      } catch (e) {
        return reply(env, { error: "already_saved" }, 409);
      }

      const next = await summary(env);
      return reply(env, { ...next, role: auth.role, savedToday: true });
    }

    if (path === "/api/records" && request.method === "POST") {
      if (auth.role !== "admin") return reply(env, { error: "forbidden" }, 403);

      let input = {};
      try { input = await request.json(); } catch (e) {}
      const value = String(input.savedAt || "");
      const parsed = parseJst(value);
      if (!parsed) return reply(env, { error: "invalid_datetime" }, 400);
      if (parsed.date.getTime() > Date.now()) return reply(env, { error: "future" }, 400);
      const when = parsed.date;

      const data = await summary(env);
      if (data.count >= MAX_COUNT) return reply(env, { error: "goal_reached" }, 400);

      try {
        await env.DB
          .prepare("INSERT INTO savings (day, saved_at, saved_by) VALUES (?, ?, ?)")
          .bind(value.slice(0, 10), when.toISOString(), auth.email)
          .run();
      } catch (e) {
        return reply(env, { error: "already_saved" }, 409);
      }
      return reply(env, { ok: true });
    }

    if (path === "/api/requests" && request.method === "POST") {
      if (auth.role !== "user") return reply(env, { error: "forbidden" }, 403);

      let input = {};
      try { input = await request.json(); } catch (e) {}
      const parsed = parseJst(String(input.savedAt || ""));
      if (!parsed) return reply(env, { error: "invalid_datetime" }, 400);
      if (parsed.date.getTime() > Date.now()) return reply(env, { error: "future" }, 400);
      if (parsed.day === todayJst()) return reply(env, { error: "today" }, 400);

      const data = await summary(env);
      if (data.count >= MAX_COUNT) return reply(env, { error: "goal_reached" }, 400);

      const saved = await env.DB.prepare("SELECT 1 FROM savings WHERE day = ?").bind(parsed.day).first();
      if (saved) return reply(env, { error: "already_saved" }, 409);

      const waiting = await env.DB
        .prepare("SELECT 1 FROM requests WHERE day = ? AND status = 'pending'")
        .bind(parsed.day)
        .first();
      if (waiting) return reply(env, { error: "already_requested" }, 409);

      await env.DB
        .prepare("INSERT INTO requests (day, target_at, requested_by, requested_at, status) VALUES (?, ?, ?, ?, 'pending')")
        .bind(parsed.day, parsed.date.toISOString(), auth.email, new Date().toISOString())
        .run();
      return reply(env, { ok: true });
    }

    const decision = path.match(/^\/api\/requests\/(\d+)\/(approve|reject)$/);
    if (decision && request.method === "POST") {
      if (auth.role !== "admin") return reply(env, { error: "forbidden" }, 403);

      const id = Number(decision[1]);
      const row = await env.DB
        .prepare("SELECT id, day, target_at, requested_by FROM requests WHERE id = ? AND status = 'pending'")
        .bind(id)
        .first();
      if (!row) return reply(env, { error: "not_found" }, 404);

      const now = new Date().toISOString();

      if (decision[2] === "reject") {
        await env.DB
          .prepare("UPDATE requests SET status = 'rejected', decided_at = ? WHERE id = ?")
          .bind(now, id)
          .run();
        return reply(env, { ok: true });
      }

      const data = await summary(env);
      if (data.count >= MAX_COUNT) return reply(env, { error: "goal_reached" }, 400);

      try {
        await env.DB.batch([
          env.DB
            .prepare("INSERT INTO savings (day, saved_at, saved_by) VALUES (?, ?, ?)")
            .bind(row.day, row.target_at, row.requested_by),
          env.DB
            .prepare("UPDATE requests SET status = 'approved', decided_at = ? WHERE id = ?")
            .bind(now, id)
        ]);
      } catch (e) {
        return reply(env, { error: "already_saved" }, 409);
      }
      return reply(env, { ok: true });
    }

    const match = path.match(/^\/api\/records\/(\d+)$/);
    if (match && request.method === "DELETE") {
      if (auth.role !== "admin") return reply(env, { error: "forbidden" }, 403);
      await env.DB.prepare("DELETE FROM savings WHERE id = ?").bind(Number(match[1])).run();
      return reply(env, { ok: true });
    }

    return reply(env, { error: "not_found" }, 404);
  }
};
