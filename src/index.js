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

function todayJst() {
  return new Date(Date.now() + 9 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

async function authenticate(request, env) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return { error: 401 };

  const res = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(token));
  if (!res.ok) return { error: 401 };

  const info = await res.json();
  if (info.aud !== env.GOOGLE_CLIENT_ID) return { error: 401 };
  if (String(info.email_verified) !== "true") return { error: 401 };

  const email = String(info.email || "").toLowerCase();
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

    const auth = await authenticate(request, env);
    if (auth.error) {
      return reply(env, { error: auth.error === 403 ? "forbidden" : "unauthorized" }, auth.error);
    }

    if (path === "/api/status" && request.method === "GET") {
      const data = await summary(env);
      const today = todayJst();
      const done = await env.DB.prepare("SELECT 1 FROM savings WHERE day = ?").bind(today).first();
      const body = { ...data, email: auth.email, role: auth.role, savedToday: Boolean(done) };

      if (auth.role === "admin") {
        const { results } = await env.DB
          .prepare("SELECT id, day, saved_at, saved_by FROM savings ORDER BY saved_at DESC")
          .all();
        body.records = results;
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

    const match = path.match(/^\/api\/records\/(\d+)$/);
    if (match && request.method === "DELETE") {
      if (auth.role !== "admin") return reply(env, { error: "forbidden" }, 403);
      await env.DB.prepare("DELETE FROM savings WHERE id = ?").bind(Number(match[1])).run();
      return reply(env, { ok: true });
    }

    return reply(env, { error: "not_found" }, 404);
  }
};
