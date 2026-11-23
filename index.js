const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Owner-Secret",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...cors },
  });
}

function b64url(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

async function derivePassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 180000, hash: "SHA-256" }, key, 256
  );
  return b64url(bits);
}

async function signJwt(payload, secret) {
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return `${data}.${b64url(sig)}`;
}

async function verifyJwt(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
  );
  const valid = await crypto.subtle.verify(
    "HMAC", key, fromB64url(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  );
  if (!valid) return null;
  const payload = JSON.parse(new TextDecoder().decode(fromB64url(parts[1])));
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

async function auth(request, env) {
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  return verifyJwt(token, env.JWT_SECRET);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    const url = new URL(request.url);

    try {
      if (request.method === "GET" && url.pathname === "/") {
        return json({ game: "LEGACY 22 API", status: "online", version: "starter-1" });
      }

      if (request.method === "POST" && url.pathname === "/api/register") {
        const { username, password } = await request.json();
        if (typeof username !== "string" || !/^[a-zA-Z0-9_]{3,18}$/.test(username) ||
            typeof password !== "string" || password.length < 8 || password.length > 128) {
          return json({ error: "Username must be 3-18 letters/numbers/_ and password at least 8 characters." }, 400);
        }
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const hash = await derivePassword(password, salt);
        const stored = `${b64url(salt)}.${hash}`;
        const result = await env.DB.prepare(
          "INSERT INTO players (username, password_hash) VALUES (?, ?)"
        ).bind(username, stored).run().catch(() => null);
        if (!result) return json({ error: "Username already exists or database error." }, 409);
        const id = result.meta.last_row_id;
        await env.DB.prepare("INSERT INTO wallets (player_id) VALUES (?)").bind(id).run();
        return json({ ok: true, player: { id, username } }, 201);
      }

      if (request.method === "POST" && url.pathname === "/api/login") {
        const { username, password } = await request.json();
        const player = await env.DB.prepare(
          "SELECT id, username, password_hash FROM players WHERE username = ?"
        ).bind(username).first();
        if (!player || typeof password !== "string") return json({ error: "Invalid login." }, 401);
        const [saltText, expected] = player.password_hash.split(".");
        const actual = await derivePassword(password, fromB64url(saltText));
        if (actual !== expected) return json({ error: "Invalid login." }, 401);
        const token = await signJwt({
          sub: player.id, username: player.username,
          exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7
        }, env.JWT_SECRET);
        return json({ token, player: { id: player.id, username: player.username } });
      }

      if (request.method === "GET" && url.pathname === "/api/profile") {
        const session = await auth(request, env);
        if (!session) return json({ error: "Unauthorized." }, 401);
        const row = await env.DB.prepare(
          "SELECT p.id, p.username, w.diamonds, w.gold FROM players p JOIN wallets w ON w.player_id=p.id WHERE p.id=?"
        ).bind(session.sub).first();
        return row ? json({ player: row }) : json({ error: "Player not found." }, 404);
      }

      if (request.method === "POST" && url.pathname === "/api/owner/grant") {
        if (!env.OWNER_SECRET || request.headers.get("X-Owner-Secret") !== env.OWNER_SECRET) {
          return json({ error: "Owner access denied." }, 403);
        }
        const { playerId, diamonds = 0, gold = 0 } = await request.json();
        if (!Number.isInteger(playerId) || !Number.isInteger(diamonds) ||
            !Number.isInteger(gold) || diamonds < 0 || gold < 0 ||
            diamonds + gold === 0 || diamonds > 1000000 || gold > 10000000) {
          return json({ error: "Invalid grant values." }, 400);
        }
        const result = await env.DB.prepare(
          "UPDATE wallets SET diamonds=diamonds+?, gold=gold+? WHERE player_id=?"
        ).bind(diamonds, gold, playerId).run();
        if (!result.meta.changes) return json({ error: "Player not found." }, 404);
        await env.DB.prepare(
          "INSERT INTO audit_logs (actor, action, target_player_id, details) VALUES ('owner','grant_currency',?,?)"
        ).bind(playerId, JSON.stringify({ diamonds, gold })).run();
        return json({ ok: true, playerId, diamondsAdded: diamonds, goldAdded: gold });
      }

      return json({ error: "Not found." }, 404);
    } catch (e) {
      return json({ error: "Server error." }, 500);
    }
  }
};
