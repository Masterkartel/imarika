// src/worker.js
// tiny REST API for Imarika (Workers + D1)

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "authorization, content-type",
      "access-control-allow-methods": "GET,POST,PUT,OPTIONS",
      ...extra,
    },
  });

const readBody = async (req) => (req.headers.get("content-type")||"").includes("application/json")
  ? await req.json() : {};

const path = (url) => new URL(url).pathname.replace(/\/+$/,"");

async function signJWT(payload, secret, ttlSec = 86400) {
  const header = { alg: "HS256", typ: "JWT" };
  const exp = Math.floor(Date.now()/1000) + ttlSec;
  const enc = (obj) => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(obj)))).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
  const body = { ...payload, exp };
  const data = `${enc(header)}.${enc(body)}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name:"HMAC", hash:"SHA-256" }, false, ["sign"]);
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf))).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
  return `${data}.${sig}`;
}
async function verifyJWT(token, secret) {
  try{
    const [h,p,s] = token.split(".");
    const data = `${h}.${p}`;
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name:"HMAC", hash:"SHA-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify("HMAC", key, Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0)), new TextEncoder().encode(data));
    if(!ok) return null;
    const payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(p.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0))));
    if(payload.exp && payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  }catch{ return null; }
}

async function requireAdmin(req, env) {
  const auth = req.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if(!token) return null;
  return await verifyJWT(token, env.ADMIN_JWT_SECRET);
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return json({});
    const url = new URL(req.url);
    const p = path(url.href);

    // --- AUTH (admin) ---
    if (p === "/api/auth/login" && req.method === "POST") {
      const { password } = await readBody(req);
      if (!password || password !== env.ADMIN_PASS) return json({ error: "invalid" }, 401);
      const token = await signJWT({ role: "admin" }, env.ADMIN_JWT_SECRET, 24*3600);
      return json({ token });
    }

    // --- USERS ---
    if (p === "/api/users" && req.method === "GET") {
      const q = url.searchParams.get("search") || "";
      const rs = q
        ? await env.IMARIKA_DB.prepare(`SELECT phone,account,full,idn,wallet,invested,created_at FROM users
                                        WHERE lower(full) LIKE ? OR phone LIKE ? OR lower(account) LIKE ?
                                        ORDER BY full`).bind(`%${q.toLowerCase()}%`, `%${q}%`, `%${q.toLowerCase()}%`).all()
        : await env.IMARIKA_DB.prepare(`SELECT phone,account,full,idn,wallet,invested,created_at FROM users ORDER BY full`).all();
      return json(rs.results || []);
    }

    if (p.startsWith("/api/users/by-acct/") && req.method === "GET") {
      const acct = decodeURIComponent(p.split("/").pop());
      const rs = await env.IMARIKA_DB.prepare(`SELECT * FROM users WHERE account=?`).bind(acct).first();
      return rs ? json(rs) : json({ error: "not-found" }, 404);
    }

    if (p.startsWith("/api/users/") && req.method === "GET") {
      const phone = decodeURIComponent(p.split("/").pop());
      const rs = await env.IMARIKA_DB.prepare(`SELECT * FROM users WHERE phone=?`).bind(phone).first();
      return rs ? json(rs) : json({ error: "not-found" }, 404);
    }

    if (p === "/api/users" && req.method === "POST") {
      const { phone, full="", idn="", account, pass_hash="" } = await readBody(req);
      if (!phone || !account) return json({ error: "phone+account required" }, 400);
      const now = Date.now();
      try{
        await env.IMARIKA_DB.prepare(`INSERT INTO users (phone,account,full,idn,pass_hash,created_at) VALUES (?,?,?,?,?,?)`)
          .bind(phone, account, full, idn, pass_hash, now).run();
        const u = await env.IMARIKA_DB.prepare(`SELECT * FROM users WHERE phone=?`).bind(phone).first();
        return json(u, 201);
      }catch(e){ return json({ error: "create-failed", detail: String(e) }, 400); }
    }

    if (p.startsWith("/api/users/") && req.method === "PUT") {
      const admin = await requireAdmin(req, env);
      if (!admin) return json({ error: "unauthorized" }, 401);
      const phone = decodeURIComponent(p.split("/").pop());
      const { wallet, invested, full, idn } = await readBody(req);
      const u = await env.IMARIKA_DB.prepare(`SELECT * FROM users WHERE phone=?`).bind(phone).first();
      if(!u) return json({ error: "not-found" }, 404);
      await env.IMARIKA_DB.prepare(`UPDATE users SET wallet=?, invested=?, full=?, idn=? WHERE phone=?`)
        .bind( Number.isFinite(wallet)?wallet:u.wallet, Number.isFinite(invested)?invested:u.invested, full ?? u.full, idn ?? u.idn, phone).run();
      const nu = await env.IMARIKA_DB.prepare(`SELECT * FROM users WHERE phone=?`).bind(phone).first();
      return json(nu);
    }

    // --- TRANSACTIONS ---
    if (p === "/api/tx" && req.method === "GET") {
      const status = url.searchParams.get("status");
      const phone = url.searchParams.get("phone");
      let q = `SELECT * FROM tx`;
      const cond = [];
      const vals = [];
      if (status) { cond.push("status=?"); vals.push(status); }
      if (phone)  { cond.push("phone=?");  vals.push(phone); }
      if (cond.length) q += " WHERE " + cond.join(" AND ");
      q += " ORDER BY ts DESC LIMIT 500";
      const rs = await env.IMARIKA_DB.prepare(q).bind(...vals).all();
      return json(rs.results || []);
    }

    if (p === "/api/tx" && req.method === "POST") {
      const { type, phone, amount, detail="" } = await readBody(req);
      if (!type || !phone || !Number.isFinite(amount) || amount <= 0) return json({ error: "bad-body" }, 400);
      const id = `TX-${Date.now()}-${Math.random().toString(36).slice(2,8).toUpperCase()}`;
      const now = Date.now();

      const user = await env.IMARIKA_DB.prepare(`SELECT * FROM users WHERE phone=?`).bind(phone).first();
      if(!user) return json({ error: "user-not-found" }, 404);

      if (type === "Withdrawal") {
        // atomic: ensure sufficient balance and deduct
        const before = await env.IMARIKA_DB.prepare(`SELECT wallet FROM users WHERE phone=?`).bind(phone).first();
        if (!before || before.wallet < amount) return json({ error: "insufficient" }, 400);
        await env.IMARIKA_DB.prepare(`UPDATE users SET wallet=wallet-? WHERE phone=?`).bind(amount, phone).run();
        await env.IMARIKA_DB.prepare(`INSERT INTO tx (id,phone,type,amount,detail,status,ts) VALUES (?,?,?,?,?,?,?)`)
          .bind(id, phone, "Withdrawal", amount, detail, "Pending", now).run();
        const t = await env.IMARIKA_DB.prepare(`SELECT * FROM tx WHERE id=?`).bind(id).first();
        return json(t, 201);
      }

      if (type === "Deposit" || type === "Investment") {
        // no immediate wallet change; admin approval will credit for Deposit
        await env.IMARIKA_DB.prepare(`INSERT INTO tx (id,phone,type,amount,detail,status,ts) VALUES (?,?,?,?,?,?,?)`)
          .bind(id, phone, type, amount, detail, "Pending", now).run();
        const t = await env.IMARIKA_DB.prepare(`SELECT * FROM tx WHERE id=?`).bind(id).first();
        return json(t, 201);
      }

      return json({ error: "unsupported-type" }, 400);
    }

    if (p.startsWith("/api/tx/") && req.method === "PUT") {
      const admin = await requireAdmin(req, env);
      if (!admin) return json({ error: "unauthorized" }, 401);

      const id = decodeURIComponent(p.split("/").pop());
      const { status } = await readBody(req);
      if (!status || !["Approved","Rejected"].includes(status)) return json({ error: "bad-status" }, 400);

      const t = await env.IMARIKA_DB.prepare(`SELECT * FROM tx WHERE id=?`).bind(id).first();
      if(!t) return json({ error: "not-found" }, 404);

      // side-effects
      if (t.type === "Deposit" && status === "Approved") {
        await env.IMARIKA_DB.prepare(`UPDATE users SET wallet=wallet+? WHERE phone=?`).bind(t.amount, t.phone).run();
      }
      if (t.type === "Withdrawal" && status === "Rejected") {
        await env.IMARIKA_DB.prepare(`UPDATE users SET wallet=wallet+? WHERE phone=?`).bind(t.amount, t.phone).run();
      }

      await env.IMARIKA_DB.prepare(`UPDATE tx SET status=? WHERE id=?`).bind(status, id).run();
      const nt = await env.IMARIKA_DB.prepare(`SELECT * FROM tx WHERE id=?`).bind(id).first();
      return json(nt);
    }

    // (optional) webhook stub you can wire to M-Pesa later
    if (p === "/api/webhooks/mpesa" && req.method === "POST") {
      // parse payload, look up phone/amount, upsert tx + approve
      return json({ ok: true });
    }

    return json({ error: "not-found" }, 404);
  }
};
