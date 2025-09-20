export default {
  async fetch(req, env) {
    // ---------- CORS ----------
    const cors = {
      "Access-Control-Allow-Origin": "https://www.imarika.net",
      "Access-Control-Allow-Headers": "authorization, content-type",
      "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS"
    };
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });

    // ---------- small helpers ----------
    const json = (d, s = 200) =>
      new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json", ...cors } });

    const url = new URL(req.url);
    const q = (sql, ...args) => env.DB.prepare(sql).bind(...args);

    const sha256 = async (s) => {
      const data = new TextEncoder().encode(s);
      const hash = await crypto.subtle.digest("SHA-256", data);
      return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
    };

    async function ensureSchema() {
      // Main table with the column names the frontend expects
      await env.DB.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          phone      TEXT UNIQUE NOT NULL,
          full_name  TEXT,
          id_number  TEXT,
          account    TEXT UNIQUE,
          wallet     INTEGER DEFAULT 0,
          invested   INTEGER DEFAULT 0,
          pass_hash  TEXT,
          created_at INTEGER DEFAULT (strftime('%s','now'))
        );
      `);
      // Make it safe on old DBs: add missing columns if table was created with older names
      const alters = [
        `ALTER TABLE users ADD COLUMN full_name  TEXT`,
        `ALTER TABLE users ADD COLUMN id_number TEXT`,
        `ALTER TABLE users ADD COLUMN account   TEXT`,
        `ALTER TABLE users ADD COLUMN wallet    INTEGER DEFAULT 0`,
        `ALTER TABLE users ADD COLUMN invested  INTEGER DEFAULT 0`,
        `ALTER TABLE users ADD COLUMN pass_hash TEXT`,
        `ALTER TABLE users ADD COLUMN created_at INTEGER DEFAULT (strftime('%s','now'))`,
      ];
      for (const sql of alters) { try { await env.DB.exec(sql); } catch (_) {} }

      // Transactions table used by your tx endpoints below
      await env.DB.exec(`
        CREATE TABLE IF NOT EXISTS transactions (
          id     TEXT PRIMARY KEY,
          phone  TEXT,
          type   TEXT,
          amount INTEGER,
          detail TEXT,
          status TEXT,
          ts     INTEGER
        );
      `);
    }

    // Health
    if (url.pathname === "/api/health") return json({ ok: true });

    // ---------- USER: REGISTER ----------
    // Body: { full_name, id_number, phone, pin }
    if (url.pathname === "/api/register" && req.method === "POST") {
      await ensureSchema();
      const { full_name, id_number, phone, pin } = await req.json();

      if (!/^0(7|1)\d{8}$/.test(String(phone || "").trim()))
        return json({ ok: false, error: "Invalid phone" }, 400);
      if (!/^\d{4}$/.test(String(pin || "")))
        return json({ ok: false, error: "PIN must be 4 digits" }, 400);

      const exists = await q(`SELECT id FROM users WHERE phone=?`, phone).first();
      if (exists) return json({ ok: false, error: "Phone already registered" }, 409);

      const acct = `IMK-${crypto.randomUUID().slice(0, 4).toUpperCase()}-${Math.floor(Math.random() * 9000 + 1000)}`;
      const pass_hash = await sha256(`${pin}:${env.PASS_SALT || "imarika-salt"}`);

      await q(
        `INSERT INTO users (phone, full_name, id_number, account, wallet, invested, pass_hash)
         VALUES (?, ?, ?, ?, 0, 0, ?)`,
        phone, full_name || null, id_number || null, acct, pass_hash
      ).run();

      const u = await q(
        `SELECT phone, full_name, id_number, account, wallet, invested, created_at
         FROM users WHERE phone=?`,
        phone
      ).first();

      return json({ ok: true, user: u });
    }

    // ---------- USER: LOGIN ----------
    // Body: { phone, pin }
    if (url.pathname === "/api/login" && req.method === "POST") {
      await ensureSchema();
      const { phone, pin } = await req.json();
      if (!/^0(7|1)\d{8}$/.test(String(phone || "").trim()))
        return json({ ok: false, error: "Invalid phone" }, 400);
      if (!/^\d{4}$/.test(String(pin || "")))
        return json({ ok: false, error: "PIN must be 4 digits" }, 400);

      const pass_hash = await sha256(`${pin}:${env.PASS_SALT || "imarika-salt"}`);
      const u = await q(
        `SELECT phone, full_name, id_number, account, wallet, invested, created_at
         FROM users WHERE phone=? AND pass_hash=?`,
        phone, pass_hash
      ).first();

      if (!u) return json({ ok: false, error: "Invalid credentials" }, 401);
      return json({ ok: true, user: u });
    }

    // ---------- tiny JWT for admin ----------
    const enc = (o) => btoa(unescape(encodeURIComponent(JSON.stringify(o)))).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
    const dec = (s) => JSON.parse(decodeURIComponent(escape(atob(s.replace(/-/g,'+').replace(/_/g,'/')))));
    const sign = async (msg, secret) => {
      const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), "HMAC", false, ["sign"]);
      const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
      return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
    };
    const makeJWT = async (payload, secret, exp=86400) => {
      const header = { alg: "HS256", typ: "JWT" };
      const now = Math.floor(Date.now()/1000);
      const body = { ...payload, iat: now, exp: now + exp };
      const h = enc(header), p = enc(body);
      const s = await sign(`${h}.${p}`, secret);
      return `${h}.${p}.${s}`;
    };
    const bearer = (req.headers.get("authorization")||"").split(" ")[1]||"";
    const isAdmin = async () => {
      try { const [,p] = bearer.split("."); return !!p && dec(p).sub === "admin"; } catch { return false; }
    };

    // ---------- ADMIN: LOGIN (alias both /api/admin/login and /api/auth/login) ----------
    if ((url.pathname === "/api/admin/login" || url.pathname === "/api/auth/login") && req.method === "POST") {
      const body = await req.json().catch(()=>({}));
      // Accept either {phone, pass} or {password}
      const ok =
        (body.phone && body.pass && body.phone === (env.ADMIN_PHONE || "") && body.pass === (env.ADMIN_PASS || "")) ||
        (body.password && body.password === (env.ADMIN_PASS || ""));
      if (!ok) return json({ ok:false, error: "Invalid credentials" }, 401);
      const token = await makeJWT({ sub: "admin" }, env.ADMIN_JWT_SECRET || "imarika-admin-secret");
      return json({ ok:true, token });
    }

    // ---------- EXISTING ENDPOINTS (kept) ----------
    if (url.pathname === "/api/users" && req.method === "GET") {
      await ensureSchema();
      const term = (url.searchParams.get("q")||"").trim();
      const res = await q(
        `SELECT id, full_name as full, phone, id_number as idn, account, wallet, invested, created_at
         FROM users
         WHERE (? = '' OR full_name LIKE ? OR phone LIKE ? OR account LIKE ?)
         ORDER BY created_at DESC
         LIMIT 200`,
        term, `%${term}%`, `%${term}%`, `%${term}%`
      ).all();
      return json(res.results||[]);
    }

    if (url.pathname === "/api/users" && req.method === "POST") {
      await ensureSchema();
      const { full="", phone, idn="" } = await req.json();
      if (!phone) return json({ error: "phone required" }, 400);
      const acct = `IMK-${Math.random().toString(36).slice(2,6).toUpperCase()}-${Math.floor(Math.random()*9000+1000)}`;
      await q(
        `INSERT INTO users (full_name, phone, id_number, account, wallet, invested)
         VALUES (?, ?, ?, ?, 0, 0)`,
        full, phone, idn, acct
      ).run();
      const user = await q(
        `SELECT phone, full_name, id_number, account, wallet, invested, created_at
         FROM users WHERE phone = ?`,
        phone
      ).first();
      return json(user, 201);
    }

    // --- transactions (create/list/approve/reject) ---
    if (url.pathname === "/api/tx" && req.method === "POST") {
      await ensureSchema();
      const { phone, type, amount, detail="" } = await req.json();
      if (!phone || !type || !Number.isFinite(amount)) return json({ error: "phone/type/amount required" }, 400);
      const id = crypto.randomUUID();
      await q(
        `INSERT INTO transactions (id, phone, type, amount, detail, status, ts)
         VALUES (?, ?, ?, ?, ?, 'Pending', ?)`,
        id, phone, type, amount, detail, Date.now()
      ).run();
      return json({ id, status: "Pending" }, 201);
    }

    if (url.pathname === "/api/tx" && req.method === "GET") {
      await ensureSchema();
      const status = url.searchParams.get("status");
      const res = await q(
        `SELECT * FROM transactions ${status ? "WHERE status = ?" : ""} ORDER BY ts DESC LIMIT 500`,
        ...(status ? [status] : [])
      ).all();
      return json(res.results||[]);
    }

    const m = url.pathname.match(/^\/api\/tx\/([^/]+)\/(approve|reject)$/);
    if (m && req.method === "PATCH") {
      await ensureSchema();
      if (!(await isAdmin())) return json({ error: "unauthorized" }, 403);
      const [_, id, action] = m;
      const t = await q(`SELECT * FROM transactions WHERE id = ?`, id).first();
      if (!t) return json({ error: "not found" }, 404);
      const newStatus = action === "approve" ? "Approved" : "Rejected";
      await q(`UPDATE transactions SET status = ? WHERE id = ?`, newStatus, id).run();

      if (t.type === "Deposit" && newStatus === "Approved") {
        await q(`UPDATE users SET wallet = wallet + ? WHERE phone = ?`, Math.abs(t.amount), t.phone).run();
      } else if (t.type === "Withdrawal" && newStatus === "Rejected") {
        await q(`UPDATE users SET wallet = wallet + ? WHERE phone = ?`, Math.abs(t.amount), t.phone).run();
      }
      return json({ id, status: newStatus });
    }

    return new Response("Not Found", { status: 404, headers: cors });
  }
};
