export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);

    // ---------- serve API here ----------
    if (url.pathname.startsWith("/api/")) {
      return handleApi(req, env);
    }

    // ---------- otherwise serve static site ----------
    // (ASSETS is provided by Pages automatically)
    return env.ASSETS.fetch(req);
  }
};

// =============== API ===============
async function handleApi(req, env) {
  const url = new URL(req.url);

  // --- CORS (simple) ---
  const ORIGINS = new Set([
    "https://imarika.net",
    "https://www.imarika.net",
    "https://imarika.pages.dev"
  ]);
  const origin = req.headers.get("origin") || "";
  const allowOrigin = ORIGINS.has(origin) ? origin : "https://imarika.net";
  const CORS = {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Headers": "authorization, content-type",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS"
  };
  if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

  const json = (d, { status = 200, headers = {} } = {}) =>
    new Response(JSON.stringify(d), {
      status,
      headers: { "content-type": "application/json", ...CORS, ...headers }
    });

  const q = (sql, ...args) => env.DB.prepare(sql).bind(...args);
  const nowSec = () => Math.floor(Date.now() / 1000);
  const acctNum = () =>
    `IMK-${crypto.randomUUID().slice(0, 4).toUpperCase()}-${Math.floor(Math.random() * 9000 + 1000)}`;
  const sha256Hex = async (s) => {
    const data = new TextEncoder().encode(s);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
  };

  // ---------- schema (safe/idempotent) ----------
  async function ensureSchema() {
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
    // tolerate older DBs missing columns
    for (const sql of [
      `ALTER TABLE users ADD COLUMN full_name  TEXT`,
      `ALTER TABLE users ADD COLUMN id_number  TEXT`,
      `ALTER TABLE users ADD COLUMN account    TEXT`,
      `ALTER TABLE users ADD COLUMN wallet     INTEGER DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN invested   INTEGER DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN pass_hash  TEXT`,
      `ALTER TABLE users ADD COLUMN created_at INTEGER DEFAULT (strftime('%s','now'))`,
    ]) { try { await env.DB.exec(sql); } catch {} }

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
    await env.DB.exec(`CREATE INDEX IF NOT EXISTS idx_tx_phone_ts ON transactions(phone, ts DESC);`);

    await env.DB.exec(`
      CREATE TABLE IF NOT EXISTS admins (
        phone TEXT PRIMARY KEY,
        pass_hash TEXT NOT NULL,
        created_at INTEGER DEFAULT (strftime('%s','now'))
      );
    `);
  }

  // ---------- JWT (HS256) ----------
  const b64url = (b) => b.replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const enc = (obj) => b64url(btoa(unescape(encodeURIComponent(JSON.stringify(obj)))));
  const signH = async (msg, secret) => {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
      { name:"HMAC", hash:"SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
    return b64url(btoa(String.fromCharCode(...new Uint8Array(sig))));
  };
  const issueAdminToken = async () => {
    const h = enc({ alg:"HS256", typ:"JWT" });
    const p = enc({ sub:"admin", iat:nowSec(), exp:nowSec()+86400 });
    const s = await signH(`${h}.${p}`, env.ADMIN_JWT_SECRET || "imarika-admin-secret");
    return `${h}.${p}.${s}`;
  };
  const verifyAdmin = async (req) => {
    const tok = (req.headers.get("authorization") || "").split(" ")[1] || "";
    const parts = tok.split(".");
    if (parts.length !== 3) return false;
    const [h, p, s] = parts;
    const sig = await signH(`${h}.${p}`, env.ADMIN_JWT_SECRET || "imarika-admin-secret");
    if (sig !== s) return false;
    try {
      const payload = JSON.parse(decodeURIComponent(escape(atob(p.replace(/-/g, "+").replace(/_/g, "/")))));
      return payload.sub === "admin" && payload.exp > nowSec();
    } catch { return false; }
  };

  // ---------- routes ----------
  if (url.pathname === "/api/health") {
    return json({ ok:true, time: Date.now() });
  }

  if (url.pathname === "/api/admin/init") {
    const given = url.searchParams.get("secret") || "";
    const expected = env.ADMIN_INIT_SECRET || "Oury2933#";
    if (given !== expected) return json({ ok:false, error:"Forbidden" }, { status:403 });

    await ensureSchema();

    // seed/update admin
    const adminPhone = env.ADMIN_PHONE || "0715151010";
    const adminPass  = env.ADMIN_PASS  || "Oury2933#";
    const salt       = env.PASS_SALT   || "imarika-salt";
    const passHash   = await sha256Hex(`${adminPass}:${salt}`);

    await q(`
      INSERT INTO admins (phone, pass_hash, created_at)
      VALUES (?, ?, ?)
      ON CONFLICT(phone) DO UPDATE SET pass_hash=excluded.pass_hash
    `, adminPhone, passHash, nowSec()).run();

    const cols = await env.DB.prepare(`PRAGMA table_info(users)`).all();
    return json({ ok:true, adminPhone, usersColumns: (cols.results||[]).map(c=>c.name) });
  }

  // public: register & login
  if (url.pathname === "/api/register" && req.method === "POST") {
    await ensureSchema();
    const { full_name, id_number, phone, pin } = await req.json().catch(()=>({}));
    if (!/^0(7|1)\d{8}$/.test(String(phone||"").trim()))
      return json({ ok:false, error:"Invalid phone" }, { status:400 });
    if (!/^\d{4}$/.test(String(pin||"")))
      return json({ ok:false, error:"PIN must be 4 digits" }, { status:400 });

    const exists = await q(`SELECT id FROM users WHERE phone=?`, phone).first();
    if (exists) return json({ ok:false, error:"Phone already registered" }, { status:409 });

    const pass_hash = await sha256Hex(`${pin}:${env.PASS_SALT || "imarika-salt"}`);
    await q(`
      INSERT INTO users (phone, full_name, id_number, account, wallet, invested, pass_hash, created_at)
      VALUES (?, ?, ?, ?, 0, 0, ?, ?)
    `, phone, full_name||null, id_number||null, acctNum(), pass_hash, nowSec()).run();

    const u = await q(`
      SELECT phone, full_name, id_number, account, wallet, invested, created_at
      FROM users WHERE phone=?
    `, phone).first();
    return json({ ok:true, user:u });
  }

  if (url.pathname === "/api/login" && req.method === "POST") {
    await ensureSchema();
    const { phone, pin } = await req.json().catch(()=>({}));
    if (!/^0(7|1)\d{8}$/.test(String(phone||"").trim()))
      return json({ ok:false, error:"Invalid phone" }, { status:400 });
    if (!/^\d{4}$/.test(String(pin||"")))
      return json({ ok:false, error:"PIN must be 4 digits" }, { status:400 });

    const pass_hash = await sha256Hex(`${pin}:${env.PASS_SALT || "imarika-salt"}`);
    const u = await q(`
      SELECT phone, full_name, id_number, account, wallet, invested, created_at
      FROM users WHERE phone=? AND pass_hash=?
    `, phone, pass_hash).first();
    if (!u) return json({ ok:false, error:"Invalid credentials" }, { status:401 });
    return json({ ok:true, user:u });
  }

  // public: create pending tx
  if (url.pathname === "/api/tx" && req.method === "POST") {
    await ensureSchema();
    const { phone, type, amount, detail = "" } = await req.json().catch(()=>({}));
    if (!phone || !type || !Number.isFinite(Number(amount)))
      return json({ ok:false, error:"phone/type/amount required" }, { status:400 });
    const id = crypto.randomUUID();
    await q(`
      INSERT INTO transactions (id, phone, type, amount, detail, status, ts)
      VALUES (?, ?, ?, ?, ?, 'Pending', ?)
    `, id, phone, String(type), Number(amount), detail, Date.now()).run();
    return json({ ok:true, id, status:'Pending' }, { status:201 });
  }

  // admin login
  if (url.pathname === "/api/admin/login" && req.method === "POST") {
    await ensureSchema();
    const { phone = "", pass = "" } = await req.json().catch(()=>({}));
    const salt = env.PASS_SALT || "imarika-salt";
    const hash = await sha256Hex(`${pass}:${salt}`);

    const row = await q(`SELECT phone FROM admins WHERE phone=? AND pass_hash=?`, phone, hash).first();
    const envOK = (env.ADMIN_PHONE && env.ADMIN_PASS &&
                   phone === env.ADMIN_PHONE && pass === env.ADMIN_PASS);
    if (!row && !envOK) return json({ ok:false, error:"Invalid credentials" }, { status:401 });

    const token = await issueAdminToken();
    return json({ ok:true, token });
  }

  // admin auth helper
  const needAdmin = async () => (await verifyAdmin(req)) ? true : false;

  if (url.pathname === "/api/admin/users" && req.method === "GET") {
    if (!(await needAdmin())) return json({ ok:false, error:"Unauthorized" }, { status:401 });
    await ensureSchema();
    const search = (url.searchParams.get("search") || "").trim();
    const res = await q(`
      SELECT full_name, phone, id_number, account, wallet, invested, created_at
      FROM users
      WHERE (?='' OR full_name LIKE ? OR phone LIKE ? OR account LIKE ?)
      ORDER BY created_at DESC LIMIT 500
    `, search, `%${search}%`, `%${search}%`, `%${search}%`).all();
    return json({ ok:true, users: res.results || [] });
  }

  if (url.pathname === "/api/admin/user" && req.method === "GET") {
    if (!(await needAdmin())) return json({ ok:false, error:"Unauthorized" }, { status:401 });
    await ensureSchema();
    const phone = url.searchParams.get("phone") || "";
    const account = url.searchParams.get("account") || "";
    if (!phone && !account) return json({ ok:false, error:"phone or account required" }, { status:400 });
    const where = phone ? "phone=?" : "account=?";
    const val = phone || account;
    const u = await q(`
      SELECT full_name, phone, id_number, account, wallet, invested, created_at
      FROM users WHERE ${where}
    `, val).first();
    if (!u) return json({ ok:false, error:"Not found" }, { status:404 });
    return json({ ok:true, user:u });
  }

  if (url.pathname === "/api/admin/user/upsert" && req.method === "POST") {
    if (!(await needAdmin())) return json({ ok:false, error:"Unauthorized" }, { status:401 });
    await ensureSchema();
    const { phone, full_name=null, id_number=null, wallet=null, invested=null, account=null } =
      await req.json().catch(()=>({}));
    if (!phone) return json({ ok:false, error:"phone is required" }, { status:400 });

    const exists = await q(`SELECT id FROM users WHERE phone=?`, phone).first();
    if (exists) {
      await q(`
        UPDATE users SET
          full_name = COALESCE(?, full_name),
          id_number = COALESCE(?, id_number),
          wallet    = COALESCE(?, wallet),
          invested  = COALESCE(?, invested),
          account   = COALESCE(?, account)
        WHERE phone=?
      `, full_name, id_number, wallet, invested, account, phone).run();
    } else {
      const acct = (account && String(account).trim()) || acctNum();
      await q(`
        INSERT INTO users (phone, full_name, id_number, account, wallet, invested, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `, phone, full_name, id_number, acct, wallet ?? 0, invested ?? 0, nowSec()).run();
    }
    const u = await q(`SELECT full_name, phone, id_number, account, wallet, invested, created_at FROM users WHERE phone=?`, phone).first();
    return json({ ok:true, user:u });
  }

  if (url.pathname === "/api/admin/pending" && req.method === "GET") {
    if (!(await needAdmin())) return json({ ok:false, error:"Unauthorized" }, { status:401 });
    await ensureSchema();
    const res = await q(`
      SELECT id, phone, type, amount, detail, status, ts
      FROM transactions
      WHERE status='Pending'
      ORDER BY ts DESC LIMIT 500
    `).all();
    return json({ ok:true, pending: res.results || [] });
  }

  if (url.pathname === "/api/admin/tx/update" && req.method === "POST") {
    if (!(await needAdmin())) return json({ ok:false, error:"Unauthorized" }, { status:401 });
    await ensureSchema();
    const { id, action } = await req.json().catch(()=>({}));
    if (!id || !action) return json({ ok:false, error:"id and action required" }, { status:400 });

    const t = await q(`SELECT * FROM transactions WHERE id=?`, id).first();
    if (!t) return json({ ok:false, error:"Not found" }, { status:404 });

    const newStatus = action === "approve" ? "Approved" : "Rejected";
    await q(`UPDATE transactions SET status=? WHERE id=?`, newStatus, id).run();

    if (t.phone) {
      if (t.type === "Deposit" && newStatus === "Approved") {
        await q(`UPDATE users SET wallet = wallet + ? WHERE phone=?`, Math.abs(t.amount || 0), t.phone).run();
      }
      if (t.type === "Withdrawal" && newStatus === "Rejected") {
        await q(`UPDATE users SET wallet = wallet + ? WHERE phone=?`, Math.abs(t.amount || 0), t.phone).run();
      }
    }
    return json({ ok:true, id, status:newStatus });
  }

  return new Response("Not Found", { status:404, headers: CORS });
}
