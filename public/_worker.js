export default {
  async fetch(req, env, ctx) {
    try {
      const url = new URL(req.url);

      // Static files via Pages (if present)
      if (!url.pathname.startsWith("/api/")) {
        if (env.ASSETS) return env.ASSETS.fetch(req);
        return new Response("OK", { status: 200 });
      }

      // CORS
      const CORS = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "authorization, content-type",
        "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS"
      };
      if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

      const json = (data, status = 200) =>
        new Response(JSON.stringify(data), {
          status,
          headers: { "content-type": "application/json", ...CORS }
        });

      const nowSec = () => Math.floor(Date.now() / 1000);
      const acctNum = () =>
        `IMK-${crypto.randomUUID().slice(0, 4).toUpperCase()}-${Math.floor(Math.random() * 9000 + 1000)}`;
      const sha256Hex = async (s) => {
        const data = new TextEncoder().encode(s);
        const hash = await crypto.subtle.digest("SHA-256", data);
        return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
      };
      const db = env.DB;
      const q = (sql, ...args) => db.prepare(sql).bind(...args);

      async function ensureSchema() {
        await db.prepare(`
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            full_name TEXT,
            id_number TEXT,
            account TEXT UNIQUE,
            wallet INTEGER DEFAULT 0,
            invested INTEGER DEFAULT 0,
            pass_hash TEXT,
            created_at INTEGER DEFAULT (strftime('%s','now'))
          )
        `).run();

        await db.prepare(`
          CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            phone TEXT,
            type TEXT,
            amount INTEGER,
            detail TEXT,
            status TEXT,
            ts INTEGER
          )
        `).run();

        await db.prepare(`
          CREATE TABLE IF NOT EXISTS admins (
            phone TEXT PRIMARY KEY,
            pass_hash TEXT NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s','now'))
          )
        `).run();

        await db.prepare(`CREATE INDEX IF NOT EXISTS idx_tx_phone_ts ON transactions(phone, ts DESC)`).run();
      }

      // --- tiny jwt util (HS256) ---
      const b64url = (str) =>
        btoa(str).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
      const b64urlFromBytes = (bytes) =>
        btoa(String.fromCharCode(...new Uint8Array(bytes)))
          .replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");

      async function hmac(msg, secret) {
        const key = await crypto.subtle.importKey(
          "raw",
          new TextEncoder().encode(secret),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["sign"]
        );
        const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
        return b64urlFromBytes(sig);
      }

      async function issueAdminToken(env) {
        const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
        const payload = b64url(JSON.stringify({ sub: "admin", iat: nowSec(), exp: nowSec() + 86400 }));
        const sig = await hmac(`${header}.${payload}`, env.ADMIN_JWT_SECRET || "imarika-admin-secret");
        return `${header}.${payload}.${sig}`;
      }

      async function verifyAdmin(req, env) {
        const hdr = req.headers.get("authorization") || "";
        const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : "";
        const parts = token.split(".");
        if (parts.length !== 3) return false;
        const [h, p, s] = parts;
        const calc = await hmac(`${h}.${p}`, env.ADMIN_JWT_SECRET || "imarika-admin-secret");
        if (calc !== s) return false;
        try {
          const payload = JSON.parse(atob(p.replace(/-/g, "+").replace(/_/g, "/")));
          return payload.sub === "admin" && payload.exp > nowSec();
        } catch { return false; }
      }

      // ---------- DIAGNOSTICS ----------
      if (url.pathname === "/api/health") {
        return json({ ok: true, time: Date.now() });
      }
      if (url.pathname === "/api/env-check") {
        return json({
          ok: true,
          haveDB: !!db,
          envs: {
            ADMIN_INIT_SECRET: !!env.ADMIN_INIT_SECRET,
            ADMIN_PHONE: !!env.ADMIN_PHONE,
            ADMIN_PASS: !!env.ADMIN_PASS,
            PASS_SALT: !!env.PASS_SALT,
            ADMIN_JWT_SECRET: !!env.ADMIN_JWT_SECRET
          }
        });
      }

      // ---------- ADMIN INIT ----------
      if (url.pathname === "/api/admin/init") {
        const given = url.searchParams.get("secret") || "";
        const expected = env.ADMIN_INIT_SECRET || "Oury2933#";
        if (given !== expected) return json({ ok:false, error:"Forbidden" }, 403);

        if (!db) return json({ ok:false, error:"DB binding missing" }, 500);
        await ensureSchema();

        const adminPhone = env.ADMIN_PHONE || "0715151010";
        const adminPass = env.ADMIN_PASS || "Oury2933#";
        const salt = env.PASS_SALT || "imarika-salt";
        const passHash = await sha256Hex(`${adminPass}:${salt}`);

        await q(`
          INSERT INTO admins (phone, pass_hash, created_at)
          VALUES (?, ?, ?)
          ON CONFLICT(phone) DO UPDATE SET pass_hash=excluded.pass_hash
        `, adminPhone, passHash, nowSec()).run();

        return json({ ok:true, adminPhone });
      }

      // ---------- PUBLIC: REGISTER ----------
      if (url.pathname === "/api/register" && req.method === "POST") {
        if (!db) return json({ ok:false, error:"DB binding missing" }, 500);
        await ensureSchema();
        const body = await req.json().catch(()=>({}));
        const { full_name, id_number, phone, pin } = body;

        if (!/^0(7|1)\d{8}$/.test(String(phone||"").trim()))
          return json({ ok:false, error:"Invalid phone" }, 400);
        if (!/^\d{4}$/.test(String(pin||"")))
          return json({ ok:false, error:"PIN must be 4 digits" }, 400);

        const exists = await q(`SELECT id FROM users WHERE phone=?`, phone).first();
        if (exists) return json({ ok:false, error:"Phone already registered" }, 409);

        const pass_hash = await sha256Hex(`${pin}:${env.PASS_SALT || "imarika-salt"}`);
        await q(`
          INSERT INTO users (phone, full_name, id_number, account, wallet, invested, pass_hash, created_at)
          VALUES (?, ?, ?, ?, 0, 0, ?, ?)
        `, phone, full_name||null, id_number||null, acctNum(), pass_hash, nowSec()).run();

        const u = await q(`
          SELECT phone, full_name, id_number, account, wallet, invested, created_at
          FROM users WHERE phone=?`, phone).first();

        return json({ ok:true, user:u });
      }

      // ---------- PUBLIC: LOGIN ----------
      if (url.pathname === "/api/login" && req.method === "POST") {
        if (!db) return json({ ok:false, error:"DB binding missing" }, 500);
        await ensureSchema();
        const { phone, pin } = await req.json().catch(()=>({}));

        if (!/^0(7|1)\d{8}$/.test(String(phone||"").trim()))
          return json({ ok:false, error:"Invalid phone" }, 400);
        if (!/^\d{4}$/.test(String(pin||"")))
          return json({ ok:false, error:"PIN must be 4 digits" }, 400);

        const pass_hash = await sha256Hex(`${pin}:${env.PASS_SALT || "imarika-salt"}`);
        const u = await q(`
          SELECT phone, full_name, id_number, account, wallet, invested, created_at
          FROM users WHERE phone=? AND pass_hash=?`, phone, pass_hash).first();

        if (!u) return json({ ok:false, error:"Invalid credentials" }, 401);
        return json({ ok:true, user:u });
      }

      // ---------- PUBLIC: USER GET (for balance refresh) ----------
      if (url.pathname === "/api/user" && req.method === "GET") {
        if (!db) return json({ ok:false, error:"DB binding missing" }, 500);
        await ensureSchema();

        const phone = url.searchParams.get("phone") || "";
        if (!phone) return json({ ok:false, error:"phone required" }, 400);

        const u = await q(`
          SELECT full_name, phone, id_number, account, wallet, invested, created_at
          FROM users WHERE phone=?
        `, phone).first();

        if (!u) return json({ ok:false, error:"Not found" }, 404);
        return json({ ok:true, user:u });
      }

      // ---------- PUBLIC: CREATE TX (Pending) ----------
      if (url.pathname === "/api/tx" && req.method === "POST") {
        if (!db) return json({ ok:false, error:"DB binding missing" }, 500);
        await ensureSchema();

        const { phone, type, amount, detail = "", status } = await req.json().catch(()=>({}));
        if (!phone || !type || !Number.isFinite(Number(amount)))
          return json({ ok:false, error:"phone/type/amount required" }, 400);

        const id = crypto.randomUUID();
        await q(`
          INSERT INTO transactions (id, phone, type, amount, detail, status, ts)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `, id, phone, String(type), Math.abs(Number(amount)), detail, status || 'Pending', Date.now()).run();

        return json({ ok:true, id, status: status || 'Pending' }, 201);
      }

      // ---------- PUBLIC: LIST TX FOR PHONE ----------
      if (url.pathname === "/api/tx" && req.method === "GET") {
        if (!db) return json({ ok:false, error:"DB binding missing" }, 500);
        await ensureSchema();

        const phone = url.searchParams.get("phone") || "";
        if (!phone) return json({ ok:false, error:"phone required" }, 400);

        const res = await q(`
          SELECT id, type, amount, detail, status, ts
          FROM transactions
          WHERE phone=?
          ORDER BY ts DESC LIMIT 500
        `, phone).all();

        return json({ ok:true, tx: res.results || [] });
      }

      // ---------- PUBLIC: MIGRATE LEGACY TX ----------
      if (url.pathname === "/api/tx/migrate" && req.method === "POST") {
        if (!db) return json({ ok:false, error:"DB binding missing" }, 500);
        await ensureSchema();

        const { phone, items = [] } = await req.json().catch(()=>({}));
        if (!phone) return json({ ok:false, error:"phone required" }, 400);

        for (const it of items) {
          const id = it.id || crypto.randomUUID();
          try {
            await q(
              `INSERT INTO transactions (id, phone, type, amount, detail, status, ts)
               VALUES (?, ?, ?, ?, ?, ?, ?)`,
              id, phone, String(it.type||''), Math.abs(Number(it.amount||0)),
              String(it.detail||''), String(it.status||'Pending'),
              Number(it.ts||Date.now())
            ).run();
          } catch {}
        }
        return json({ ok:true, count: items.length });
      }

      // ---------- ADMIN: LOGIN ----------
      if (url.pathname === "/api/admin/login" && req.method === "POST") {
        if (!db) return json({ ok:false, error:"DB binding missing" }, 500);
        await ensureSchema();

        const { phone = "", pass = "" } = await req.json().catch(()=>({}));
        const salt = env.PASS_SALT || "imarika-salt";
        const hash = await sha256Hex(`${pass}:${salt}`);

        const row = await q(`SELECT phone FROM admins WHERE phone=? AND pass_hash=?`, phone, hash).first();
        const envOK = (env.ADMIN_PHONE && env.ADMIN_PASS &&
                       phone === env.ADMIN_PHONE && pass === env.ADMIN_PASS);
        if (!row && !envOK) return json({ ok:false, error:"Invalid credentials" }, 401);

        const token = await issueAdminToken(env);
        return json({ ok:true, token });
      }

      // ----- ADMIN GUARD -----
      const needAdmin = async () => await verifyAdmin(req, env);

      // ADMIN: USERS LIST
      if (url.pathname === "/api/admin/users" && req.method === "GET") {
        if (!(await needAdmin())) return json({ ok:false, error:"Unauthorized" }, 401);
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

      // ADMIN: FIND/UPSERT USER
      if (url.pathname === "/api/admin/user" && req.method === "GET") {
        if (!(await needAdmin())) return json({ ok:false, error:"Unauthorized" }, 401);
        await ensureSchema();

        const phone = url.searchParams.get("phone") || "";
        const account = url.searchParams.get("account") || "";
        if (!phone && !account) return json({ ok:false, error:"phone or account required" }, 400);

        const where = phone ? "phone=?" : "account=?";
        const val = phone || account;
        const u = await q(`
          SELECT full_name, phone, id_number, account, wallet, invested, created_at
          FROM users WHERE ${where}
        `, val).first();

        if (!u) return json({ ok:false, error:"Not found" }, 404);
        return json({ ok:true, user:u });
      }

      if (url.pathname === "/api/admin/user/upsert" && req.method === "POST") {
        if (!(await needAdmin())) return json({ ok:false, error:"Unauthorized" }, 401);
        await ensureSchema();

        const { phone, full_name=null, id_number=null, wallet=null, invested=null, account=null } =
          await req.json().catch(()=>({}));
        if (!phone) return json({ ok:false, error:"phone is required" }, 400);

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

      // ADMIN: PENDING TX
      if (url.pathname === "/api/admin/pending" && req.method === "GET") {
        if (!(await needAdmin())) return json({ ok:false, error:"Unauthorized" }, 401);
        await ensureSchema();

        const res = await q(`
          SELECT id, phone, type, amount, detail, status, ts
          FROM transactions
          WHERE status='Pending'
          ORDER BY ts DESC LIMIT 500
        `).all();

        return json({ ok:true, pending: res.results || [] });
      }

      // ADMIN: UPDATE TX + ADJUST WALLET
      if (url.pathname === "/api/admin/tx/update" && req.method === "POST") {
        if (!(await needAdmin())) return json({ ok:false, error:"Unauthorized" }, 401);
        await ensureSchema();

        const { id, action } = await req.json().catch(()=>({}));
        if (!id || !action) return json({ ok:false, error:"id and action required" }, 400);

        const t = await q(`SELECT * FROM transactions WHERE id=?`, id).first();
        if (!t) return json({ ok:false, error:"Not found" }, 404);

        const newStatus = action === "approve" ? "Approved" : "Rejected";
        await q(`UPDATE transactions SET status=? WHERE id=?`, newStatus, id).run();

        if (t.phone) {
          const amt = Math.abs(Number(t.amount || 0));
          // Deposits credit wallet on approval
          if (t.type === "Deposit" && newStatus === "Approved") {
            await q(`UPDATE users SET wallet = wallet + ? WHERE phone=?`, amt, t.phone).run();
          }
          // Withdrawals deduct wallet on approval
          if (t.type === "Withdrawal" && newStatus === "Approved") {
            await q(`UPDATE users SET wallet = wallet - ? WHERE phone=?`, amt, t.phone).run();
          }
          // No wallet change on rejection (we never held server-side)
        }

        return json({ ok:true, id, status:newStatus });
      }

      return new Response("Not found", { status: 404, headers: CORS });
    } catch (err) {
      return new Response(JSON.stringify({ ok:false, error:String(err && err.message || err) }), {
        status: 500,
        headers: { "content-type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
  }
};
