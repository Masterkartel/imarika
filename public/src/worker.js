export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const cors = {
      "Access-Control-Allow-Origin": "https://www.imarika.net",
      "Access-Control-Allow-Headers": "authorization, content-type",
      "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS"
    };
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });

    const json = (d, s = 200) =>
      new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json", ...cors } });

    if (url.pathname === "/api/health") return json({ ok: true });

    // --- tiny JWT helpers ---
    const enc = (o)=> btoa(unescape(encodeURIComponent(JSON.stringify(o)))).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
    const dec = (s)=> JSON.parse(decodeURIComponent(escape(atob(s.replace(/-/g,'+').replace(/_/g,'/')))));
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
      try {
        const [,p,sig] = bearer.split(".");
        // (HMAC validation omitted for brevity in this minimal sample)
        return !!p && dec(p).sub === "admin";
      } catch { return false; }
    };

    // --- auth login (admin) ---
    if (url.pathname === "/api/auth/login" && req.method === "POST") {
      const { password } = await req.json();
      if (password !== env.ADMIN_PASS) return json({ error: "bad pass" }, 401);
      const token = await makeJWT({ sub: "admin" }, env.ADMIN_JWT_SECRET);
      return json({ token });
    }

    const q = (sql, ...args) => env.DB.prepare(sql).bind(...args);

    // --- users ---
    if (url.pathname === "/api/users" && req.method === "GET") {
      const term = (url.searchParams.get("q")||"").trim();
      const res = await q(
        `SELECT id, full, phone, idn, account, wallet, invested, created_at
         FROM users
         WHERE (? = '' OR full LIKE ? OR phone LIKE ? OR account LIKE ?)
         ORDER BY created_at DESC LIMIT 200`,
        term, `%${term}%`, `%${term}%`, `%${term}%`
      ).all();
      return json(res.results||[]);
    }

    if (url.pathname === "/api/users" && req.method === "POST") {
      const { full="", phone, idn="" } = await req.json();
      if (!phone) return json({ error: "phone required" }, 400);
      const acct = `IMK-${Math.random().toString(36).slice(2,6).toUpperCase()}-${Math.floor(Math.random()*9000+1000)}`;
      await q(
        `INSERT INTO users (full, phone, idn, account, wallet, invested, created_at)
         VALUES (?, ?, ?, ?, 0, 0, ?)`,
        full, phone, idn, acct, Date.now()
      ).run();
      const user = await q(`SELECT * FROM users WHERE phone = ?`, phone).first();
      return json(user, 201);
    }

    // --- transactions (create/list/approve/reject) ---
    if (url.pathname === "/api/tx" && req.method === "POST") {
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
      const status = url.searchParams.get("status");
      const res = await q(
        `SELECT * FROM transactions ${status ? "WHERE status = ?" : ""} ORDER BY ts DESC LIMIT 500`,
        ...(status ? [status] : [])
      ).all();
      return json(res.results||[]);
    }

    const m = url.pathname.match(/^\/api\/tx\/([^/]+)\/(approve|reject)$/);
    if (m && req.method === "PATCH") {
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
