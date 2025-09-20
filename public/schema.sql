// ---------- helpers ----------
const json = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s, headers: { "content-type": "application/json" }
});

async function requireSecret(url, env) {
  const given = new URL(url).searchParams.get("secret") || "";
  const expected = env.ADMIN_INIT_SECRET || "";
  if (!expected || given !== expected) {
    throw new Error("Not allowed");
  }
}

// ---------- /api/admin/init (create tables + seed admin) ----------
if (pathname === "/api/admin/init") {
  try {
    await requireSecret(request.url, env);

    // Tables (names/columns match the rest of the code!)
    const USERS_SQL = `
      CREATE TABLE IF NOT EXISTS users (
        phone TEXT PRIMARY KEY,
        account TEXT UNIQUE NOT NULL,
        full_name TEXT,
        id_number TEXT,
        pass_hash TEXT,
        wallet INTEGER DEFAULT 0,
        invested INTEGER DEFAULT 0,
        created_at INTEGER
      );`;

    const TX_SQL = `
      CREATE TABLE IF NOT EXISTS tx (
        id TEXT PRIMARY KEY,
        phone TEXT NOT NULL,
        type TEXT NOT NULL,
        amount INTEGER NOT NULL,
        detail TEXT,
        status TEXT NOT NULL,
        ts INTEGER
      );`;

    const IDX1 = `CREATE INDEX IF NOT EXISTS tx_phone_idx ON tx(phone);`;
    const IDX2 = `CREATE INDEX IF NOT EXISTS tx_status_idx ON tx(status);`;

    const ADMINS_SQL = `
      CREATE TABLE IF NOT EXISTS admins (
        phone TEXT PRIMARY KEY,
        pass_hash TEXT NOT NULL,
        created_at INTEGER
      );`;

    // run schema (separately)
    await env.DB.exec(USERS_SQL);
    await env.DB.exec(TX_SQL);
    await env.DB.exec(IDX1);
    await env.DB.exec(IDX2);
    await env.DB.exec(ADMINS_SQL);

    // seed admin (idempotent)
    const adminPhone = env.ADMIN_PHONE || "0715151010";
    const adminPass  = env.ADMIN_PASS  || "Oury2933#";
    const salt       = env.PASS_SALT   || "imarika-salt";

    async function hash(str, s = "") {
      const data = new TextEncoder().encode(`${str}:${s}`);
      const buf  = await crypto.subtle.digest("SHA-256", data);
      return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
    }
    const passHash = await hash(adminPass, salt);

    await env.DB.prepare(
      "INSERT OR IGNORE INTO admins (phone, pass_hash, created_at) VALUES (?, ?, strftime('%s','now'))"
    ).bind(adminPhone, passHash).run();

    return json({ ok: true, created: true, adminPhone });
  } catch (e) {
    return json({ ok: false, error: String(e) }, 400);
  }
}

// ---------- OPTIONAL: /api/admin/sql (manual SQL exec) ----------
if (pathname === "/api/admin/sql" && request.method === "POST") {
  try {
    await requireSecret(request.url, env);
    const body = await request.json().catch(() => ({}));
    const sql = (body.sql || "").trim();
    if (!sql) return json({ ok: false, error: "Empty SQL" }, 400);
    const rs = await env.DB.exec(sql);
    return json({ ok: true, result: rs });
  } catch (e) {
    return json({ ok: false, error: String(e) }, 400);
  }
}
