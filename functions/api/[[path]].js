// API del panel de Carim (Cloudflare Pages Functions).
// Necesita en Cloudflare: un KV namespace enlazado como "DB" y una variable secreta "ADMIN_PIN".
const PUBLIC_COLS = ["busy"];      // se pueden leer sin código (solo día, hora y duración)
const PUBLIC_DOCS = ["public/promo"];
const COLS = ["appts", "cards", "busy"];
const DOCS = ["public/promo", "settings/goals"];
const TOKEN_DAYS = 30;

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra } });
const err = (msg, status) => json({ error: msg }, status);
const rid = () => crypto.randomUUID().replace(/-/g, "").slice(0, 20);

async function hmac(secret, text) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function same(a, b) { if (a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i); return x === 0; }
async function makeToken(env) { const exp = Math.floor(Date.now() / 1000) + TOKEN_DAYS * 86400; return exp + "." + (await hmac(env.ADMIN_PIN, "carim:" + exp)); }
async function isAdmin(request, env) {
  const h = request.headers.get("Authorization") || ""; const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [exp, sig] = t.split("."); if (!exp || !sig || +exp < Date.now() / 1000) return false;
  return same(sig, await hmac(env.ADMIN_PIN, "carim:" + exp));
}
async function readCol(env, col) { return (await env.DB.get("c:" + col, "json")) || {}; }
async function writeCol(env, col, obj) { await env.DB.put("c:" + col, JSON.stringify(obj)); }
async function body(request) { try { return await request.json(); } catch (e) { return null; } }

export async function onRequest({ request, env, params }) {
  if (!env.DB || !env.ADMIN_PIN) return err("Falta configurar el guardado en Cloudflare (DB y ADMIN_PIN).", 503);
  const parts = [].concat(params.path || []);
  const [a, b, c] = parts; const m = request.method;

  // fotos subidas por Carim
  if (a === "img" && b && m === "GET") {
    const r = await env.DB.getWithMetadata("img:" + b, "arrayBuffer");
    if (!r || !r.value) return err("No existe", 404);
    return new Response(r.value, { headers: { "Content-Type": (r.metadata && r.metadata.type) || "image/jpeg", "Cache-Control": "public, max-age=31536000, immutable" } });
  }
  if (a === "catalog" && m === "GET") { const v = await env.DB.get("catalog"); return v ? new Response(v, { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }) : err("Sin catálogo", 404); }

  if (a === "login" && m === "POST") {
    const ip = request.headers.get("CF-Connecting-IP") || "x"; const rk = "rl:" + ip;
    const n = +(await env.DB.get(rk)) || 0;
    if (n >= 8) return err("Demasiados intentos", 429);
    const j = await body(request); const pin = String((j && j.pin) || "");
    if (!same(pin, String(env.ADMIN_PIN))) { await env.DB.put(rk, String(n + 1), { expirationTtl: 600 }); return err("Código incorrecto", 401); }
    await env.DB.delete(rk);
    return json({ token: await makeToken(env) });
  }

  const admin = await isAdmin(request, env);
  if (a === "me") return admin ? json({ ok: true }) : err("Sin acceso", 401);

  if (a === "c" && COLS.includes(b)) {
    if (m === "GET") {
      if (!admin && !PUBLIC_COLS.includes(b)) return err("Sin acceso", 401);
      const o = await readCol(env, b); let rows = Object.entries(o).map(([id, v]) => ({ id, v }));
      if (!admin && b === "busy") rows = rows.map(({ id, v }) => ({ id, v: { date: v.date, time: v.time, min: v.min, kind: v.kind } }));
      return json(rows);
    }
    if (!admin) return err("Sin acceso", 401);
    const o = await readCol(env, b);
    if (m === "POST" && !c) { const v = await body(request); if (!v || typeof v !== "object") return err("Datos inválidos", 400); const id = rid(); o[id] = v; await writeCol(env, b, o); return json({ id }); }
    if (c && m === "PUT") { const v = await body(request); if (!v || typeof v !== "object") return err("Datos inválidos", 400); o[c] = v; await writeCol(env, b, o); return json({ ok: true }); }
    if (c && m === "PATCH") { const v = await body(request); if (!v || typeof v !== "object") return err("Datos inválidos", 400); if (!o[c]) return err("No existe", 404); o[c] = { ...o[c], ...v }; await writeCol(env, b, o); return json({ ok: true }); }
    if (c && m === "DELETE") { delete o[c]; await writeCol(env, b, o); return json({ ok: true }); }
  }

  if (a === "d" && b && c && DOCS.includes(b + "/" + c)) {
    const path = b + "/" + c;
    if (m === "GET") { if (!admin && !PUBLIC_DOCS.includes(path)) return err("Sin acceso", 401); return json(await env.DB.get("d:" + path, "json")); }
    if (!admin) return err("Sin acceso", 401);
    if (m === "PUT") { const v = await body(request); if (!v || typeof v !== "object") return err("Datos inválidos", 400); await env.DB.put("d:" + path, JSON.stringify(v)); return json({ ok: true }); }
    if (m === "DELETE") { await env.DB.delete("d:" + path); return json({ ok: true }); }
  }

  if (!admin) return err("Sin acceso", 401);

  if (a === "catalog" && m === "PUT") {
    const t = await request.text(); let v; try { v = JSON.parse(t); } catch (e) { return err("Catálogo inválido", 400); }
    if (!v || typeof v !== "object") return err("Catálogo inválido", 400);
    await env.DB.put("catalog", JSON.stringify(v)); return json({ ok: true });
  }
  if (a === "upload" && m === "POST") {
    const type = request.headers.get("Content-Type") || "application/octet-stream";
    if (!/^(image|video)\//.test(type)) return err("Solo fotos o videos", 400);
    const buf = await request.arrayBuffer();
    if (buf.byteLength > 24 * 1024 * 1024) return err("El archivo es muy grande (máximo 24 MB)", 413);
    const id = rid(); await env.DB.put("img:" + id, buf, { metadata: { type } });
    return json({ url: "/api/img/" + id });
  }
  return err("No encontrado", 404);
}
