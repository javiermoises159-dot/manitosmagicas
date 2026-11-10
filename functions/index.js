// Sirve la página con el catálogo que Carim guardó desde su panel.
export async function onRequestGet({ request, env, next }) {
  const res = await next();
  if (!env.DB) return res;
  const ct = res.headers.get("Content-Type") || "";
  if (!ct.includes("text/html")) return res;
  const cat = await env.DB.get("catalog");
  if (!cat) return res;
  const html = await res.text();
  const safe = cat.replace(/</g, "\\u003c");
  const out = html.replace(/(<script type="application\/json" id="catalog-data">)[\s\S]*?(<\/script>)/, (_, a, b) => a + safe + b);
  const h = new Headers(res.headers); h.set("Cache-Control", "no-store"); h.delete("Content-Length");
  return new Response(out, { status: res.status, headers: h });
}
