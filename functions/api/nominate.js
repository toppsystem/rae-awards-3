// GET  /api/nominate  -> my submitted cards   |   POST /api/nominate { category_id, name, biz, photo } -> sends a card as "pending"
// Authorization: Bearer <supabase user jwt>. Needs SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY.
const J = (o, s) => new Response(JSON.stringify(o), { status: s || 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const svc = (env) => { const h = { apikey: env.SUPABASE_SERVICE_ROLE_KEY }; if (String(env.SUPABASE_SERVICE_ROLE_KEY).startsWith('eyJ')) h.Authorization = 'Bearer ' + env.SUPABASE_SERVICE_ROLE_KEY; return h; };
async function who(request, env) {
  const a = request.headers.get('Authorization') || '';
  if (!/^Bearer\s+\S+$/.test(a)) return null;
  const r = await fetch(env.SUPABASE_URL + '/auth/v1/user', { headers: { Authorization: a, apikey: env.SUPABASE_ANON_KEY } });
  return r.ok ? r.json() : null;
}
const FIELDS = 'id,category_id,name,biz,status,active,photo_url,submitted_at';
export async function onRequestGet({ request, env }) {
  try {
    const u = await who(request, env); if (!u) return J({ error: 'Please sign in again.' }, 401);
    const q = (f) => fetch(`${env.SUPABASE_URL}/rest/v1/nominees?submitted_by=eq.${u.id}&select=${f}&order=submitted_at.desc&limit=20`, { headers: svc(env) });
    let r = await q(FIELDS + ',reject_reason'); if (!r.ok) r = await q(FIELDS);
    return J({ items: r.ok ? await r.json() : [] });
  } catch (e) { return J({ items: [] }); }
}
export async function onRequestPost({ request, env }) {
  try {
    const u = await who(request, env); if (!u) return J({ error: 'Please sign in again.' }, 401);
    let b; try { b = await request.json(); } catch (e) { return J({ error: 'Invalid request.' }, 400); }
    const category_id = Number(b.category_id), name = String(b.name || '').trim(), biz = String(b.biz || '').trim();
    const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(b.photo || ''));
    if (!Number.isInteger(category_id) || category_id < 1 || name.length < 2 || name.length > 120 || biz.length > 120) return J({ error: 'Check your name and category.' }, 400);
    if (!m || m[2].length > 280000) return J({ error: 'Photo is too large or the wrong format.' }, 400);
    const base = env.SUPABASE_URL + '/rest/v1', H = svc(env), JH = { ...H, 'Content-Type': 'application/json' };
    const mine = await (await fetch(`${base}/nominees?submitted_by=eq.${u.id}&select=id`, { headers: H })).json();
    if (Array.isArray(mine) && mine.length >= 3) return J({ error: 'You have reached the limit of 3 cards.' }, 429);
    const ir = await fetch(`${base}/nominees`, { method: 'POST', headers: { ...JH, Prefer: 'return=representation' }, body: JSON.stringify({ category_id, name, biz: biz || null, status: 'pending', active: true, submitted_by: u.id }) });
    if (!ir.ok) { const t = await ir.text(); return J({ error: ir.status === 409 || t.includes('23505') ? 'You already sent a card for this category.' : 'Could not save your card. Please try again.' }, ir.status === 409 ? 409 : 400); }
    const row = (await ir.json())[0], ext = m[1] === 'jpeg' ? 'jpg' : m[1], bin = Uint8Array.from(atob(m[2]), (c) => c.charCodeAt(0));
    const up = () => fetch(`${env.SUPABASE_URL}/storage/v1/object/nominees/${row.id}.${ext}`, { method: 'POST', headers: { ...H, 'Content-Type': 'image/' + m[1], 'x-upsert': 'true' }, body: bin });
    let r = await up();
    if (!r.ok && (r.status === 404 || r.status === 400)) { await fetch(`${env.SUPABASE_URL}/storage/v1/bucket`, { method: 'POST', headers: JH, body: JSON.stringify({ id: 'nominees', name: 'nominees', public: true }) }); r = await up(); }
    if (!r.ok) { await fetch(`${base}/nominees?id=eq.${row.id}`, { method: 'DELETE', headers: H }); return J({ error: 'Photo could not be saved. Please try again.' }, 500); }
    await fetch(`${base}/nominees?id=eq.${row.id}`, { method: 'PATCH', headers: { ...JH, Prefer: 'return=minimal' }, body: JSON.stringify({ photo_url: `${env.SUPABASE_URL}/storage/v1/object/public/nominees/${row.id}.${ext}?v=${Date.now()}` }) });
    return J({ ok: true });
  } catch (e) { return J({ error: 'Something went wrong. Please try again.' }, 500); }
}
