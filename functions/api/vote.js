// POST /api/vote  { category_id, nominee_id, turnstile_token }  + Authorization: Bearer <supabase user jwt>
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const J = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

const svc = (env) => {
  const h = { apikey: env.SUPABASE_SERVICE_ROLE_KEY };
  if (String(env.SUPABASE_SERVICE_ROLE_KEY).startsWith('eyJ')) h.Authorization = `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`;
  return h;
};

export async function onRequestPost({ request, env }) {
  try {
    for (const k of ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY', 'TURNSTILE_SECRET_KEY']) {
      if (!env[k]) return J({ error: `Server not configured (missing ${k}).` }, 500);
    }
    let body;
    try { body = await request.json(); } catch { return J({ error: 'Invalid request.' }, 400); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return J({ error: 'Invalid request.' }, 400);

    const category_id = Number(body.category_id);
    const nominee_id = String(body.nominee_id || '').trim();
    const token = String(body.turnstile_token || '').trim();
    const auth = request.headers.get('Authorization') || '';
    if (!/^Bearer\s+\S+$/.test(auth) || !token || !Number.isInteger(category_id) || category_id < 1 || !UUID.test(nominee_id)) {
      return J({ error: 'Invalid ballot or missing sign-in.' }, 400);
    }
    
