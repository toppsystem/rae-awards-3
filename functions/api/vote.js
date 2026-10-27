
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

    const category_id = Number(body.category_id);
    const nominee_id = String(body.nominee_id || '').trim();
    const token = String(body.turnstile_token || '').trim();
    const auth = request.headers.get('Authorization') || '';
    if (!/^Bearer\s+\S+$/.test(auth) || !token || !Number.isInteger(category_id) || category_id < 1 || !UUID.test(nominee_id)) {
      return J({ error: 'Invalid ballot or missing sign-in.' }, 400);
    }

    // 1. Who is voting (verified by Supabase Auth)
    const ur = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, { headers: { Authorization: auth, apikey: env.SUPABASE_ANON_KEY } });
    if (!ur.ok) return J({ error: 'Your sign-in expired. Please sign in again.' }, 401);
    const user = await ur.json();
    if (!user || !user.id || !user.email || !user.email_confirmed_at) {
      return J({ error: 'Please sign in with a verified Google account.' }, 403);
    }
    const S = svc(env), base = env.SUPABASE_URL + '/rest/v1';

    // 2. Voting window (server clock, not the phone's)
    const sr = await fetch(`${base}/settings?id=eq.true&select=vote_open,vote_close`, { headers: S });
    const st = await sr.json();
    if (!Array.isArray(st) || !st[0]) return J({ error: 'Voting is not configured yet.' }, 503);
    const now = Date.now();
    if (now < Date.parse(st[0].vote_open)) return J({ error: 'Voting has not opened yet.' }, 403);
    if (now > Date.parse(st[0].vote_close)) return J({ error: 'Voting is closed.' }, 403);

    // 3. Nominee must be active and in this category
    const nr = await fetch(`${base}/nominees?id=eq.${nominee_id}&category_id=eq.${category_id}&active=eq.true&select=id`, { headers: S });
    const nn = await nr.json();
    if (!Array.isArray(nn) || !nn.length) return J({ error: 'That nominee is not valid for this category.' }, 400);

    // 4. Already voted? (checked before Turnstile so a token is not wasted)
    const dr = await fetch(`${base}/votes?user_id=eq.${user.id}&category_id=eq.${category_id}&select=nominee_id`, { headers: S });
    const dd = await dr.json();
    if (Array.isArray(dd) && dd.length) return J({ error: 'You already voted in this category. Votes are final.', already: true }, 409);

    // 5. Bot check
    const fd = new FormData();
    fd.append('secret', env.TURNSTILE_SECRET_KEY);
    fd.append('response', token);
    const ip = request.headers.get('CF-Connecting-IP');
    if (ip) fd.append('remoteip', ip);
    const tr = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: fd });
    const t = await tr.json();
    if (!t.success) return J({ error: 'Security check failed. Please try again.', retry: true }, 403);
    if (t.hostname && t.hostname !== new URL(request.url).hostname) return J({ error: 'Security check failed.' }, 403);

    // 6. Insert. The (user_id, category_id) primary key is the real guard against double votes.
    const ir = await fetch(`${base}/votes`, {
      method: 'POST',
      headers: { ...S, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ user_id: user.id, category_id, nominee_id })
    });
    if (!ir.ok) {
      const txt = await ir.text();
      if (ir.status === 409 || txt.includes('23505')) return J({ error: 'You already voted in this category. Votes are final.', already: true }, 409);
      console.error('vote insert failed', ir.status, txt);
      return J({ error: 'Could not record your vote. Please try again.' }, 500);
    }
    return J({ success: true });
  } catch (e) {
    console.error('vote error', e && e.message);
    return J({ error: 'Server error. Please try again.' }, 500);
  }
                                                                                           }
                                                                           
