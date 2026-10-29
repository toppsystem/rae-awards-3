// POST /api/vote  { category_id, nominee_id, turnstile_token }
// Authorization: Bearer <supabase user jwt>
// Backup path: the app normally votes through /api/unlock + the cast_vote database function.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function J(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

function svc(env) {
  const h = { apikey: env.SUPABASE_SERVICE_ROLE_KEY };
  if (String(env.SUPABASE_SERVICE_ROLE_KEY).startsWith('eyJ')) {
    h.Authorization = 'Bearer ' + env.SUPABASE_SERVICE_ROLE_KEY;
  }
  return h;
}

export async function onRequestPost(ctx) {
  const request = ctx.request;
  const env = ctx.env;
  try {
    const need = [
      'SUPABASE_URL',
      'SUPABASE_ANON_KEY',
      'SUPABASE_SERVICE_ROLE_KEY',
      'TURNSTILE_SECRET_KEY',
    ];
    for (const k of need) {
      if (!env[k]) return J({ error: 'Server not configured (missing ' + k + ').' }, 500);
    }

    let body;
    try {
      body = await request.json();
    } catch (e) {
      return J({ error: 'Invalid request.' }, 400);
    }

    const category_id = Number(body.category_id);
    const nominee_id = String(body.nominee_id || '').trim();
    const token = String(body.turnstile_token || '').trim();
    const auth = request.headers.get('Authorization') || '';
    const okAuth = /^Bearer\s+\S+$/.test(auth);
    if (!okAuth || !token || !Number.isInteger(category_id) || category_id < 1) {
      return J({ error: 'Invalid ballot or missing sign-in.' }, 400);
    }
    if (!UUID.test(nominee_id)) {
      return J({ error: 'Invalid ballot or missing sign-in.' }, 400);
    }

    // 1. Who is voting (checked by Supabase Auth)
    const ur = await fetch(env.SUPABASE_URL + '/auth/v1/user', {
      headers: { Authorization: auth, apikey: env.SUPABASE_ANON_KEY },
    });
    if (!ur.ok) return J({ error: 'Your sign-in expired. Please sign in again.' }, 401);
    const user = await ur.json();
    if (!user || !user.id || !user.email || !user.email_confirmed_at) {
      return J({ error: 'Please sign in with a verified Google account.' }, 403);
    }

    const S = svc(env);
    const base = env.SUPABASE_URL + '/rest/v1';

    // 2. Voting window (server clock)
    const sr = await fetch(base + '/settings?id=eq.true&select=vote_open,vote_close', { headers: S });
    const st = await sr.json();
    if (!Array.isArray(st) || !st[0]) return J({ error: 'Voting is not configured yet.' }, 503);
    const now = Date.now();
    if (now < Date.parse(st[0].vote_open)) return J({ error: 'Voting has not opened yet.' }, 403);
    if (now > Date.parse(st[0].vote_close)) return J({ error: 'Voting is closed.' }, 403);

    // 3. Category must not be paused
    const cr = await fetch(base + '/categories?id=eq.' + category_id + '&select=paused', { headers: S });
    const cc = await cr.json();
    if (!Array.isArray(cc) || !cc[0]) return J({ error: 'Unknown category.' }, 400);
    if (Number(cc[0].paused) > 0) return J({ error: 'Voting is paused for this category.' }, 403);

    // 4. Nominee must be active, approved and in this category
    const nq = '/nominees?id=eq.' + nominee_id + '&category_id=eq.' + category_id;
    const nr = await fetch(base + nq + '&active=eq.true&select=id,status', { headers: S });
    const nn = await nr.json();
    const approved = Array.isArray(nn) && nn[0] && (!nn[0].status || nn[0].status === 'approved');
    if (!approved) return J({ error: 'That nominee is not valid for this category.' }, 400);

    // 5. Already voted? (checked before the bot check so a token is not wasted)
    const dq = '/votes?user_id=eq.' + user.id + '&category_id=eq.' + category_id + '&select=nominee_id';
    const dr = await fetch(base + dq, { headers: S });
    const dd = await dr.json();
    if (Array.isArray(dd) && dd.length) {
      return J({ error: 'You already voted in this category. Votes are final.', already: true }, 409);
    }

    // 6. Bot check
    const fd = new FormData();
    fd.append('secret', env.TURNSTILE_SECRET_KEY);
    fd.append('response', token);
    const ip = request.headers.get('CF-Connecting-IP');
    if (ip) fd.append('remoteip', ip);
    const tr = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: fd,
    });
    const t = await tr.json();
    if (!t.success) return J({ error: 'Security check failed. Please try again.', retry: true }, 403);
    if (t.hostname && t.hostname !== new URL(request.url).hostname) {
      return J({ error: 'Security check failed.' }, 403);
    }

    // 7. Save the vote. The database rule (one vote per person per category) is the final guard.
    const ir = await fetch(base + '/votes', {
      method: 'POST',
      headers: Object.assign({}, S, { 'Content-Type': 'application/json', Prefer: 'return=minimal' }),
      body: JSON.stringify({ user_id: user.id, category_id: category_id, nominee_id: nominee_id }),
    });
    if (!ir.ok) {
      const txt = await ir.text();
      if (ir.status === 409 || txt.indexOf('23505') > -1) {
        return J({ error: 'You already voted in this category. Votes are final.', already: true }, 409);
      }
      console.error('vote insert failed', ir.status, txt);
      return J({ error: 'Could not record your vote. Please try again.' }, 500);
    }
    return J({ success: true });
  } catch (e) {
    console.error('vote error', e && e.message);
    return J({ error: 'Server error. Please try again.' }, 500);
  }
}
