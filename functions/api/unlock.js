// POST /api/unlock  { turnstile_token }  + Authorization: Bearer <user jwt>
// One bot check per voter (valid 7 days). After this, votes go straight to the database.

function J(o, s) {
  return new Response(JSON.stringify(o), {
    status: s || 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

export async function onRequestPost(ctx) {
  const request = ctx.request;
  const env = ctx.env;
  try {
    const need = ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY', 'TURNSTILE_SECRET_KEY'];
    for (const k of need) {
      if (!env[k]) return J({ error: 'Server not configured (missing ' + k + ').' }, 500);
    }

    let body;
    try {
      body = await request.json();
    } catch (e) {
      return J({ error: 'Invalid request.' }, 400);
    }
    const token = String(body.turnstile_token || '').trim();
    const auth = request.headers.get('Authorization') || '';
    if (!token || !/^Bearer\s+\S+$/.test(auth)) {
      return J({ error: 'Missing sign-in or security check.' }, 400);
    }

    const ur = await fetch(env.SUPABASE_URL + '/auth/v1/user', {
      headers: { Authorization: auth, apikey: env.SUPABASE_ANON_KEY },
    });
    if (!ur.ok) return J({ error: 'Your sign-in expired. Please sign in again.' }, 401);
    const user = await ur.json();
    if (!user || !user.id || !user.email || !user.email_confirmed_at) {
      return J({ error: 'Please sign in with a verified Google account.' }, 403);
    }

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
    if (!t.success) return J({ error: 'Security check failed. Please try again.' }, 403);
    if (t.hostname && t.hostname !== new URL(request.url).hostname) {
      return J({ error: 'Security check failed.' }, 403);
    }

    const S = { apikey: env.SUPABASE_SERVICE_ROLE_KEY };
    if (String(env.SUPABASE_SERVICE_ROLE_KEY).startsWith('eyJ')) {
      S.Authorization = 'Bearer ' + env.SUPABASE_SERVICE_ROLE_KEY;
    }
    const r = await fetch(env.SUPABASE_URL + '/rest/v1/voters?on_conflict=user_id', {
      method: 'POST',
      headers: Object.assign({}, S, {
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates,return=minimal',
      }),
      body: JSON.stringify({ user_id: user.id, verified_at: new Date().toISOString() }),
    });
    if (!r.ok) {
      console.error('unlock upsert', r.status, await r.text());
      return J({ error: 'Could not verify. Please try again.' }, 500);
    }
    return J({ ok: true });
  } catch (e) {
    console.error('unlock error', e && e.message);
    return J({ error: 'Server error. Please try again.' }, 500);
  }
}
