// POST /api/my-tickets   Authorization: Bearer <supabase user jwt>
// Returns every ticket belonging to the signed-in Google account (same email, or linked user_id).
const J = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const svc = (env) => {
  const h = { apikey: env.SUPABASE_SERVICE_ROLE_KEY };
  if (String(env.SUPABASE_SERVICE_ROLE_KEY).startsWith('eyJ')) h.Authorization = `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`;
  return h;
};

export async function onRequestPost({ request, env }) {
  try {
    for (const k of ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY']) {
      if (!env[k]) return J({ error: `Server not configured (missing ${k}).` }, 500);
    }
    const auth = request.headers.get('Authorization') || '';
    if (!/^Bearer\s+\S+$/.test(auth)) return J({ error: 'Sign in first.' }, 401);

    const ur = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, { headers: { Authorization: auth, apikey: env.SUPABASE_ANON_KEY } });
    if (!ur.ok) return J({ error: 'Your sign-in expired. Please sign in again.' }, 401);
    const user = await ur.json();
    const email = String(user && user.email || '').toLowerCase();
    if (!user.id || !email || !user.email_confirmed_at || /[",()\\]/.test(email)) {
      return J({ error: 'Please sign in with a verified Google account.' }, 403);
    }

    const S = svc(env), base = env.SUPABASE_URL + '/rest/v1';
    const filter = encodeURIComponent(`(email.eq."${email}",user_id.eq.${user.id})`);
    const [tr, kr] = await Promise.all([
      fetch(`${base}/tickets?or=${filter}&verified=eq.true&revoked=not.is.true&select=id,reference,tier_id,buyer_name,qr_token,checked_in_at,user_id&order=created_at.desc&limit=100`, { headers: S }),
      fetch(`${base}/ticket_tiers?select=id,name,kind`, { headers: S })
    ]);
    if (!tr.ok || !kr.ok) { console.error('my-tickets query', tr.status, kr.status); return J({ error: 'Could not load tickets.' }, 500); }
    const rows = await tr.json(), tiers = await kr.json();
    const tmap = {}; (tiers || []).forEach((t) => { tmap[t.id] = t; });

    // Link email-matched tickets to this account so they follow it even if the email differs later.
    const unlinked = rows.filter((r) => !r.user_id).map((r) => r.id);
    if (unlinked.length) {
      fetch(`${base}/tickets?id=in.(${unlinked.join(',')})&user_id=is.null`, {
        method: 'PATCH', headers: { ...S, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
        body: JSON.stringify({ user_id: user.id })
      }).catch(() => {});
    }
    return J({
      tickets: rows.map((r) => ({
        reference: r.reference, buyer_name: r.buyer_name, qr_token: r.qr_token, checked_in_at: r.checked_in_at,
        tier_name: (tmap[r.tier_id] || {}).name || r.tier_id, kind: (tmap[r.tier_id] || {}).kind || 'ticket'
      }))
    });
  } catch (e) {
    console.error('my-tickets error', e && e.message);
    return J({ error: 'Server error. Please try again.' }, 500);
  }
}
