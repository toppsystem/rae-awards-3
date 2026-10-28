// POST /api/verify-ticket { reference, email }  -> verifies with Paystack, issues (or returns) the pass
const J = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
// Paystack may add its fee on top of the ticket price. Accept price .. price + fee allowance.
const amountOk = (paid, price) => {
  paid = Number(paid); price = Number(price);
  return Number.isFinite(paid) && paid >= price && paid <= price + Math.max(Math.round(price * 0.05), 50000);
};
const insTicket = async (base, S, row) => {
  const r = await fetch(`${base}/tickets?on_conflict=reference`, {
    method: 'POST',
    headers: { ...S, 'Content-Type': 'application/json', Prefer: 'resolution=ignore-duplicates,return=minimal' },
    body: JSON.stringify(row)
  });
  return { ok: r.ok, status: r.status, text: r.ok ? '' : await r.text().catch(() => '') };
};
// Tries the full row first; if the database rejects it (e.g. a column is missing), retries with the essentials.
const issue = async (base, S, f) => {
  let r = await insTicket(base, S, f);
  if (r.ok) return r;
  const first = r.status + ' ' + r.text;
  r = await insTicket(base, S, { reference: f.reference, tier_id: f.tier_id, buyer_name: f.buyer_name, email: f.email, verified: true });
  if (!r.ok) r.text = (first + ' | ' + r.status + ' ' + r.text).slice(0, 300);
  else r.degraded = first.slice(0, 300);
  return r;
};
const svc = (env) => {
  const h = { apikey: env.SUPABASE_SERVICE_ROLE_KEY };
  if (String(env.SUPABASE_SERVICE_ROLE_KEY).startsWith('eyJ')) h.Authorization = `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`;
  return h;
};

// Records a payment that needs a human and emails you once per reference.
// Needs Cloudflare env vars RESEND_API_KEY, ALERT_EMAIL, ALERT_FROM. Never throws.
const alertFail = async (env, S, base, info) => {
  try {
    const amt = Number(info.amount);
    const row = { reference: String(info.reference || 'unknown').slice(0, 100), email: info.email || null, tier_id: info.tier_id || null, amount_kobo: Number.isFinite(amt) ? amt : null, reason: String(info.reason || '').slice(0, 500) };
    const r = await fetch(`${base}/failed_payments?on_conflict=reference`, {
      method: 'POST',
      headers: { ...S, 'Content-Type': 'application/json', Prefer: 'resolution=ignore-duplicates,return=representation' },
      body: JSON.stringify(row)
    });
    const created = r.ok ? await r.json().catch(() => []) : [];
    if (r.ok && !(Array.isArray(created) && created.length)) return; // already reported, do not email again
    if (env.RESEND_API_KEY && env.ALERT_EMAIL) {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: env.ALERT_FROM || 'alerts@resend.dev', to: [env.ALERT_EMAIL], subject: 'Payment needs attention: ' + row.reference, text: `Reason: ${row.reason}\nReference: ${row.reference}\nEmail: ${row.email}\nTier: ${row.tier_id}\nAmount (kobo): ${row.amount_kobo}` })
      });
    }
  } catch (e) { console.error('alert failed', e && e.message); }
};

export async function onRequestPost({ request, env }) {
  try {
    for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'PAYSTACK_SECRET_KEY']) {
      if (!env[k]) return J({ error: `Server not configured (missing ${k}).`, code: 'CONFIG_' + k, retry: false }, 500);
    }
    let body;
    try { body = await request.json(); } catch { return J({ error: 'Invalid request.' }, 400); }
    const reference = String(body.reference || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    if (!/^[A-Za-z0-9._-]{6,100}$/.test(reference) || !/^.+@.+\..+$/.test(email)) {
      return J({ error: 'Enter a valid payment reference and email.' }, 400);
    }

    const pr = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
      headers: { Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}` }
    });
    const pj = await pr.json().catch(() => ({}));
    if (!pj.status || !pj.data) {
      return J({ error: pr.status === 401 ? 'Payment key is not accepted by Paystack.' : 'Payment not found yet. If you were charged, wait a minute and try again.', code: pr.status === 401 ? 'PS_KEY_INVALID' : 'PS_NOT_FOUND', retry: pr.status !== 401 }, pr.status === 401 ? 500 : 404);
    }
    const tx = pj.data;
    if (tx.status !== 'success') {
      const pending = ['pending', 'ongoing', 'processing', 'queued'].includes(tx.status);
      return J({ error: pending ? 'Payment is still processing.' : 'This payment was not completed.', retry: pending }, pending ? 202 : 400);
    }
    if (tx.reference !== reference) return J({ error: 'Reference mismatch.' }, 400);
    if (String(tx.customer && tx.customer.email || '').toLowerCase() !== email) {
      return J({ error: 'That email does not match this payment.' }, 403);
    }
    if (tx.currency !== 'NGN') return J({ error: 'Unsupported currency.' }, 400);

    const meta = tx.metadata || {};
    const tier_id = String(meta.tier_id || '').trim();
    const buyer_name = String(meta.buyer_name || '').trim().slice(0, 120);
    const phone = String(meta.phone || '').trim().slice(0, 30);
    if (!tier_id || !buyer_name) return J({ error: 'Payment details incomplete. Contact the organisers with your reference.' }, 400);

    const S = svc(env), base = env.SUPABASE_URL + '/rest/v1';
    const tr = await fetch(`${base}/ticket_tiers?id=eq.${encodeURIComponent(tier_id)}&select=*`, { headers: S });
    const tiers = await tr.json();
    if (!Array.isArray(tiers) || !tiers[0]) return J({ error: 'Unknown ticket type. Contact the organisers with your reference.' }, 400);
    const tier = tiers[0];
    if (!amountOk(tx.amount, tier.price_kobo)) {
      await alertFail(env, S, base, { reference, email, tier_id, amount: tx.amount, reason: 'Price mismatch at verify' });
      return J({ error: 'Amount paid does not match the ticket price. Contact the organisers with your reference.' }, 400);
    }

    // Idempotent: the webhook or an earlier call may already have inserted it.
    const row = { reference, tier_id, buyer_name, phone, email, amount_kobo: Number(tx.amount), verified: true };
    if (tier.event_id) row.event_id = tier.event_id;   // only once the SQL migration has been run
    const ins = await issue(base, S, row);
    if (!ins.ok) {
      console.error('ticket insert', ins.text);
      await alertFail(env, S, base, { reference, email, tier_id, amount: tx.amount, reason: 'Ticket insert failed at verify: ' + ins.text });
      return J({ error: 'Payment received, but the pass could not be saved. The organisers have been alerted by your reference.', code: 'DB_INSERT', retry: false }, 500);
    }
    if (ins.degraded) await alertFail(env, S, base, { reference, email, tier_id, amount: tx.amount, reason: 'Ticket issued with reduced fields: ' + ins.degraded });

    const gr = await fetch(`${base}/tickets?reference=eq.${encodeURIComponent(reference)}&select=reference,tier_id,buyer_name,qr_token,checked_in_at`, { headers: S });
    const rows = await gr.json();
    if (!Array.isArray(rows) || !rows[0]) return J({ error: 'Could not load your pass. Try again.', code: 'DB_READ', retry: true }, 500);
    // If the buyer is signed in, link this ticket to their account (best effort).
    const auth = request.headers.get('Authorization') || '';
    if (/^Bearer\s+\S+$/.test(auth) && env.SUPABASE_ANON_KEY) {
      try {
        const ur = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, { headers: { Authorization: auth, apikey: env.SUPABASE_ANON_KEY } });
        const u = ur.ok ? await ur.json() : null;
        if (u && u.id && String(u.email || '').toLowerCase() === email) {
          await fetch(`${base}/tickets?reference=eq.${encodeURIComponent(reference)}&user_id=is.null`, {
            method: 'PATCH', headers: { ...S, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
            body: JSON.stringify({ user_id: u.id })
          });
        }
      } catch (e) { /* ignore */ }
    }
    return J({ success: true, ticket: rows[0], tier_name: tier.name, kind: tier.kind });
  } catch (e) {
    console.error('verify error', e && e.message);
    return J({ error: 'Server error. Please try again.', code: 'EXCEPTION', retry: true }, 500);
  }
}

