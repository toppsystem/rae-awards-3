// POST /api/paystack-webhook  (set this URL in Paystack Dashboard > Settings > API Keys & Webhooks)
// Safety net: issues the ticket even if the buyer closed the page right after paying.
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
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
function safeEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

export async function onRequestPost({ request, env }) {
  try {
    const sig = request.headers.get('x-paystack-signature');
    if (!sig || !env.PAYSTACK_SECRET_KEY) return new Response('Unauthorized', { status: 401 });
    const raw = await request.text();
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.PAYSTACK_SECRET_KEY), { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
    const mac = hex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(raw)));
    if (!safeEq(mac, sig.toLowerCase())) return new Response('Invalid signature', { status: 401 });

    const ev = JSON.parse(raw);
    if (ev.event !== 'charge.success') return new Response('Ignored', { status: 200 });
    const tx = ev.data || {};
    const meta = tx.metadata || {};
    const tier_id = String(meta.tier_id || '').trim();
    const buyer_name = String(meta.buyer_name || '').trim().slice(0, 120);
    const phone = String(meta.phone || '').trim().slice(0, 30);
    const email = String(tx.customer && tx.customer.email || '').trim().toLowerCase();
    const S = svc(env), base = env.SUPABASE_URL + '/rest/v1';
    if (!tx.reference || !tier_id || !buyer_name || !email || tx.currency !== 'NGN') {
      if (tx.reference) await alertFail(env, S, base, { reference: tx.reference, email, tier_id, amount: tx.amount, reason: 'Paid but metadata incomplete or currency not NGN' });
      return new Response('Incomplete metadata', { status: 200 });
    }
    const tr = await fetch(`${base}/ticket_tiers?id=eq.${encodeURIComponent(tier_id)}&select=*`, { headers: S });
    const tiers = await tr.json();
    if (!Array.isArray(tiers) || !tiers[0] || !amountOk(tx.amount, tiers[0].price_kobo)) {
      console.error('webhook price mismatch', tx.reference);
      await alertFail(env, S, base, { reference: tx.reference, email, tier_id, amount: tx.amount, reason: 'Price mismatch or unknown ticket type' });
      return new Response('Price mismatch', { status: 200 }); // do not retry; you are emailed instead
    }
    const row = { reference: tx.reference, tier_id, buyer_name, phone, email, amount_kobo: Number(tx.amount), verified: true };
    if (tiers[0].event_id) row.event_id = tiers[0].event_id;   // only once the SQL migration has been run
    const ins = await issue(base, S, row);
    if (!ins.ok) {
      console.error('webhook insert', ins.text);
      await alertFail(env, S, base, { reference: tx.reference, email, tier_id, amount: tx.amount, reason: 'Ticket insert failed: ' + ins.text });
      return new Response('Retry', { status: 500 });
    }
    if (ins.degraded) await alertFail(env, S, base, { reference: tx.reference, email, tier_id, amount: tx.amount, reason: 'Ticket issued with reduced fields. Database rejected the full row: ' + ins.degraded });
    return new Response('OK', { status: 200 });
  } catch (e) {
    console.error('webhook error', e && e.message);
    return new Response('Error', { status: 500 });
  }
}
