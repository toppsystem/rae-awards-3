
// POST /api/paystack-webhook  (set this URL in Paystack Dashboard > Settings > API Keys & Webhooks)
// Safety net: issues the ticket even if the buyer closed the page right after paying.
const svc = (env) => {
  const h = { apikey: env.SUPABASE_SERVICE_ROLE_KEY };
  if (String(env.SUPABASE_SERVICE_ROLE_KEY).startsWith('eyJ')) h.Authorization = `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`;
  return h;
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
    if (!tx.reference || !tier_id || !buyer_name || !email || tx.currency !== 'NGN') return new Response('Incomplete metadata', { status: 200 });

    const S = svc(env), base = env.SUPABASE_URL + '/rest/v1';
    const tr = await fetch(`${base}/ticket_tiers?id=eq.${encodeURIComponent(tier_id)}&select=price_kobo`, { headers: S });
    const tiers = await tr.json();
    if (!Array.isArray(tiers) || !tiers[0] || Number(tx.amount) !== Number(tiers[0].price_kobo)) {
      console.error('webhook price mismatch', tx.reference);
      return new Response('Price mismatch', { status: 200 }); // do not retry; needs a human
    }
    const ins = await fetch(`${base}/tickets?on_conflict=reference`, {
      method: 'POST',
      headers: { ...S, 'Content-Type': 'application/json', Prefer: 'resolution=ignore-duplicates,return=minimal' },
      body: JSON.stringify({ reference: tx.reference, tier_id, buyer_name, phone, email, amount_kobo: Number(tx.amount), verified: true })
    });
    if (!ins.ok) { console.error('webhook insert', ins.status, await ins.text()); return new Response('Retry', { status: 500 }); }
    return new Response('OK', { status: 200 });
  } catch (e) {
    console.error('webhook error', e && e.message);
    return new Response('Error', { status: 500 });
  }
}
