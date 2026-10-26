
export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const signature = request.headers.get('x-paystack-signature');
    if (!signature || !env.PAYSTACK_SECRET_KEY) {
      return new Response('Unauthorized', { status: 401 });
    }

    const rawBody = await request.text();

    // Verify HMAC SHA-512 Signature using Web Crypto API
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(env.PAYSTACK_SECRET_KEY),
      { name: 'HMAC', hash: 'SHA-512' },
      false,
      ['sign']
    );
    const sigBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(rawBody));
    const computedHex = Array.from(new Uint8Array(sigBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    if (computedHex !== signature) {
      return new Response('Invalid signature', { status: 401 });
    }

    const event = JSON.parse(rawBody);
    if (event.event !== 'charge.success') {
      return new Response('Ignored event', { status: 200 });
    }

    const tx = event.data;
    const meta = tx.metadata || {};
    const tier_id = String(meta.tier_id || '').trim();
    const buyer_name = String(meta.buyer_name || '').trim();
    const phone = String(meta.phone || '').trim();
    const email = String(tx.customer?.email || '').trim().toLowerCase();

    if (!tier_id || !buyer_name || !email || tx.currency !== 'NGN') {
      return new Response('Missing metadata', { status: 200 });
    }

    const serviceHeaders = {
      'apikey': env.SUPABASE_SERVICE_ROLE_KEY,
      'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`
    };

    const tierRes = await fetch(
      `${env.SUPABASE_URL}/rest/v1/ticket_tiers?id=eq.${encodeURIComponent(tier_id)}&select=price_kobo`,
      { headers: serviceHeaders }
    );
    const tiers = await tierRes.json();

    if (!Array.isArray(tiers) || tiers.length === 0 || Number(tx.amount) < Number(tiers[0].price_kobo)) {
      return new Response('Price mismatch', { status: 200 });
    }

    await fetch(`${env.SUPABASE_URL}/rest/v1/tickets`, {
      method: 'POST',
      headers: {
        ...serviceHeaders,
        'Content-Type': 'application/json',
        'Prefer': 'resolution=ignore-duplicates'
      },
      body: JSON.stringify({
        reference: tx.reference,
        tier_id: tier_id,
        buyer_name: buyer_name,
        phone: phone,
        email: email,
        amount_kobo: Number(tx.amount),
        verified: true
      })
    });

    return new Response('Webhook processed', { status: 200 });
  } catch (err) {
    return new Response('Webhook error', { status: 500 });
  }
      }
    
