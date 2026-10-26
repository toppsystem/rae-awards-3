
export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json();
    const reference = String(body.reference || '').trim();
    const callerEmail = String(body.email || '').trim().toLowerCase();

    if (!reference || !callerEmail) {
      return Response.json({ error: 'Payment reference and email are required.' }, { status: 400 });
    }

    // 1. Verify transaction directly with Paystack API using Secret Key
    const psRes = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
      headers: {
        'Authorization': `Bearer ${env.PAYSTACK_SECRET_KEY}`
      }
    });
    const psData = await psRes.json();

    if (!psData.status || !psData.data || psData.data.status !== 'success') {
      return Response.json({ error: 'Transaction has not been confirmed by Paystack.' }, { status: 400 });
    }

    const tx = psData.data;
    const paidEmail = String(tx.customer?.email || '').trim().toLowerCase();

    // Prevent reference enumeration by verifying the caller knows the buyer's email
    if (paidEmail !== callerEmail) {
      return Response.json({ error: 'Email does not match the payment record for this reference.' }, { status: 403 });
    }

    if (tx.currency !== 'NGN') {
      return Response.json({ error: 'Invalid transaction currency.' }, { status: 400 });
    }

    // 2. Read tamper-proof buyer metadata stored inside Paystack transaction
    const meta = tx.metadata || {};
    const tier_id = String(meta.tier_id || '').trim();
    const buyer_name = String(meta.buyer_name || '').trim();
    const phone = String(meta.phone || '').trim();

    if (!tier_id || !buyer_name) {
      return Response.json({ error: 'Transaction metadata is incomplete.' }, { status: 400 });
    }

    const serviceHeaders = {
      'apikey': env.SUPABASE_SERVICE_ROLE_KEY,
      'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`
    };

    // 3. Fetch official tier price from Supabase ticket_tiers table
    const tierRes = await fetch(
      `${env.SUPABASE_URL}/rest/v1/ticket_tiers?id=eq.${encodeURIComponent(tier_id)}&select=id,name,price_kobo`,
      { headers: serviceHeaders }
    );
    const tiers = await tierRes.json();

    if (!Array.isArray(tiers) || tiers.length === 0) {
      return Response.json({ error: 'Invalid ticket tier specified.' }, { status: 400 });
    }

    const expectedKobo = Number(tiers[0].price_kobo);
    const paidKobo = Number(tx.amount);

    if (paidKobo < expectedKobo) {
      return Response.json({ error: `Underpayment detected: paid ${paidKobo} kobo, required ${expectedKobo} kobo.` }, { status: 400 });
    }

    // 4. Insert verified ticket (Idempotent via unique reference constraint)
    const ticketRes = await fetch(`${env.SUPABASE_URL}/rest/v1/tickets`, {
      method: 'POST',
      headers: {
        ...serviceHeaders,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
      },
      body: JSON.stringify({
        reference: reference,
        tier_id: tier_id,
        buyer_name: buyer_name,
        phone: phone,
        email: paidEmail,
        amount_kobo: paidKobo,
        verified: true
      })
    });

    if (!ticketRes.ok) {
      // If webhook or previous request already inserted this reference, return the existing pass
      const existingRes = await fetch(
        `${env.SUPABASE_URL}/rest/v1/tickets?reference=eq.${encodeURIComponent(reference)}&email=eq.${encodeURIComponent(paidEmail)}&select=id,reference,tier_id,buyer_name,qr_token,checked_in_at`,
        { headers: serviceHeaders }
      );
      const existing = await existingRes.json();
      if (Array.isArray(existing) && existing.length > 0) {
        return Response.json({ success: true, ticket: existing[0], tier_name: tiers[0].name }, { status: 200 });
      }
      return Response.json({ error: 'Could not issue or retrieve ticket record.' }, { status: 500 });
    }

    const inserted = await ticketRes.json();
    return Response.json({ success: true, ticket: inserted[0], tier_name: tiers[0].name }, { status: 200 });
  } catch (err) {
    return Response.json({ error: 'Server error verifying ticket.' }, { status: 500 });
  }
        }
    
