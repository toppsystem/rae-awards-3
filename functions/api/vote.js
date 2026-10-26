
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json();
    const category_id = Number(body.category_id);
    const nominee_id = String(body.nominee_id || '').trim();
    const turnstile_token = String(body.turnstile_token || '').trim();
    const authHeader = request.headers.get('Authorization');

    if (!authHeader || !turnstile_token || !Number.isInteger(category_id) || !UUID_REGEX.test(nominee_id)) {
      return Response.json({ error: 'Invalid ballot payload or missing authentication.' }, { status: 400 });
    }

    // 1. Server-Side Cloudflare Turnstile Verification
    const ip = request.headers.get('CF-Connecting-IP') || '';
    const turnstileForm = new FormData();
    turnstileForm.append('secret', env.TURNSTILE_SECRET_KEY);
    turnstileForm.append('response', turnstile_token);
    turnstileForm.append('remoteip', ip);

    const tsRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: turnstileForm
    });
    const tsOutcome = await tsRes.json();

    if (!tsOutcome.success) {
      return Response.json({ error: 'Bot security check failed. Please refresh and try again.' }, { status: 403 });
    }

    // 2. Verify Google Session JWT directly with Supabase Auth
    const userRes = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
      headers: {
        'Authorization': authHeader,
        'apikey': env.SUPABASE_ANON_KEY
      }
    });

    if (!userRes.ok) {
      return Response.json({ error: 'Your login session has expired. Please sign in again.' }, { status: 401 });
    }
    const user = await userRes.json();

    const serviceHeaders = {
      'apikey': env.SUPABASE_SERVICE_ROLE_KEY,
      'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`
    };

    // 3. Enforce Voting Window (settings table)
    const settingsRes = await fetch(
      `${env.SUPABASE_URL}/rest/v1/settings?id=eq.true&select=vote_open,vote_close`,
      { headers: serviceHeaders }
    );
    const settings = await settingsRes.json();
    if (!Array.isArray(settings) || settings.length === 0) {
      return Response.json({ error: 'Voting configuration is missing.' }, { status: 500 });
    }

    const now = new Date();
    if (now < new Date(settings[0].vote_open) || now > new Date(settings[0].vote_close)) {
      return Response.json({ error: 'Official voting window is currently closed.' }, { status: 403 });
    }

    // 4. Verify Nominee exists, is ACTIVE, and belongs to this exact CATEGORY_ID
    const nomRes = await fetch(
      `${env.SUPABASE_URL}/rest/v1/nominees?id=eq.${encodeURIComponent(nominee_id)}&category_id=eq.${category_id}&active=eq.true&select=id`,
      { headers: serviceHeaders }
    );
    const validNominees = await nomRes.json();
    if (!Array.isArray(validNominees) || validNominees.length === 0) {
      return Response.json({ error: 'Invalid or inactive nominee for this category.' }, { status: 400 });
    }

    // 5. Insert Immutable Vote (Primary Key user_id + category_id blocks duplicates)
    const voteRes = await fetch(`${env.SUPABASE_URL}/rest/v1/votes`, {
      method: 'POST',
      headers: {
        ...serviceHeaders,
        'Content-Type': 'application/json',
        'Prefer': 'return=minimal'
      },
      body: JSON.stringify({
        user_id: user.id,
        category_id: category_id,
        nominee_id: nominee_id
      })
    });

    if (!voteRes.ok) {
      const errText = await voteRes.text();
      if (errText.includes('23505') || errText.includes('duplicate key')) {
        return Response.json({ error: 'You have already voted in this category. Votes are final.' }, { status: 409 });
      }
      return Response.json({ error: 'Vote rejected by database security policy.' }, { status: 400 });
    }

    return Response.json({ success: true }, { status: 200 });
  } catch (err) {
    return Response.json({ error: 'Internal server error processing vote.' }, { status: 500 });
  }
        }
      
