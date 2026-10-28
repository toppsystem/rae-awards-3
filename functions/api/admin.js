// POST /api/admin { action, ... }   Google or password sign-in, OTP only for register/reset, roles, audit log.
// Env: SUPABASE_URL SUPABASE_ANON_KEY SUPABASE_SERVICE_ROLE_KEY RESEND_API_KEY OTP_FROM OTP_PEPPER
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const svc = (env) => { const h = { apikey: env.SUPABASE_SERVICE_ROLE_KEY }; if (String(env.SUPABASE_SERVICE_ROLE_KEY).startsWith('eyJ')) h.Authorization = 'Bearer ' + env.SUPABASE_SERVICE_ROLE_KEY; return h; };
const RANK = { gate: 1, ticketing: 1.5, admin: 2, super: 3 };
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/, UUID = /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i, TOKEN = /^[0-9a-f]{64}$/i;
const DAILY_CAP = 40;            // admin OTP emails per 24h across everyone (Resend free tier = 100/day)
const enc = encodeURIComponent;
const sha = async (s) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, '0')).join('');
const same = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const csvCell = (v) => { let s = v == null ? '' : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
const toCsv = (rows) => { if (!rows.length) return ''; const k = Object.keys(rows[0]); return [k.map(csvCell).join(','), ...rows.map((r) => k.map((c) => csvCell(r[c])).join(','))].join('\n'); };

const mkdb = (env) => async (path, method = 'GET', body, prefer = 'return=representation') => {
  const r = await fetch(env.SUPABASE_URL + '/rest/v1/' + path, { method, headers: { ...svc(env), 'Content-Type': 'application/json', Prefer: prefer }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j = null; try { j = t ? JSON.parse(t) : null; } catch {}
  if (!r.ok) throw new Error(path + ' ' + r.status + ' ' + t.slice(0, 200));
  return j;
};

const all = async (q, path) => { let o = 0, out = []; for (;;) { const r = await q(`${path}&limit=1000&offset=${o}`); out = out.concat(r); if (r.length < 1000) return out; o += 1000; } };   // Supabase caps a page at 1000 rows
const sidOf = (auth) => { try { return String(JSON.parse(atob(auth.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).session_id || ''); } catch { return ''; } };
const codeOk = async (env, q, email, code) => {
  const row = (await q(`admin_otps?email=eq.${enc(email)}&select=*`))[0];
  if (!row || !/^\d{6}$/.test(code)) return false;
  if (Date.parse(row.expires_at) < Date.now() || row.tries >= 5) { await q(`admin_otps?email=eq.${enc(email)}`, 'DELETE', undefined, 'return=minimal'); return false; }
  if (!same(row.code_hash, await sha(`${email}:${code}:${env.OTP_PEPPER}`))) { await q(`admin_otps?email=eq.${enc(email)}`, 'PATCH', { tries: row.tries + 1 }, 'return=minimal'); return false; }
  await q(`admin_otps?email=eq.${enc(email)}`, 'DELETE', undefined, 'return=minimal'); return true;
};

const putPhoto = async (env, id, dataUrl) => {   // WebP, ~20-50 KB, shrunk in the browser; stored in Supabase Storage
  const m = /^data:image\/(webp|jpeg|png);base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl || ''));
  if (!m || m[2].length > 280000) return { err: 'Picture is too large or the wrong format.' };
  const ext = m[1] === 'jpeg' ? 'jpg' : m[1], bin = Uint8Array.from(atob(m[2]), (c) => c.charCodeAt(0));
  const up = () => fetch(`${env.SUPABASE_URL}/storage/v1/object/nominees/${id}.${ext}`, { method: 'POST', headers: { ...svc(env), 'Content-Type': `image/${m[1]}`, 'x-upsert': 'true' }, body: bin });
  let r = await up();
  if (!r.ok && (r.status === 404 || r.status === 400)) {   // bucket missing: create it once, then retry
    await fetch(`${env.SUPABASE_URL}/storage/v1/bucket`, { method: 'POST', headers: { ...svc(env), 'Content-Type': 'application/json' }, body: JSON.stringify({ id: 'nominees', name: 'nominees', public: true }) });
    r = await up();
  }
  return r.ok ? { url: `${env.SUPABASE_URL}/storage/v1/object/public/nominees/${id}.${ext}?v=${Date.now()}` } : { err: `Photo storage error ${r.status}. Check the nominees bucket in Supabase Storage.` };
};
const pid = (x) => Number(String(x).replace(/^PH-/, ''));

export async function onRequestPost({ request, env }) {
  try {
    for (const k of ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY', 'RESEND_API_KEY', 'OTP_FROM', 'OTP_PEPPER'])
      if (!env[k]) return J({ error: `Server not configured (missing ${k}).` }, 500);
    let b; try { b = await request.json(); } catch { return J({ error: 'Invalid request.' }, 400); }
    const a = String(b.action || ''), ip = request.headers.get('CF-Connecting-IP') || '', q = mkdb(env);
    const email = String(b.email || '').trim().toLowerCase();
    const log = (actor, action, detail) => q('audit_log', 'POST', { actor, action, detail: detail || {}, ip }, 'return=minimal').catch((e) => console.error('audit', e.message));

    // ---------- public actions (no session yet) ----------
    if (a === 'otp_send') return otpSend(env, q, email, ip);
    if (a === 'enroll') return enroll(env, q, b, email, log);
    if (a === 'login') return login(env, q, b, email, log);

    // ---------- everything else needs a verified session AND an active, enrolled admin row ----------
    const auth = request.headers.get('Authorization') || '';
    if (!/^Bearer\s+\S+$/.test(auth)) return J({ error: 'Sign in first.' }, 401);
    const ur = await fetch(env.SUPABASE_URL + '/auth/v1/user', { headers: { Authorization: auth, apikey: env.SUPABASE_ANON_KEY } });
    if (!ur.ok) return J({ error: 'Session expired. Sign in again.' }, 401);
    const user = await ur.json();
    const em = String(user.email || '').toLowerCase();
    if (!em || !user.email_confirmed_at) return J({ error: 'Email not verified.' }, 403);
    const me = (await q(`admins?email=eq.${enc(em)}&select=*`))[0];
    if (!me || !me.active) return J({ error: 'This account is not an admin.' }, 403);
    if (!me.enrolled_at) return J({ error: 'Finish registration first: use "First time or forgot password" and enter the emailed code.' }, 403);
    const via = (user.app_metadata && user.app_metadata.provider) || 'password';
    const need = (r) => RANK[me.role] >= RANK[r];
    const deny = () => J({ error: 'Your role cannot do that.' }, 403);
    // Second factor: admin and super sessions that did not come from Google must be verified once with an emailed code.
    // This makes a guessed password useless on its own, even if someone bypasses /api/admin and hits Supabase directly.
    const sid = sidOf(auth), needV = me.role !== 'gate' && via !== 'google';
    const verified = !needV || (!!sid && (await q(`admin_sessions?sid=eq.${enc(sid)}&email=eq.${enc(em)}&select=sid`)).length > 0);
    if (a === 'verify_send') return otpSend(env, q, em, ip);
    if (a === 'verify') {
      if (!sid || !(await codeOk(env, q, em, String(b.code || '').trim()))) return J({ error: 'That code is wrong or expired.' }, 400);
      await q('admin_sessions?on_conflict=sid', 'POST', { sid, email: em }, 'resolution=ignore-duplicates,return=minimal');
      await log(em, 'session_verified', {}); return J({ ok: true });
    }
    if (a !== 'me' && !verified) return J({ error: 'Verify this sign-in with the emailed code.', verify: true }, 403);

    switch (a) {
      case 'me':
        if (b.fresh) await log(em, 'session_start', { via });
        return J({ email: em, role: me.role, via, verify: !verified });

      case 'overview': {
        if (!need('gate')) return deny();
        const o = await q('rpc/admin_overview', 'POST', {});
        const h = o.hourly.map((x) => x.n), avg = h.reduce((s, n) => s + n, 0) / 24;   // true 24h average, quiet hours count as zero
        o.hourly = o.hourly.map((x) => ({ ...x, spike: x.n >= 30 && x.n > 3 * avg }));   // flag: 30+ votes AND 3x the 24h hourly average
        o.people_in = (await all(q, 'tickets?guests_in=gt.0&select=guests_in')).reduce((s, r) => s + r.guests_in, 0);
        if (me.role === 'gate') return J({ capacity: o.capacity, people_in: o.people_in, tiers: o.tiers.map((t) => ({ name: t.name, sold: t.sold, guests: t.guests })), by_category: [], hourly: [], votes_total: 0, voters: 0 });   // gate staff never see money or votes
        return J(o);
      }
      case 'settings_get': return J((await q('settings?id=eq.true&select=vote_open,vote_close,notice,capacity'))[0]);
      case 'settings_set': {
        if (!need('super')) return deny();
        const p = {};
        if (b.vote_open || b.vote_close) {
          const o = Date.parse(b.vote_open), c = Date.parse(b.vote_close);
          if (!(o < c)) return J({ error: 'Closing time must be after opening time.' }, 400);
          p.vote_open = new Date(o).toISOString(); p.vote_close = new Date(c).toISOString();
        }
        if ('notice' in b) { const n = String(b.notice || '').trim().slice(0, 280); p.notice = n || null; }
        if ('capacity' in b) { const c = Number(b.capacity); if (!Number.isInteger(c) || c < 0 || c > 100000) return J({ error: 'Invalid capacity.' }, 400); p.capacity = c; }
        if (!Object.keys(p).length) return J({ error: 'Nothing to change.' }, 400);
        await q('settings?id=eq.true', 'PATCH', p, 'return=minimal'); await log(em, 'settings_set', p);
        return J({ ok: true });
      }
      case 'nominees_list': if (!need('admin')) return deny(); return J(await q('nominees?select=id,category_id,name,biz,active&order=category_id,name'));
      case 'nominee_add': {
        if (!need('admin')) return deny();
        const category_id = Number(b.category_id), name = String(b.name || '').trim(), biz = String(b.biz || '').trim(), photo_url = String(b.photo_url || '').trim();
        if (!Number.isInteger(category_id) || category_id < 1 || name.length < 2 || name.length > 120 || biz.length > 120 || (photo_url && !/^https:\/\/\S{4,480}$/.test(photo_url))) return J({ error: 'Check the category, name and photo link (must start with https://).' }, 400);
        const r = await q('nominees', 'POST', { category_id, name, biz: biz || null, photo_url: photo_url || null });
        await log(em, 'nominee_add', { id: r[0].id, name, category_id }); return J({ ok: true });
      }
      case 'nominee_toggle': {
        if (!need('admin')) return deny();
        if (!UUID.test(String(b.id)) || typeof b.active !== 'boolean') return J({ error: 'Invalid request.' }, 400);
        await q(`nominees?id=eq.${b.id}`, 'PATCH', { active: b.active }, 'return=minimal'); await log(em, 'nominee_toggle', { id: b.id, active: b.active }); return J({ ok: true });
      }
      case 'category_pause': {
        if (!need('admin')) return deny();
        const id = Number(b.id), paused = b.paused ? 1 : 0;
        if (!Number.isInteger(id) || id < 1) return J({ error: 'Invalid category.' }, 400);
        await q(`categories?id=eq.${id}`, 'PATCH', { paused }, 'return=minimal'); await log(em, 'category_pause', { id, paused }); return J({ ok: true });
      }
      case 'export': {
        if (!need('admin')) return deny();
        const rows = b.what === 'votes' ? await all(q, 'vote_results?select=category,nominee,biz,votes')
          : await all(q, 'tickets?select=reference,tier_id,buyer_name,phone,email,amount_kobo,seat,revoked,guests_in,checked_in_at,created_at&order=created_at,reference');
        await log(em, 'export', { what: b.what === 'votes' ? 'votes' : 'tickets', rows: rows.length });
        return J({ filename: `rae-${b.what === 'votes' ? 'votes' : 'tickets'}-${new Date().toISOString().slice(0, 10)}.csv`, csv: toCsv(rows) });
      }
      case 'checkin': {
        if (!need('gate')) return deny();
        let tok = (String(b.token || '').match(/[0-9a-f]{64}/i) || [''])[0];
        const ref = String(b.reference || '').trim();   // manual fallback when a QR will not scan
        if (!tok && /^[A-Za-z0-9._-]{6,100}$/.test(ref)) tok = ((await q(`tickets?reference=eq.${enc(ref)}&select=qr_token`))[0] || {}).qr_token || '';
        if (!TOKEN.test(tok)) return J({ result: 'INVALID' });
        const r = (await q('rpc/checkin', 'POST', { p_token: tok.toLowerCase(), p_all: !!b.all }))[0];
        await log(em, 'checkin', { result: r.result, buyer: r.buyer_name, tier: r.tier_id }); return J(r);
      }
      case 'live': {   // ONE call returns everything a screen needs, to stay far inside the free request limits
        const g = me.role === 'gate', t = me.role === 'ticketing', ad = need('admin'), su = need('super');
        const [o, st, nom, res, reqs, team, aud, sales] = await Promise.all([
          t ? null : q('rpc/admin_overview', 'POST', {}),
          q('settings?id=eq.true&select=vote_open,vote_close'),
          ad ? q('nominees?select=id,category_id,name,biz,active,status,placement,photo_url&order=category_id,name&limit=1000') : [],
          ad ? q('vote_results?select=category,nominee,votes&limit=1000') : [],
          (t || ad) ? q('pickup_requests?select=id,buyer_name,tier_id,loc,st,created_at&order=id.desc&limit=300') : [],
          su ? q('admins?select=email,role,active&order=created_at') : [],
          ad ? q('audit_log?select=at,actor,action&order=id.desc&limit=200') : [],
          ad ? q('tickets?select=buyer_name,tier_id,created_at&order=created_at.desc&limit=6') : [],
        ]);
        const out = { open: true, nominees: [], reqs: [], team: [], aud: [], sales: [] };
        const now = Date.now(), s0 = st[0] || {};
        out.open = !(s0.vote_open && now < Date.parse(s0.vote_open)) && !(s0.vote_close && now > Date.parse(s0.vote_close));
        if (o) {
          const h = o.hourly.map((x) => x.n), avg = h.reduce((a, n) => a + n, 0) / 24;
          o.hourly = o.hourly.map((x) => ({ ...x, spike: x.n >= 30 && x.n > 3 * avg }));
          o.people_in = (await all(q, 'tickets?guests_in=gt.0&select=guests_in')).reduce((a, r) => a + r.guests_in, 0);
          Object.assign(out, g ? { tiers: o.tiers.map((x) => ({ id: x.id, sold: x.sold, guests: x.guests })), people_in: o.people_in } : o);
        }
        if (ad) {
          const cn = Object.fromEntries((o.by_category || []).map((c) => [c.id, c.name])), vv = {};
          res.forEach((r) => { vv[r.category + '|' + r.nominee] = r.votes; });
          out.nominees = nom.filter((n) => n.active !== false).map((n) => ({ ...n, v: vv[cn[n.category_id] + '|' + n.name] || 0 }));
          out.aud = aud.slice(0, 40); out.sales = sales;
        }
        out.reqs = reqs.map((r) => ({ id: 'PH-' + r.id, name: r.buyer_name, tier: r.tier_id, loc: r.loc, st: r.st, at: r.created_at }));
        if (su) { const cnt = {}; aud.forEach((a) => { cnt[a.actor] = (cnt[a.actor] || 0) + 1; }); out.team = team.map((x) => ({ email: x.email, role: x.role, on: x.active, n: cnt[x.email] || 0 })); }
        return J(out);
      }
      case 'nominee_new': {
        if (!need('admin')) return deny();
        const category_id = Number(b.category_id), name = String(b.name || '').trim(), biz = String(b.biz || '').trim();
        if (!Number.isInteger(category_id) || category_id < 1 || name.length < 2 || name.length > 120 || biz.length > 120) return J({ error: 'Check the category and name.' }, 400);
        const pl = ['cat', 'home', 'both'].includes(b.placement) ? b.placement : 'cat';
        const r = (await q('nominees', 'POST', { category_id, name, biz: biz || null, placement: pl, status: 'approved' }))[0];
        if (b.photo) { const u = await putPhoto(env, r.id, b.photo); if (u.url) await q(`nominees?id=eq.${r.id}`, 'PATCH', { photo_url: u.url }, 'return=minimal'); }
        await log(em, 'nominee_add', { id: r.id, name }); return J({ ok: true });
      }
      case 'nominee_review': {
        if (!need('admin')) return deny();
        const ids = (Array.isArray(b.ids) ? b.ids : []).map(String).filter((n) => UUID.test(n)).slice(0, 200);
        if (!ids.length) return J({ error: 'Nothing selected.' }, 400);
        const p = b.ok ? { status: 'approved' } : { status: 'rejected' };
        if (b.ok && ['cat', 'home', 'both'].includes(b.placement)) p.placement = b.placement;
        await q(`nominees?id=in.(${ids.join(',')})&status=eq.pending`, 'PATCH', p, 'return=minimal');
        await log(em, b.ok ? 'nominees_approved' : 'nominees_rejected', { ids }); return J({ ok: true });
      }
      case 'nominee_photo': {
        if (!need('admin')) return deny();
        const id = String(b.id); if (!UUID.test(id)) return J({ error: 'Bad nominee.' }, 400);
        const u = await putPhoto(env, id, b.data); if (!u.url) return J({ error: u.err }, 400);
        await q(`nominees?id=eq.${id}`, 'PATCH', { photo_url: u.url }, 'return=minimal'); await log(em, 'nominee_photo', { id }); return J({ ok: true });
      }
      case 'voting_toggle': {
        if (!need('admin')) return deny();
        const n = Date.now(), cur = (await q('settings?id=eq.true&select=vote_close'))[0] || {};
        const p = b.open ? { vote_open: new Date(n - 6e4).toISOString(), vote_close: new Date(Math.max(Date.parse(cur.vote_close) || 0, n + 30 * 864e5)).toISOString() } : { vote_close: new Date(n).toISOString() };
        await q('settings?id=eq.true', 'PATCH', p, 'return=minimal'); await log(em, b.open ? 'voting_opened' : 'voting_closed', {}); return J({ ok: true });
      }
      case 'pickup_set': {
        if (!need('ticketing')) return deny();
        const ids = (Array.isArray(b.ids) ? b.ids : []).map(pid).filter((n) => Number.isInteger(n) && n > 0).slice(0, 300);
        if (!ids.length) return J({ error: 'Nothing selected.' }, 400);
        await q(`pickup_requests?id=in.(${ids.join(',')})&st=eq.0`, 'PATCH', { st: 1, updated_at: new Date().toISOString(), handled_by: em }, 'return=minimal');
        await log(em, 'pickup_ready', { ids }); return J({ ok: true });
      }
      case 'pickup_confirm': {
        if (!need('ticketing')) return deny();
        const id = pid(b.id), r = Number.isInteger(id) ? (await q(`pickup_requests?id=eq.${id}&select=code,st`))[0] : null;
        if (!r || r.st !== 1) return J({ error: 'This request is not ready for handover.' }, 400);
        if (!same(String(r.code), String(b.code || '').trim())) return J({ error: 'Code does not match. Check the buyer’s ticket page.' }, 400);
        await q(`pickup_requests?id=eq.${id}`, 'PATCH', { st: 2, updated_at: new Date().toISOString(), handled_by: em }, 'return=minimal');
        await log(em, 'pickup_handover', { id }); return J({ ok: true });
      }
      case 'ticket_get': {
        if (!need('admin')) return deny();
        const ref = String(b.reference || '').trim();
        if (!/^[A-Za-z0-9._-]{6,100}$/.test(ref)) return J({ error: 'Enter a valid payment reference.' }, 400);
        const r = (await q(`tickets?reference=eq.${enc(ref)}&select=reference,tier_id,buyer_name,phone,email,seat,revoked,guests_in,checked_in_at`))[0];
        return r ? J(r) : J({ error: 'No ticket with that reference.' }, 404);
      }
      case 'ticket_update': {
        const reference = String(b.reference || '').trim();
        if (!/^[A-Za-z0-9._-]{6,100}$/.test(reference)) return J({ error: 'Enter a valid payment reference.' }, 400);
        const p = {};
        if ('seat' in b) { if (!need('admin')) return deny(); p.seat = String(b.seat || '').trim().slice(0, 40) || null; }
        if ('revoked' in b) { if (!need('super')) return deny(); p.revoked = !!b.revoked; }
        if (!Object.keys(p).length) return J({ error: 'Nothing to change.' }, 400);
        const r = await q(`tickets?reference=eq.${enc(reference)}`, 'PATCH', p);
        if (!r.length) return J({ error: 'No ticket with that reference.' }, 404);
        await log(em, 'ticket_update', { reference, ...p }); return J({ ok: true });
      }
      case 'admins_list': if (!need('super')) return deny(); return J(await q('admins?select=email,role,active,enrolled_at,locked_until&order=created_at'));
      case 'admin_add': {
        if (!need('super')) return deny();
        const role = String(b.role);
        if (!EMAIL.test(email) || email.length > 254 || !RANK[role]) return J({ error: 'Enter a valid email and role.' }, 400);
        await q('admins?on_conflict=email', 'POST', { email, role, created_by: em }, 'resolution=ignore-duplicates,return=minimal');
        await log(em, 'admin_add', { email, role }); return J({ ok: true });
      }
      case 'admin_set': {
        if (!need('super')) return deny();
        if (email === em) return J({ error: 'You cannot change your own access.' }, 400);
        const p = {}; if (typeof b.active === 'boolean') p.active = b.active; if (RANK[b.role]) p.role = b.role;
        if (!Object.keys(p).length) return J({ error: 'Nothing to change.' }, 400);
        await q(`admins?email=eq.${enc(email)}`, 'PATCH', p, 'return=minimal'); await log(em, 'admin_set', { email, ...p }); return J({ ok: true });
      }
      case 'audit_list': if (!need('super')) return deny(); return J(await q('audit_log?select=at,actor,action,detail&order=id.desc&limit=60'));
      default: return J({ error: 'Unknown action.' }, 400);
    }
  } catch (e) {
    console.error('admin error', e && e.message);
    return J({ error: 'Server error. Please try again.' }, 500);
  }
}

async function otpSend(env, q, email, ip) {
  const OK = J({ ok: true, message: 'If this email is registered as an admin, a code is on its way. It expires in 10 minutes.' });
  if (!EMAIL.test(email) || email.length > 254) return OK;
  const ad = (await q(`admins?email=eq.${enc(email)}&active=eq.true&select=email,enrolled_at`))[0];
  if (!ad) return OK;                                                            // non-admins get the same answer and no email
  const now = Date.now();
  const day = await q(`admin_otp_log?created_at=gte.${new Date(now - 864e5).toISOString()}&select=email,ip,created_at`);
  const age = (r) => now - Date.parse(r.created_at), mine = day.filter((r) => r.email === email);
  if (day.length >= DAILY_CAP) return J({ error: 'Daily code limit reached. Try again tomorrow or ask the super admin.' }, 429);
  if (mine.some((r) => age(r) < 60e3)) return J({ error: 'Wait a minute before asking for another code.' }, 429);
  if (mine.filter((r) => age(r) < 36e5).length >= 3) return J({ error: 'Too many codes this hour. Try again later.' }, 429);
  if (ip && day.filter((r) => r.ip === ip && age(r) < 36e5).length >= 10) return J({ error: 'Too many requests. Try again later.' }, 429);
  const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
  await q('admin_otps?on_conflict=email', 'POST', { email, code_hash: await sha(`${email}:${code}:${env.OTP_PEPPER}`), expires_at: new Date(now + 600e3).toISOString(), tries: 0 }, 'resolution=merge-duplicates,return=minimal');
  await q('admin_otp_log', 'POST', { email, ip }, 'return=minimal');
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST', headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.OTP_FROM, to: [email], subject: 'Your RAE admin code: ' + code, text: `Your RAE Awards admin code is ${code}.\nIt expires in 10 minutes. If you did not ask for it, ignore this email.` })
  });
  if (!r.ok) { console.error('resend', r.status, await r.text()); return J({ error: 'Could not send the email. Try again shortly.' }, 502); }
  return OK;
}

async function enroll(env, q, b, email, log) {
  const code = String(b.code || '').trim(), pw = String(b.password || '');
  const bad = J({ error: 'That code is wrong or expired. Request a new one.' }, 400);
  if (!EMAIL.test(email) || !/^\d{6}$/.test(code)) return J({ error: 'Enter your email and the 6-digit code.' }, 400);
  if (pw.length < 10 || pw.length > 72 || pw.toLowerCase().includes(email.split('@')[0].toLowerCase())) return J({ error: 'Use a password of 10 to 72 characters that does not contain your email name.' }, 400);
  const ad = (await q(`admins?email=eq.${enc(email)}&active=eq.true&select=email,enrolled_at`))[0];
  const row = ad && (await q(`admin_otps?email=eq.${enc(email)}&select=*`))[0];
  if (!row) return bad;
  if (Date.parse(row.expires_at) < Date.now() || row.tries >= 5) { await q(`admin_otps?email=eq.${enc(email)}`, 'DELETE', undefined, 'return=minimal'); return bad; }
  if (!same(row.code_hash, await sha(`${email}:${code}:${env.OTP_PEPPER}`))) { await q(`admin_otps?email=eq.${enc(email)}`, 'PATCH', { tries: row.tries + 1 }, 'return=minimal'); return bad; }
  // Code is correct: create or update the Supabase login (email pre-confirmed, so Supabase sends no email)
  const uid = await q('rpc/auth_uid_by_email', 'POST', { p: email });
  const url = env.SUPABASE_URL + '/auth/v1/admin/users' + (uid ? '/' + uid : '');
  const r = await fetch(url, { method: uid ? 'PUT' : 'POST', headers: { ...svc(env), 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: pw, email_confirm: true }) });
  if (!r.ok) { console.error('auth admin', r.status, await r.text()); return J({ error: 'Could not set the password. Try a stronger one.' }, 400); }
  await q(`admin_otps?email=eq.${enc(email)}`, 'DELETE', undefined, 'return=minimal');
  await q(`admins?email=eq.${enc(email)}`, 'PATCH', { enrolled_at: ad.enrolled_at || new Date().toISOString(), failed_attempts: 0, locked_until: null }, 'return=minimal');
  await log(email, ad.enrolled_at ? 'password_reset' : 'enrolled', {});
  return J({ ok: true, message: 'Done. You can now sign in with your password or Google.' });
}

async function login(env, q, b, email, log) {
  const pw = String(b.password || '');
  const bad = J({ error: 'Wrong email or password.' }, 401);
  if (!EMAIL.test(email) || !pw) return bad;
  const ad = (await q(`admins?email=eq.${enc(email)}&select=*`))[0];
  if (!ad || !ad.active) return bad;
  if (!ad.enrolled_at) return J({ error: 'Finish registration first: tap "First time or forgot password".' }, 403);
  if (ad.locked_until && Date.parse(ad.locked_until) > Date.now()) return J({ error: 'Too many wrong attempts. Try again in 15 minutes, or reset your password.' }, 429);
  const r = await fetch(env.SUPABASE_URL + '/auth/v1/token?grant_type=password', { method: 'POST', headers: { apikey: env.SUPABASE_ANON_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: pw }) });
  if (!r.ok) {
    const n = ad.failed_attempts + 1;
    await q(`admins?email=eq.${enc(email)}`, 'PATCH', n >= 5 ? { failed_attempts: 0, locked_until: new Date(Date.now() + 900e3).toISOString() } : { failed_attempts: n }, 'return=minimal');
    await log(email, 'login_failed', { n });
    return bad;
  }
  const s = await r.json();
  await q(`admins?email=eq.${enc(email)}`, 'PATCH', { failed_attempts: 0, locked_until: null }, 'return=minimal');
  await log(email, 'session_start', { via: 'password' });
  return J({ access_token: s.access_token, refresh_token: s.refresh_token, expires_in: s.expires_in });
}
