// ============================================================
// Hacktales CFP API — Mailchimp only.
// This service has ONE job: receive a subscriber and push it to
// Mailchimp. It serves no HTML and knows nothing about the
// landing page (that lives separately on cPanel).
//
// Requires only Node 18+ (built-in fetch & crypto). No npm deps.
//
// Render environment variables:
//   MAILCHIMP_API_KEY      e.g.  abcd1234...-us21
//   MAILCHIMP_AUDIENCE_ID  e.g.  a1b2c3d4e5
// Optional:
//   ALLOWED_ORIGINS        comma-separated list of the exact site origins
//                          allowed to call this API, e.g.
//                          https://hacktales.com,https://www.hacktales.com
//                          (leave unset while testing = allow any origin)
// ============================================================
const http = require('http');
const crypto = require('crypto');

const ALLOWED_TAGS = ['cfp entry', 'stemlab cybersecurity'];
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

function corsHeaders(origin) {
  const h = {
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
  if (origin && (allowedOrigins.length === 0 || allowedOrigins.includes(origin))) {
    h['Access-Control-Allow-Origin'] = origin;
  }
  return h;
}

function sendJSON(res, status, obj, origin) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...corsHeaders(origin) });
  res.end(JSON.stringify(obj));
}

async function subscribe({ name, email, phone, tag }) {
  const memberTag = ALLOWED_TAGS.includes(tag) ? tag : 'cfp entry';

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { status: 400, body: { ok: false, error: 'Invalid email' } };
  }

  const apiKey = process.env.MAILCHIMP_API_KEY;
  const listId = process.env.MAILCHIMP_AUDIENCE_ID;
  if (!apiKey || !listId) {
    console.error('Missing MAILCHIMP_API_KEY or MAILCHIMP_AUDIENCE_ID');
    return { status: 500, body: { ok: false, error: 'Server not configured' } };
  }

  const dc = apiKey.split('-').pop();
  const hash = crypto.createHash('md5').update(email.toLowerCase()).digest('hex');
  const url = `https://${dc}.api.mailchimp.com/3.0/lists/${listId}/members/${hash}`;
  const auth = 'Basic ' + Buffer.from('anystring:' + apiKey).toString('base64');

  // Normalise a Nigerian number to +234 international form, which Mailchimp's
  // phone validators accept.  0803... -> +234803...,  234803... -> +234803...
  let phoneClean = (phone || '').replace(/[^\d+]/g, '');
  if (phoneClean.startsWith('00')) phoneClean = '+' + phoneClean.slice(2);
  if (/^0\d{10}$/.test(phoneClean)) phoneClean = '+234' + phoneClean.slice(1);
  else if (/^234\d{10}$/.test(phoneClean)) phoneClean = '+' + phoneClean;

  // Helper: PUT the member with a given body, return {ok, data}
  async function put(body) {
    const r = await fetch(url, {
      method: 'PUT',
      headers: { 'Authorization': auth, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    let data = {};
    try { data = await r.json(); } catch {}
    return { ok: r.ok, status: r.status, data };
  }
  async function applyTag() {
    await fetch(url + '/tags', {
      method: 'POST',
      headers: { 'Authorization': auth, 'Content-Type': 'application/json' },
      body: JSON.stringify({ tags: [{ name: memberTag, status: 'active' }] })
    }).catch(err => console.warn('Tag call failed:', err.message));
  }

  const base = { email_address: email, status_if_new: 'subscribed', tags: [memberTag] };

  try {
    // Attempt 1: full record with name + phone
    let res = await put({ ...base, merge_fields: { FNAME: name || '', MMERGE2: phone || '', COUNTRY: '-' } });

    // Attempt 2: if rejected, log why and retry WITHOUT merge fields so the
    // lead + tag are never lost (fix the field in Mailchimp to keep the phone).
    if (!res.ok) {
      console.error('Mailchimp error:', res.status, res.data.title, '|', res.data.detail);
      if (Array.isArray(res.data.errors)) {
        res.data.errors.forEach(e => console.error('  field:', e.field, '->', e.message));
      }
      res = await put({ ...base, merge_fields: { COUNTRY: '-' } });
      if (res.ok) {
        await applyTag();
        console.warn('Saved WITHOUT merge fields (phone/name dropped). Fix the MMERGE2 field type in Mailchimp. Email:', email);
        return { status: 200, body: { ok: true, warning: 'saved without merge fields' } };
      }
      console.error('Mailchimp error (retry):', res.status, res.data.title, '|', res.data.detail);
      return { status: 502, body: { ok: false, error: res.data.title || 'Mailchimp error' } };
    }

    await applyTag();
    console.log('Subscribed:', email, '| tag:', memberTag);
    return { status: 200, body: { ok: true } };
  } catch (err) {
    console.error('Mailchimp request failed:', err.message);
    return { status: 502, body: { ok: false, error: 'Mailchimp unreachable' } };
  }
}

const server = http.createServer((req, res) => {
  const origin = req.headers.origin;
  const { pathname } = new URL(req.url, `http://${req.headers.host}`);

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders(origin));
    return res.end();
  }

  // Diagnostics — visiting the service URL in a browser confirms it's live
  if (req.method === 'GET' && pathname === '/') {
    return sendJSON(res, 200, {
      service: 'hacktales-cfp-api',
      status: 'running',
      mailchimp_configured: Boolean(process.env.MAILCHIMP_API_KEY && process.env.MAILCHIMP_AUDIENCE_ID),
      cors: allowedOrigins.length ? allowedOrigins : 'all origins (testing mode)'
    }, origin);
  }

  // Warm-up ping (frontend calls this on page load to wake a sleeping instance)
  if (req.method === 'GET' && pathname === '/health') {
    return sendJSON(res, 200, { ok: true }, origin);
  }

  // The one real endpoint
  if (req.method === 'POST' && pathname === '/api/subscribe') {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > 1e5) req.destroy(); // guard against oversized bodies
    });
    req.on('end', async () => {
      let payload = {};
      try { payload = JSON.parse(raw || '{}'); }
      catch { return sendJSON(res, 400, { ok: false, error: 'Invalid JSON' }, origin); }
      const result = await subscribe(payload);
      sendJSON(res, result.status, result.body, origin);
    });
    return;
  }

  sendJSON(res, 404, { ok: false, error: 'Not found' }, origin);
});

const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`hacktales-cfp-api listening on :${port}`));