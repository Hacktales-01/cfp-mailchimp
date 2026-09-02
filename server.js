// Hacktales CFP landing — static site + Mailchimp subscribe endpoint.
// Secrets live in Render environment variables, never in this repo:
//   MAILCHIMP_API_KEY      e.g. abc123...-us21   (Account -> Extras -> API keys)
//   MAILCHIMP_AUDIENCE_ID  e.g. a1b2c3d4e5      (Audience -> Settings -> Audience name and defaults)
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());

// ---- CORS: allow the cPanel-hosted frontend to call this API ----
// Set ALLOWED_ORIGINS in Render env as a comma-separated list, e.g.:
//   https://hacktales.com,https://www.hacktales.com,https://cfp.hacktales.com
const allowed = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && (allowed.length === 0 || allowed.includes(origin))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Lightweight endpoint the frontend pings on page load to wake a sleeping
// free-tier service before the visitor submits the form.
app.get('/health', (req, res) => res.json({ ok: true }));

app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/subscribe', async (req, res) => {
  const { name, email, phone } = req.body || {};
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ ok: false, error: 'Invalid email' });
  }

  const apiKey = process.env.MAILCHIMP_API_KEY;
  const listId = process.env.MAILCHIMP_AUDIENCE_ID;
  if (!apiKey || !listId) {
    console.error('Mailchimp env vars missing');
    return res.status(500).json({ ok: false, error: 'Server not configured' });
  }

  const dc = apiKey.split('-').pop();                       // datacenter from key suffix
  const hash = crypto.createHash('md5').update(email.toLowerCase()).digest('hex');
  const url = `https://${dc}.api.mailchimp.com/3.0/lists/${listId}/members/${hash}`;

  try {
    const r = await fetch(url, {
      method: 'PUT',                                        // upsert: add or update
      headers: {
        'Authorization': 'Basic ' + Buffer.from('anystring:' + apiKey).toString('base64'),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email_address: email,
        status_if_new: 'subscribed',
        merge_fields: { FNAME: name || '', PHONE: phone || '' },
        tags: ['cfp entry']
      })
    });
    const data = await r.json();
    if (!r.ok) {
      console.error('Mailchimp error:', data.title, data.detail);
      return res.status(502).json({ ok: false, error: data.title || 'Mailchimp error' });
    }
    // PUT upserts don't re-apply tags to already-existing members — set the tag explicitly
    await fetch(url + '/tags', {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from('anystring:' + apiKey).toString('base64'),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ tags: [{ name: 'cfp entry', status: 'active' }] })
    }).catch(err => console.warn('Tag call failed:', err.message));

    return res.json({ ok: true });
  } catch (err) {
    console.error('Mailchimp request failed:', err.message);
    return res.status(502).json({ ok: false, error: 'Mailchimp unreachable' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`CFP site running on :${port}`));
