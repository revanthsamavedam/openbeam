// Resolve a drop code to its file via the Blob HTTP API (no SDK dependency).
// Expired drops delete themselves lazily on first lookup after expiry.
const CODE_RE = /^[A-HJ-NP-Z2-9]{6}$/;
const API = 'https://blob.vercel-storage.com';

function send(res, status, obj) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(obj));
}

export default async function handler(req, res) {
  const code = (new URL(req.url, 'http://localhost').searchParams.get('code') || '').toUpperCase();
  if (!CODE_RE.test(code)) {
    return send(res, 400, { ok: false, error: 'bad code' });
  }
  const token = process.env.BLOB_READ_WRITE_TOKEN || '';
  if (!token) {
    return send(res, 500, { ok: false, error: 'storage not configured' });
  }
  const headers = { authorization: `Bearer ${token}`, 'x-api-version': '13' };
  const listRes = await fetch(
    `${API}?prefix=${encodeURIComponent(`drops-meta/${code}.json`)}&limit=1`,
    { headers });
  if (!listRes.ok) {
    return send(res, 502, { ok: false, error: `storage lookup failed (${listRes.status})` });
  }
  const data = await listRes.json();
  const blobs = data.blobs || [];
  if (!blobs.length) {
    return send(res, 404, { ok: false, error: 'no drop with that code' });
  }
  const metaUrl = blobs[0].url;
  const metaRes = await fetch(metaUrl);
  if (!metaRes.ok) {
    return send(res, 502, { ok: false, error: 'drop metadata unreadable' });
  }
  const meta = await metaRes.json();
  if (Date.now() > meta.expiresAt) {
    try {
      await fetch(`${API}/delete`, {
        method: 'POST',
        headers: { ...headers, 'content-type': 'application/json' },
        body: JSON.stringify({ urls: [meta.url, metaUrl] }),
      });
    } catch { /* best effort */ }
    return send(res, 410, { ok: false, error: 'this drop has expired' });
  }
  return send(res, 200, {
    ok: true,
    code: meta.code,
    filename: meta.filename,
    size: meta.size,
    sha256: meta.sha256,
    mime: meta.mime,
    url: meta.url,
    expiresAt: meta.expiresAt,
  });
}
