// Register a drop: validate the client's report and store its metadata as a
// small JSON blob via the Blob HTTP API (no SDK dependency).
const CODE_RE = /^[A-HJ-NP-Z2-9]{6}$/;
const MAX_DROP_BYTES = 1073741824; // 1 GB
const TTL_MS = 24 * 60 * 60 * 1000; // drops live 24 hours
const API = 'https://blob.vercel-storage.com';

function send(res, status, obj) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(obj));
}

async function readJson(req) {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  return JSON.parse(raw);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return send(res, 405, { ok: false, error: 'POST only' });
  }
  let m;
  try {
    m = await readJson(req);
  } catch {
    return send(res, 400, { ok: false, error: 'bad request' });
  }
  const code = String(m.code || '').toUpperCase();
  const url = String(m.url || '');
  const filename = String(m.filename || 'file').slice(0, 200);
  const size = Number(m.size || 0);
  const sha256 = String(m.sha256 || '');
  const mime = String(m.mime || 'application/octet-stream').slice(0, 128);

  if (!CODE_RE.test(code)) {
    return send(res, 400, { ok: false, error: 'bad code' });
  }
  let host = '';
  try { host = new URL(url).hostname; } catch { /* invalid */ }
  if (!host.endsWith('.blob.vercel-storage.com')) {
    return send(res, 400, { ok: false, error: 'bad file url' });
  }
  if (!(size > 0 && size <= MAX_DROP_BYTES)) {
    return send(res, 400, { ok: false, error: 'bad size' });
  }
  if (sha256 && !/^[0-9a-f]{64}$/.test(sha256)) {
    return send(res, 400, { ok: false, error: 'bad sha256' });
  }

  const token = process.env.BLOB_READ_WRITE_TOKEN || '';
  if (!token) {
    return send(res, 500, { ok: false, error: 'storage not configured' });
  }
  const meta = {
    code, url, filename, size, sha256, mime,
    createdAt: Date.now(),
    expiresAt: Date.now() + TTL_MS,
  };
  const body = JSON.stringify(meta);
  const res2 = await fetch(`${API}/?pathname=${encodeURIComponent(`drops-meta/${code}.json`)}`, {
    method: 'PUT',
    headers: {
      authorization: `Bearer ${token}`,
      'x-api-version': '13',
      'x-vercel-blob-access': 'public',
      'x-content-type': 'application/json',
      'x-add-random-suffix': '0',
      'x-content-length': String(Buffer.byteLength(body)),
    },
    body,
  });
  if (!res2.ok) {
    return send(res, 502, { ok: false, error: `storage write failed (${res2.status})` });
  }
  return send(res, 200, { ok: true, code, expiresAt: meta.expiresAt });
}
