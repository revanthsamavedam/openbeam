// Hand-rolled equivalent of @vercel/blob/client handleUpload (token issuing
// only — no upload-completed callback is registered, so drops register
// themselves through /api/register). Token format mirrors the SDK exactly:
//   payload  = base64(JSON {maximumSizeInBytes, tokenPayload, pathname, validUntil})
//   sig      = HMAC-SHA256 hex of payload, keyed by the read-write token
//   token    = vercel_blob_client_<storeId>_<base64(sig + "." + payload)>
import { createHmac } from 'node:crypto';

const MAX_DROP_BYTES = 1073741824; // 1 GB

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
  let body;
  try {
    body = await readJson(req);
  } catch {
    return send(res, 400, { error: 'bad request' });
  }
  try {
    if (body.type === 'blob.generate-client-token') {
      const { pathname, clientPayload } = body.payload || {};
      if (!pathname || !pathname.startsWith('drops/')) {
        throw new Error('unexpected upload path');
      }
      const rw = process.env.BLOB_READ_WRITE_TOKEN || '';
      const storeId = rw.split('_')[3] || '';
      if (!storeId) throw new Error('storage not configured');
      const payloadObj = {
        maximumSizeInBytes: MAX_DROP_BYTES,
        tokenPayload: clientPayload ?? '',
        pathname,
        validUntil: Date.now() + 3600_000,
      };
      const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64');
      const sig = createHmac('sha256', rw).update(payload).digest('hex');
      const clientToken =
        `vercel_blob_client_${storeId}_${Buffer.from(sig + '.' + payload).toString('base64')}`;
      return send(res, 200, { type: body.type, clientToken });
    }
    if (body.type === 'blob.upload-completed') {
      return send(res, 200, { type: body.type, response: 'ok' });
    }
    throw new Error('invalid event type');
  } catch (e) {
    return send(res, 400, { error: String((e && e.message) || e) });
  }
}
