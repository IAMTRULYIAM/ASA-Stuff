/**
 * Cloudflare Pages Function - RP Calendar State
 * Handles GET (read) and POST (write) for the current RP date.
 *
 * Requires a KV namespace binding named RP_STATE.
 * See README.md for setup instructions.
 */

const CORS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export async function onRequest({ request, env }) {
  const method = request.method;

  /* Preflight */
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  /* Read current state */
  if (method === 'GET') {
    const saved = await env.RP_STATE.get('current');
    return new Response(saved || '{}', { headers: CORS });
  }

  /* Write new state (GM publish) */
  if (method === 'POST') {
    let body;
    try {
      body = await request.text();
      JSON.parse(body); /* validate JSON before storing */
    } catch {
      return new Response('{"error":"invalid body"}', { status: 400, headers: CORS });
    }
    await env.RP_STATE.put('current', body);
    return new Response('{"ok":true}', { headers: CORS });
  }

  return new Response('{"error":"method not allowed"}', { status: 405, headers: CORS });
}
