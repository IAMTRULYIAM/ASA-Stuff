// Cloudflare Pages Function: /api/characters
// Bind a KV namespace to this Pages project. Any of the names below will be picked up.

function getKV(env) {
  return env.ASA_KV || env.KV || env.CHARACTERS || env.ASA_CHARACTERS || null;
}

const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type'
};

function json(body, status) {
  return new Response(JSON.stringify(body), { status: status || 200, headers: JSON_HEADERS });
}

function makeId() {
  const t = Date.now().toString(36);
  const r = Math.random().toString(36).slice(2, 8);
  return t + '-' + r;
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: JSON_HEADERS });
}

export async function onRequestPost(context) {
  const kv = getKV(context.env);
  if (!kv) return json({ ok: false, error: 'No KV namespace is bound to this project.' }, 500);

  let body;
  try {
    body = await context.request.json();
  } catch (e) {
    return json({ ok: false, error: 'Body was not valid JSON.' }, 400);
  }

  const name = String(body.name || '').trim().slice(0, 80);
  if (!name) return json({ ok: false, error: 'A character name is required.' }, 400);

  const record = {
    id: makeId(),
    name: name,
    equity: String(body.equity || '').slice(0, 40),
    equityLabel: String(body.equityLabel || '').slice(0, 80),
    discipline: body.discipline ? String(body.discipline).slice(0, 40) : null,
    creature: body.creature ? String(body.creature).slice(0, 60) : null,
    schools: Array.isArray(body.schools) ? body.schools.slice(0, 4).map(function (s) { return String(s).slice(0, 40); }) : [],
    spells: Array.isArray(body.spells) ? body.spells.slice(0, 12).map(function (s) {
      return {
        school: String(s.school || '').slice(0, 40),
        name: String(s.name || '').slice(0, 80),
        level: Number(s.level) || 0
      };
    }) : [],
    created: new Date().toISOString()
  };

  await kv.put('char:' + record.id, JSON.stringify(record));
  return json({ ok: true, id: record.id, record: record });
}

export async function onRequestGet(context) {
  const kv = getKV(context.env);
  if (!kv) return json({ ok: false, error: 'No KV namespace is bound to this project.' }, 500);

  const url = new URL(context.request.url);
  const id = url.searchParams.get('id');

  if (id) {
    const raw = await kv.get('char:' + id);
    if (!raw) return json({ ok: false, error: 'No character with that id.' }, 404);
    return json({ ok: true, record: JSON.parse(raw) });
  }

  const listed = await kv.list({ prefix: 'char:', limit: 1000 });
  const records = [];
  for (const key of listed.keys) {
    const raw = await kv.get(key.name);
    if (raw) {
      try { records.push(JSON.parse(raw)); } catch (e) { /* skip malformed */ }
    }
  }
  records.sort(function (a, b) { return (b.created || '').localeCompare(a.created || ''); });
  return json({ ok: true, count: records.length, records: records });
}
