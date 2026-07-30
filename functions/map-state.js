/* Cloudflare Pages Function backing the character map.
 *
 * Path:     functions/map-state.js   ->   serves /map-state
 * Bindings: MAP_KV          KV namespace
 *           MOD_PASSPHRASE  secret, the moderator passphrase
 *           SESSION_SECRET  secret, random string used to sign moderator tokens
 *
 * The client can no longer hand over a whole board. It sends a batch of small
 * operations and this file decides which ones it is allowed to perform.
 *
 * A character is protected by its lock code or not at all. There is no separate
 * moderator pin: a moderator overrides any code, and that is the whole model.
 *
 * One character per address. See the note above ipFingerprint for what that
 * does and does not achieve.
 *
 * Lock codes. A pawn stores a public salt and a private verifier. The client
 * derives proof = PBKDF2(code, salt, 150k) and sends the proof; the server
 * stores and compares SHA-256(proof). The verifier never leaves the server, so
 * a stolen board gives an attacker nothing to grind offline. The expensive KDF
 * runs on the client, which keeps this inside the Workers CPU budget.
 */

const KEY = 'board';
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

const LIMITS = {
  pawns: 200,
  marks: 300,
  nameLen: 40,
  textLen: 48,
  imgBytes: 500000,
  mapBytes: 4000000,
  boardBytes: 6000000,
  opsPerBatch: 64
};

const PAWN_SIZES = [46, 64, 88, 120];
const MARK_SIZES = [32, 48, 72, 104];
const MARK_ICONS = ['none', 'house', 'city', 'castle', 'ruin', 'tent', 'temple', 'swords',
  'danger', 'anchor', 'mountain', 'tree', 'star', 'flag', 'ring'];

const emptyBoard = () => ({ pawns: {}, marks: {}, map: null, rev: 0 });

/* ── small helpers ─────────────────────────────────────────────── */

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });
}

const te = new TextEncoder();

function hex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += ('0' + bytes[i].toString(16)).slice(-2);
  return s;
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', te.encode(str));
  return hex(new Uint8Array(buf));
}

/* compare without an early exit, so a wrong value cannot be probed byte by byte */
function ctEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey('raw', te.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, te.encode(msg));
  return hex(new Uint8Array(sig));
}

/* A one way fingerprint of the address, salted with the server secret, so KV
 * never holds a raw IP. Rotating SESSION_SECRET frees every slot. */
async function ipFingerprint(env, ip) {
  return (await sha256Hex('ip|' + signingSecret(env) + '|' + ip)).slice(0, 32);
}

function signingSecret(env) {
  return env.SESSION_SECRET || env.MOD_PASSPHRASE || '';
}

async function issueToken(env) {
  const body = 'mod.' + (Date.now() + TOKEN_TTL_MS);
  return body + '.' + await hmacHex(signingSecret(env), body);
}

async function validToken(env, token) {
  if (typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'mod') return false;
  const exp = Number(parts[1]);
  if (!isFinite(exp) || exp < Date.now()) return false;
  return ctEq(await hmacHex(signingSecret(env), 'mod.' + parts[1]), parts[2]);
}

/* Best effort throttle on guessing. Isolates are per colo and short lived, so
 * this slows a casual script and nothing more. Add a Cloudflare rate limiting
 * rule on /map-state for anything stronger. */
const attempts = new Map();
const FAIL_WINDOW_MS = 5 * 60 * 1000;
const FAIL_MAX = 12;

function throttled(ip) {
  const rec = attempts.get(ip);
  if (!rec || Date.now() - rec.start > FAIL_WINDOW_MS) return false;
  return rec.n >= FAIL_MAX;
}
function noteFail(ip) {
  const now = Date.now();
  const rec = attempts.get(ip);
  if (!rec || now - rec.start > FAIL_WINDOW_MS) attempts.set(ip, { start: now, n: 1 });
  else rec.n++;
  if (attempts.size > 5000) attempts.clear();
}

/* ── validation ────────────────────────────────────────────────── */

function str(v, max, dflt) {
  return (typeof v === 'string') ? v.slice(0, max) : dflt;
}
function unit(v, dflt) {
  return (typeof v === 'number' && isFinite(v)) ? Math.min(1, Math.max(0, v)) : dflt;
}
function isHex(v, len) {
  return typeof v === 'string' && v.length === len && /^[0-9a-f]+$/.test(v);
}
function isDataImage(v) {
  return typeof v === 'string' && v.slice(0, 11) === 'data:image/';
}
function safeId(v) {
  return (typeof v === 'string' && /^[a-z0-9]{4,40}$/.test(v)) ? v : null;
}

/* Builds the stored pawn. Identity and code material are taken from the
 * previous record, never from the request. */
function cleanPawn(inp, prev) {
  const p = {
    id: prev ? prev.id : safeId(inp.id),
    name: str(inp.name, LIMITS.nameLen, prev ? prev.name : 'Unnamed') || 'Unnamed',
    img: isDataImage(inp.img) ? inp.img : (prev ? prev.img : null),
    x: unit(inp.x, prev ? prev.x : 0.5),
    y: unit(inp.y, prev ? prev.y : 0.5),
    size: PAWN_SIZES.indexOf(inp.size) >= 0 ? inp.size : (prev ? prev.size : 64),
    owner: prev ? prev.owner : str(inp.owner, 40, ''),
    /* code material and the address fingerprint are never taken from the body */
    salt: prev ? prev.salt : null,
    verifier: prev ? prev.verifier : null,
    ip: prev ? prev.ip : null
  };
  return p;
}

function cleanMark(inp, prev) {
  return {
    id: prev ? prev.id : safeId(inp.id),
    text: str(inp.text, LIMITS.textLen, prev ? prev.text : ''),
    icon: MARK_ICONS.indexOf(inp.icon) >= 0 ? inp.icon : (prev ? prev.icon : 'none'),
    x: unit(inp.x, prev ? prev.x : 0.5),
    y: unit(inp.y, prev ? prev.y : 0.5),
    size: MARK_SIZES.indexOf(inp.size) >= 0 ? inp.size : (prev ? prev.size : 48)
  };
}

/* What clients are allowed to see. The verifier and the address fingerprint are
 * stripped; each caller is told only which characters its own address holds. */
function publicBoard(board, ipFp) {
  const pawns = {};
  for (const id in board.pawns) {
    const p = board.pawns[id];
    pawns[id] = {
      id: p.id, name: p.name, img: p.img, x: p.x, y: p.y, size: p.size,
      owner: p.owner,
      protected: !!p.verifier,
      salt: p.verifier ? p.salt : null,
      yours: !!(ipFp && p.ip && ctEq(p.ip, ipFp))
    };
  }
  return { pawns: pawns, marks: board.marks, map: board.map, rev: board.rev };
}

/* ── storage ───────────────────────────────────────────────────── */

async function readBoard(env) {
  const raw = await env.MAP_KV.get(KEY);
  if (!raw) return emptyBoard();
  try {
    const b = JSON.parse(raw);
    return {
      pawns: (b && typeof b.pawns === 'object' && b.pawns) || {},
      marks: (b && typeof b.marks === 'object' && b.marks) || {},
      map: (b && typeof b.map === 'string') ? b.map : null,
      rev: (b && typeof b.rev === 'number') ? b.rev : 0
    };
  } catch (e) {
    return emptyBoard();
  }
}

async function writeBoard(env, board) {
  board.rev = Date.now();
  const out = JSON.stringify(board);
  if (out.length > LIMITS.boardBytes) {
    return { ok: false, error: 'Board is too large', bytes: out.length, limit: LIMITS.boardBytes };
  }
  await env.MAP_KV.put(KEY, out);
  return { ok: true, bytes: out.length };
}

/* ── request handlers ──────────────────────────────────────────── */

export async function onRequestGet({ request, env }) {
  if (!env.MAP_KV) return json({ error: 'KV binding MAP_KV is missing' }, 500);
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  return json(publicBoard(await readBoard(env), await ipFingerprint(env, ip)));
}

export async function onRequestPost({ request, env }) {
  if (!env.MAP_KV) return json({ error: 'KV binding MAP_KV is missing' }, 500);

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: 'Body was not JSON' }, 400); }
  if (!body || typeof body !== 'object') return json({ error: 'Body was not an object' }, 400);

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  /* ── moderator unlock ── */
  if (body.op === 'mod-unlock') {
    if (!env.MOD_PASSPHRASE) return json({ error: 'MOD_PASSPHRASE is not configured' }, 500);
    if (throttled(ip)) return json({ error: 'Too many attempts. Wait a few minutes.' }, 429);
    const given = await sha256Hex(String(body.passphrase || ''));
    const want = await sha256Hex(String(env.MOD_PASSPHRASE));
    if (!ctEq(given, want)) { noteFail(ip); return json({ error: 'Incorrect passphrase' }, 403); }
    return json({ ok: true, token: await issueToken(env), ttl: TOKEN_TTL_MS });
  }

  /* ── prove a lock code without changing anything ── */
  if (body.op === 'verify') {
    if (throttled(ip)) return json({ error: 'Too many attempts. Wait a few minutes.' }, 429);
    const board = await readBoard(env);
    const p = board.pawns[safeId(body.id)];
    if (!p || !p.verifier) return json({ error: 'That character has no lock code' }, 404);
    if (!isHex(body.proof, 64) || !ctEq(await sha256Hex(body.proof), p.verifier)) {
      noteFail(ip);
      return json({ error: 'Incorrect code' }, 403);
    }
    return json({ ok: true });
  }

  /* ── batched board operations ── */
  const ops = Array.isArray(body.ops) ? body.ops : null;
  if (!ops) return json({ error: 'No operations given' }, 400);
  if (ops.length > LIMITS.opsPerBatch) return json({ error: 'Too many operations in one batch' }, 400);

  const isMod = await validToken(env, body.mod);
  if (body.mod && !isMod) return json({ error: 'Moderator session expired', modExpired: true }, 401);

  const proofs = (body.proofs && typeof body.proofs === 'object') ? body.proofs : {};
  const client = str(body.client, 40, '');

  const ipFp = await ipFingerprint(env, ip);
  const board = await readBoard(env);
  const results = [];
  let changed = false;

  /* may this request act on an existing pawn */
  async function mayTouch(prev) {
    if (isMod) return true;
    if (prev && prev.verifier) {
      const proof = proofs[prev.id];
      if (!isHex(proof, 64)) return false;
      return ctEq(await sha256Hex(proof), prev.verifier);
    }
    return true;
  }

  for (let i = 0; i < ops.length; i++) {
    const op = ops[i];
    const kind = op && op.op;
    try {
      if (kind === 'pawn-put') {
        const inp = op.pawn || {};
        const id = safeId(inp.id);
        if (!id) { results.push({ op: kind, ok: false, error: 'Bad id' }); continue; }
        const prev = board.pawns[id] || null;
        if (!prev && Object.keys(board.pawns).length >= LIMITS.pawns) {
          results.push({ op: kind, ok: false, error: 'Board is full' }); continue;
        }
        /* one character per address. Moderators are exempt and the characters
         * they place hold no fingerprint, which is the way to seat a player who
         * shares a connection with someone already on the board. */
        if (!prev && !isMod) {
          let taken = false;
          for (const k in board.pawns) {
            if (board.pawns[k].ip && ctEq(board.pawns[k].ip, ipFp)) { taken = true; break; }
          }
          if (taken) {
            results.push({ op: kind, ok: false,
              error: 'One character per person. Remove yours before adding another.' });
            continue;
          }
        }
        if (!(await mayTouch(prev))) {
          results.push({ op: kind, id: id, ok: false, error: 'Locked by a code' }); continue;
        }
        if (isDataImage(inp.img) && inp.img.length > LIMITS.imgBytes) {
          results.push({ op: kind, id: id, ok: false, error: 'Picture is too large' }); continue;
        }
        const next = cleanPawn(inp, prev);
        /* set, change or clear the lock code */
        if (op.setCode && isHex(op.setCode.salt, 32) && isHex(op.setCode.proof, 64)) {
          next.salt = op.setCode.salt;
          next.verifier = await sha256Hex(op.setCode.proof);
        } else if (op.clearCode) {
          next.salt = null; next.verifier = null;
        }
        if (!prev) next.ip = isMod ? null : ipFp;
        board.pawns[id] = next; changed = true;
        results.push({ op: kind, id: id, ok: true, protectedNow: !!next.verifier });

      } else if (kind === 'pawn-delete') {
        const id = safeId(op.id);
        const prev = id ? board.pawns[id] : null;
        if (!prev) { results.push({ op: kind, id: id, ok: true, note: 'already gone' }); continue; }
        if (!(await mayTouch(prev))) {
          results.push({ op: kind, id: id, ok: false, error: 'Locked by a code' }); continue;
        }
        /* soft ownership check: the client id is self declared, so this stops
         * accidents between players and nothing more */
        const mineByIp = prev.ip && ctEq(prev.ip, ipFp);
        if (!isMod && !prev.verifier && !mineByIp && prev.owner && prev.owner !== client) {
          results.push({ op: kind, id: id, ok: false, error: 'Added by another player' }); continue;
        }
        delete board.pawns[id]; changed = true;
        results.push({ op: kind, id: id, ok: true });

      } else if (kind === 'mark-put') {
        if (!isMod) { results.push({ op: kind, ok: false, error: 'Moderators only' }); continue; }
        const inp = op.mark || {};
        const id = safeId(inp.id);
        if (!id) { results.push({ op: kind, ok: false, error: 'Bad id' }); continue; }
        if (!board.marks[id] && Object.keys(board.marks).length >= LIMITS.marks) {
          results.push({ op: kind, ok: false, error: 'Too many markers' }); continue;
        }
        board.marks[id] = cleanMark(inp, board.marks[id] || null); changed = true;
        results.push({ op: kind, id: id, ok: true });

      } else if (kind === 'mark-delete') {
        if (!isMod) { results.push({ op: kind, ok: false, error: 'Moderators only' }); continue; }
        const id = safeId(op.id);
        if (id) delete board.marks[id];
        changed = true;
        results.push({ op: kind, id: id, ok: true });

      } else if (kind === 'marks-clear') {
        if (!isMod) { results.push({ op: kind, ok: false, error: 'Moderators only' }); continue; }
        board.marks = {}; changed = true;
        results.push({ op: kind, ok: true });

      } else if (kind === 'pawns-clear') {
        if (!isMod) { results.push({ op: kind, ok: false, error: 'Moderators only' }); continue; }
        board.pawns = {}; changed = true;
        results.push({ op: kind, ok: true });

      } else if (kind === 'map-set') {
        if (!isMod) { results.push({ op: kind, ok: false, error: 'Moderators only' }); continue; }
        if (op.map === null) {
          board.map = null;
        } else if (isDataImage(op.map) && op.map.length <= LIMITS.mapBytes) {
          board.map = op.map;
        } else {
          results.push({ op: kind, ok: false, error: 'Map image is not usable' }); continue;
        }
        changed = true;
        results.push({ op: kind, ok: true });

      } else {
        results.push({ op: String(kind), ok: false, error: 'Unknown operation' });
      }
    } catch (e) {
      results.push({ op: String(kind), ok: false, error: 'Operation failed' });
    }
  }

  if (changed) {
    const w = await writeBoard(env, board);
    if (!w.ok) return json({ error: w.error, bytes: w.bytes, limit: w.limit }, 413);
  }

  let denied = 0;
  for (let i = 0; i < results.length; i++) if (!results[i].ok) denied++;

  return json({
    ok: denied === 0,
    isMod: isMod,
    results: results,
    board: publicBoard(board, ipFp)
  });
}
