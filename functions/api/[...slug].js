// functions/api/[...slug].js
const ALLOW = ['https://yanjianyecao.github.io', 'http://localhost:8787']; // 允许的前端域

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const origin = request.headers.get('Origin') || '';
  const send = (obj, status=200) => new Response(JSON.stringify(obj), { status, headers: cors(origin) });

  if (request.method === 'OPTIONS') return new Response('', { headers: cors(origin) });

  try {
    // 路由：/api/signup | /api/login | /api/me | /api/data
    const path = url.pathname.replace(/\/+$/, '');

    if (path.endsWith('/api/signup') && request.method === 'POST') {
      const { username, password } = await request.json();
      if (!/^[A-Za-z0-9_]{3,30}$/.test(username) || !password || password.length < 8)
        return send({ error: 'invalid input' }, 400);

      const exist = await env.APP_KV.get(`user:${username}`);
      if (exist) return send({ error: 'user exists' }, 409);

      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iter = 120000;
      const dk = await pbkdf2(password, salt, iter);
      const record = {
        id: crypto.randomUUID(),
        username,
        pwd: `pbkdf2$${iter}$${b64(salt)}$${b64(new Uint8Array(dk))}`,
        createdAt: Date.now()
      };
      await env.APP_KV.put(`user:${username}`, JSON.stringify(record));
      return send({ ok: true });
    }

    if (path.endsWith('/api/login') && request.method === 'POST') {
      const { username, password } = await request.json();
      const raw = await env.APP_KV.get(`user:${username}`);
      if (!raw) return send({ error: 'not found' }, 404);

      const user = JSON.parse(raw);
      const [, iterStr, saltB64, hashB64] = user.pwd.split('$');
      const salt = u8(atob(saltB64));
      const dk = await pbkdf2(password, salt, parseInt(iterStr, 10));
      if (b64(new Uint8Array(dk)) !== hashB64) return send({ error: 'invalid credentials' }, 401);

      const token = await signJWT({ sub: user.id, username: user.username }, env.JWT_SECRET, 7 * 24 * 3600);
      return send({ token });
    }

    if (path.endsWith('/api/me') && request.method === 'GET') {
      const auth = await requireAuth(request, env);
      return send({ user: { id: auth.sub, username: auth.username } });
    }

    if (path.endsWith('/api/data')) {
      if (request.method === 'GET') {
        const auth = await requireAuth(request, env);
        const data = await env.APP_KV.get(`data:${auth.sub}`);
        return send(data ? JSON.parse(data) : { presets: {}, storeProducts: [] });
      }
      if (request.method === 'POST') {
        const auth = await requireAuth(request, env);
        const body = await request.json();
        await env.APP_KV.put(`data:${auth.sub}`, JSON.stringify({
          presets: body.presets || {},
          storeProducts: body.storeProducts || []
        }));
        return send({ ok: true });
      }
    }

    return send({ error: 'Not found' }, 404);
  } catch (e) {
    return send({ error: 'Server error', detail: String(e) }, 500);
  }
}

/* ---------- helpers ---------- */
function allow(origin) {
  try {
    if (!origin) return ALLOW[0];
    const u = new URL(origin);
    if (ALLOW.includes(origin)) return origin;               // GitHub Pages / 本地
    if (u.hostname.endsWith('.pages.dev')) return origin;    // 你的 Cloudflare Pages 预览/生产域
  } catch {}
  return ALLOW[0];
}
function cors(origin) {
  const a = allow(origin);
  return {
    'Access-Control-Allow-Origin': a,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
    'Content-Type': 'application/json;charset=utf-8'
  };
}
function u8(buf) { return new Uint8Array(buf); }
function b64(u8arr) { let s=''; for (const b of u8arr) s+=String.fromCharCode(b); return btoa(s); }

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name:'PBKDF2' }, false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name:'PBKDF2', hash:'SHA-256', salt, iterations }, key, 256);
}
async function signJWT(payload, secret, expSecs) {
  const header = { alg:'HS256', typ:'JWT' };
  const now = Math.floor(Date.now()/1000);
  const body = { ...payload, iat: now, exp: now + expSecs };
  const enc = (o)=>btoa(unescape(encodeURIComponent(JSON.stringify(o)))).replace(/=+/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  const data = `${enc(header)}.${enc(body)}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)));
  return `${data}.${b64(sig).replace(/=+/g,'').replace(/\+/g,'-').replace(/\//g,'_')}`;
}
async function requireAuth(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) throw new Response('Unauthorized', { status: 401 });

  const [h, p, s] = token.split('.');
  const data = `${h}.${p}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.JWT_SECRET), { name:'HMAC', hash:'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('HMAC', key, b64urlToU8(s), new TextEncoder().encode(data));
  if (!ok) throw new Response('Unauthorized', { status: 401 });

  const body = JSON.parse(decodeURIComponent(escape(atob(p.replace(/-/g,'+').replace(/_/g,'/')))));
  if (body.exp && Math.floor(Date.now()/1000) > body.exp) throw new Response('Unauthorized', { status: 401 });
  return body;
}
function b64urlToU8(b64url) {
  const pad = '='.repeat((4 - b64url.length % 4) % 4);
  const b64 = (b64url + pad).replace(/-/g,'+').replace(/_/g,'/');
  return u8(Uint8Array.from(atob(b64), c=>c.charCodeAt(0)));
}
