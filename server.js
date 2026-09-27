require('dotenv').config();

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const APP_URL = String(process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID || '';
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET || '';
const KICK_SCOPES = process.env.KICK_SCOPES || 'user:read channel:read';
const SESSION_SECRET = process.env.SESSION_SECRET || '';

if (!SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET no está configurado. Configúralo en Render antes de usar OAuth.');
}

app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));

const isHttps = APP_URL.startsWith('https://');
const cookieSecure = isHttps;

app.use(session({
  name: 'k9.sid',
  secret: SESSION_SECRET || 'dev-only-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: cookieSecure,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function randomString(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function createPkce() {
  const verifier = randomString(48);
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
  return { verifier, challenge };
}

function deriveKey() {
  return crypto.createHash('sha256').update(SESSION_SECRET || 'dev-only-change-me').digest();
}

// Encrypts the short-lived OAuth transaction so the browser can carry it
// between /auth/kick and /auth/kick/callback without depending on the
// express-session store. The cookie is HTTP-only, Secure on HTTPS and SameSite=Lax.
function encryptOAuthTransaction(payload) {
  const iv = crypto.randomBytes(12);
  const key = deriveKey();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(payload));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64url')}.${tag.toString('base64url')}.${ciphertext.toString('base64url')}`;
}

function decryptOAuthTransaction(value) {
  if (!value || typeof value !== 'string') return null;
  const parts = value.split('.');
  if (parts.length !== 3) return null;
  try {
    const [ivB64, tagB64, dataB64] = parts;
    const iv = Buffer.from(ivB64, 'base64url');
    const tag = Buffer.from(tagB64, 'base64url');
    const ciphertext = Buffer.from(dataB64, 'base64url');
    const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(), iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  } catch {
    return null;
  }
}

function parseCookies(header) {
  const result = {};
  if (!header) return result;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    result[key] = decodeURIComponent(value);
  }
  return result;
}

function setOAuthCookie(res, transaction) {
  const value = encryptOAuthTransaction(transaction);
  const parts = [
    `k9.oauth=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=600'
  ];
  if (cookieSecure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearOAuthCookie(res) {
  const parts = [
    'k9.oauth=',
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0'
  ];
  if (cookieSecure) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

function timingSafeEqualStrings(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function requireConfig(res) {
  const missing = [];
  if (!KICK_CLIENT_ID) missing.push('KICK_CLIENT_ID');
  if (!KICK_CLIENT_SECRET) missing.push('KICK_CLIENT_SECRET');
  if (!SESSION_SECRET) missing.push('SESSION_SECRET');
  if (missing.length) {
    res.status(500).send(`Faltan variables de entorno: ${missing.join(', ')}`);
    return false;
  }
  return true;
}

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: 'K9 Stream Tools Backend',
    oauth: 'kick',
    time: new Date().toISOString()
  });
});

app.get('/auth/kick', (req, res) => {
  if (!requireConfig(res)) return;

  const state = randomString(32);
  const { verifier, challenge } = createPkce();
  const redirectUri = `${APP_URL}/auth/kick/callback`;

  setOAuthCookie(res, {
    state,
    verifier,
    createdAt: Date.now()
  });

  const params = new URLSearchParams({
    client_id: KICK_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: KICK_SCOPES,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  });

  res.redirect(`https://id.kick.com/oauth/authorize?${params.toString()}`);
});

app.get('/auth/kick/callback', async (req, res) => {
  if (!requireConfig(res)) return;

  const { code, state, error, error_description: errorDescription } = req.query;

  if (error) {
    clearOAuthCookie(res);
    return res.status(400).send(`KICK rechazó OAuth: ${errorDescription || error}`);
  }

  if (!code || !state) {
    clearOAuthCookie(res);
    return res.status(400).send('OAuth inválido: KICK no devolvió code y state.');
  }

  const cookies = parseCookies(req.headers.cookie);
  const transaction = decryptOAuthTransaction(cookies['k9.oauth']);

  if (!transaction || !transaction.state || !transaction.verifier) {
    clearOAuthCookie(res);
    return res.status(400).send('OAuth inválido: falta la cookie de seguridad. Inicia la conexión desde K9 Stream Tools y no desde una URL guardada.');
  }

  if (Date.now() - Number(transaction.createdAt || 0) > 10 * 60 * 1000) {
    clearOAuthCookie(res);
    return res.status(400).send('OAuth expirado: vuelve a iniciar la conexión con KICK.');
  }

  if (!timingSafeEqualStrings(String(state), String(transaction.state))) {
    clearOAuthCookie(res);
    return res.status(400).send('OAuth inválido: state no coincide. Vuelve a iniciar la conexión con KICK desde K9 Stream Tools.');
  }

  try {
    const redirectUri = `${APP_URL}/auth/kick/callback`;
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET,
      redirect_uri: redirectUri,
      code: String(code),
      code_verifier: String(transaction.verifier)
    });

    const tokenResponse = await fetch('https://id.kick.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });

    const tokenText = await tokenResponse.text();
    let tokenData;
    try {
      tokenData = JSON.parse(tokenText);
    } catch {
      tokenData = { raw: tokenText };
    }

    if (!tokenResponse.ok) {
      console.error('KICK token error:', tokenResponse.status, tokenData);
      clearOAuthCookie(res);
      return res.status(400).send(`KICK rechazó el intercambio del código (${tokenResponse.status}). Revisa Redirect URI, Client ID/Secret y permisos.`);
    }

    req.session.kick = {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token || null,
      tokenType: tokenData.token_type || 'Bearer',
      expiresIn: tokenData.expires_in || null,
      connectedAt: new Date().toISOString()
    };

    clearOAuthCookie(res);

    res.send(`<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>K9 Stream Tools</title>
<style>body{font-family:Arial,sans-serif;background:#111;color:#fff;display:grid;place-items:center;min-height:100vh;margin:0}.box{max-width:520px;padding:32px;text-align:center;background:#1c1c1c;border-radius:18px}a{color:#58e6a8}</style></head>
<body><div class="box"><h1>✅ KICK conectado</h1><p>La autorización terminó correctamente.</p><p><a href="/api/me">Probar conexión con KICK</a></p><p><a href="/">Volver a K9 Stream Tools</a></p></div></body></html>`);
  } catch (error) {
    console.error('OAuth callback error:', error);
    clearOAuthCookie(res);
    res.status(500).send('Error interno al completar OAuth con KICK. Revisa los logs de Render.');
  }
});

app.get('/api/me', async (req, res) => {
  const accessToken = req.session?.kick?.accessToken;
  if (!accessToken) {
    return res.status(401).json({ ok: false, error: 'No hay una sesión de KICK. Conecta primero en /auth/kick.' });
  }

  try {
    const response = await fetch('https://api.kick.com/public/v1/users', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json'
      }
    });

    const text = await response.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }

    res.status(response.status).json({ ok: response.ok, data });
  } catch (error) {
    console.error('KICK API error:', error);
    res.status(502).json({ ok: false, error: 'No se pudo contactar la API de KICK.' });
  }
});

app.post('/webhooks/kick', (req, res) => {
  res.status(200).json({ ok: true, received: true });
});

app.get('/', (req, res) => {
  const connected = Boolean(req.session?.kick?.accessToken);
  res.send(`<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>K9 Stream Tools Backend</title>
<style>body{font-family:Arial,sans-serif;background:#101010;color:#fff;margin:0;padding:40px}.card{max-width:700px;margin:auto;background:#1b1b1b;border-radius:18px;padding:28px}a{color:#58e6a8}li{margin:10px 0}</style></head>
<body><div class="card"><h1>🐺 K9 Stream Tools Backend</h1><p>Backend activo.</p><ul><li><a href="/health">Health check</a></li><li><a href="/auth/kick">${connected ? 'Volver a conectar KICK' : 'Conectar con KICK'}</a></li><li><a href="/api/me">Probar /api/me</a></li></ul><p>Estado de sesión: <strong>${connected ? 'conectado' : 'no conectado'}</strong></p></div></body></html>`);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`K9 Stream Tools Backend escuchando en 0.0.0.0:${PORT}`);
  console.log(`APP_URL: ${APP_URL}`);
  console.log(`OAuth callback: ${APP_URL}/auth/kick/callback`);
});
