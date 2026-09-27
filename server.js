require("dotenv").config();

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", 1);
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const CLIENT_ID = process.env.KICK_CLIENT_ID || "";
const CLIENT_SECRET = process.env.KICK_CLIENT_SECRET || "";
const SCOPES = process.env.KICK_SCOPES || "user:read channel:read";

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-me-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: APP_URL.startsWith("https://"),
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

function base64url(buffer) {
  return buffer.toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function makePkce() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(
    crypto.createHash("sha256").update(verifier).digest()
  );
  return { verifier, challenge };
}

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "K9 Stream Tools Backend",
    time: new Date().toISOString()
  });
});

app.get("/auth/kick", (req, res) => {
  if (!CLIENT_ID) {
    return res.status(500).send("Falta KICK_CLIENT_ID en las variables de entorno.");
  }

  const state = base64url(crypto.randomBytes(24));
  const { verifier, challenge } = makePkce();

  req.session.oauthState = state;
  req.session.pkceVerifier = verifier;

  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: `${APP_URL}/auth/kick/callback`,
    scope: SCOPES,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });

  res.redirect(`https://id.kick.com/oauth/authorize?${params.toString()}`);
});

app.get("/auth/kick/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).send(`KICK OAuth: ${error_description || error}`);
  }

  if (!code || !state || state !== req.session.oauthState) {
    return res.status(400).send("OAuth inválido: state o code no coinciden.");
  }

  if (!CLIENT_ID || !CLIENT_SECRET || !req.session.pkceVerifier) {
    return res.status(500).send("Faltan variables de entorno de KICK/OAuth.");
  }

  try {
    const tokenResponse = await fetch("https://id.kick.com/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: `${APP_URL}/auth/kick/callback`,
        code,
        code_verifier: req.session.pkceVerifier
      })
    });

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok) {
      console.error("KICK token error:", tokenData);
      return res.status(502).send("KICK rechazó el intercambio del código.");
    }

    req.session.kick = {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      expiresIn: tokenData.expires_in,
      tokenType: tokenData.token_type
    };

    delete req.session.oauthState;
    delete req.session.pkceVerifier;

    res.redirect("/api/me");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error conectando con KICK.");
  }
});

app.get("/api/me", async (req, res) => {
  if (!req.session.kick?.accessToken) {
    return res.status(401).json({
      connected: false,
      message: "KICK no está conectado. Usa /auth/kick."
    });
  }

  try {
    const response = await fetch("https://api.kick.com/public/v1/users", {
      headers: {
        Authorization: `Bearer ${req.session.kick.accessToken}`,
        Accept: "application/json"
      }
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    res.json({ connected: true, data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ connected: false, error: "No se pudo consultar KICK." });
  }
});

app.post("/webhooks/kick", (req, res) => {
  console.log("KICK webhook recibido:", req.body);
  res.sendStatus(204);
});

app.get("/", (_req, res) => {
  res.type("html").send(`
    <h1>K9 Stream Tools Backend</h1>
    <p>Backend funcionando.</p>
    <ul>
      <li><a href="/health">Health check</a></li>
      <li><a href="/auth/kick">Conectar con KICK</a></li>
    </ul>
  `);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`K9 Stream Tools Backend escuchando en ${PORT}`);
  console.log(`APP_URL: ${APP_URL}`);
});
