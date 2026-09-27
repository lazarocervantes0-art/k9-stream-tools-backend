# K9 Stream Tools — Backend

Backend inicial para conectar K9 Stream Tools con KICK mediante OAuth 2.0 + PKCE.

## Archivos

- `package.json` — dependencias y comando de inicio.
- `server.js` — servidor Express y flujo OAuth.
- `.env.example` — plantilla de variables.
- `.gitignore` — evita publicar secretos.
- `README.md` — instrucciones.

## Render

Build Command:

```bash
npm install
```

Start Command:

```bash
npm start
```

Runtime: Node.

Cuando Render entregue la URL HTTPS, configura:

```text
APP_URL=https://TU-URL.onrender.com
```

Y en KICK Dev usa como Redirect URL:

```text
https://TU-URL.onrender.com/auth/kick/callback
```

## Variables privadas

Configura en Render:

- `KICK_CLIENT_ID`
- `KICK_CLIENT_SECRET`
- `SESSION_SECRET`
- `APP_URL`
- `KICK_SCOPES`

Nunca publiques `.env` ni `KICK_CLIENT_SECRET`.

## Pruebas

- `/health` debe responder JSON con `ok: true`.
- `/auth/kick` inicia la conexión con KICK.

La API y los permisos exactos disponibles deben configurarse según la documentación vigente de KICK Dev.
