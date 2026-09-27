# K9 Stream Tools Backend — OAuth corregido

Versión 1.1.0. Corrige el problema de `OAuth inválido: state o code no coinciden` evitando depender de `express-session` para transportar el estado temporal de OAuth.

## Qué cambia

- OAuth de KICK usa Authorization Code + PKCE.
- `state` + PKCE verifier se guardan en una cookie temporal cifrada, HttpOnly, SameSite=Lax y Secure cuando se usa HTTPS.
- La sesión de Express se mantiene para el access token después del login.
- El callback valida `state`, caducidad y la integridad de la cookie.
- No requiere cambiar el Client ID ni el Client Secret.

## Variables de Render

Mantén estas variables:

- `KICK_CLIENT_ID` = Client ID de tu app KICK
- `KICK_CLIENT_SECRET` = Client Secret de tu app KICK
- `SESSION_SECRET` = secreto largo y aleatorio
- `APP_URL` = URL exacta de tu servicio Render, sin `/` final
- `KICK_SCOPES` = los scopes que hayas habilitado en tu app de KICK

`PORT` puede dejarse sin configurar en Render; Render lo proporciona.

## Redirect URI

En KICK Developer debe existir exactamente:

`https://TU-SERVICIO.onrender.com/auth/kick/callback`

No pongas `/` al final.

## Render

Build Command:

`npm install`

Start Command:

`npm start`

Después de cambiar el código, haz Manual Deploy / Deploy latest commit.

## Prueba

1. Abre `https://TU-SERVICIO.onrender.com/health`.
2. Abre `https://TU-SERVICIO.onrender.com/`.
3. Pulsa `Conectar con KICK`.
4. Autoriza la app.
5. Debe aparecer `KICK conectado`.
6. Pulsa `Probar conexión con KICK`.

## Importante

Nunca subas `.env` ni el Client Secret a GitHub. El secreto debe permanecer únicamente en Render Environment Variables.
