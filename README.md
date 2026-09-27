# K9 Stream Tools — Backend

Backend inicial para conectar K9 con KICK mediante OAuth 2.1 + PKCE.

## 1. Requisitos
- Node.js 20+
- Una aplicación creada en KICK Dev
- Client ID y Client Secret

## 2. Instalar
```bash
npm install
```

## 3. Configurar
Copia `.env.example` a `.env` y completa:

```env
APP_URL=http://localhost:3000
KICK_CLIENT_ID=...
KICK_CLIENT_SECRET=...
SESSION_SECRET=...
KICK_SCOPES=user:read channel:read
```

Nunca publiques `.env` ni compartas el Client Secret.

## 4. Ejecutar
```bash
npm start
```

Prueba:
- http://localhost:3000/health
- http://localhost:3000/auth/kick

## 5. Redirect URI para KICK
En desarrollo:
`http://localhost:3000/auth/kick/callback`

En producción:
`https://TU-DOMINIO/auth/kick/callback`

La URI configurada en KICK debe coincidir con la que usa el backend.

## 6. Siguiente fase de K9
1. Persistir tokens en una base de datos segura.
2. Implementar refresh token.
3. Validar firmas de webhooks de KICK.
4. Suscribir eventos de chat.
5. Motor de filtros anti-spam/insultos.
6. TTS.
7. WebSocket/SSE para enviar eventos al panel.
8. Overlay para OBS.
