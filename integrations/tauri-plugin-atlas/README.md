# tauri-plugin-atlas

Atlas for [Tauri 2](https://v2.tauri.app). The hosted sign-in runs in the system browser (authorization code with PKCE, loopback redirect per RFC 8252), the OAuth access token is traded for an Atlas session, the rotating refresh token is kept in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service), and your frontend asks for a fresh session token whenever it calls your API.

```rust
// src-tauri/src/main.rs
tauri::Builder::default()
    .plugin(tauri_plugin_atlas::init())
    .run(tauri::generate_context!())?;
```

```json
// src-tauri/tauri.conf.json
{ "plugins": { "atlas": {
  "issuer": "https://auth.example.com",
  "publishableKey": "pk_live_...",
  "clientId": "your_first_party_public_client"
} } }
```

```json
// src-tauri/capabilities/default.json
{ "permissions": ["atlas:default"] }
```

```ts
import { signIn, getToken, signOut, status } from 'tauri-plugin-atlas-api';

await signIn();
const res = await fetch('https://api.example.com/orders', { headers: { Authorization: `Bearer ${await getToken()}` } });
```

Register `http://127.0.0.1/callback` as a redirect URI of the OAuth client. A free port is chosen for each sign-in, which is fine: Atlas matches loopback redirect URIs on any port (RFC 8252). Set `redirectPort` only if you want a fixed one.

Security: the `state` is checked, the authorize and token endpoints must be on the issuer's origin, the redirect listener accepts only `GET /callback` on 127.0.0.1 and gives up after `timeoutSecs` (300). The token is for your own API: verify it there with a server SDK. The webview never sees the refresh token.
