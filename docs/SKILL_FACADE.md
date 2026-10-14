# Skill Facade — REST endpoints over the MCP tool surface

Agent skills (and plain curl) speak HTTP+JSON, not MCP. The facade exposes the
full MCP tool surface as two endpoints, authenticated with a single long-lived
key. The MCP route (`/mcp`, Claude.ai connector) keeps working unchanged.

## Endpoints

| Route | Method | Purpose |
|---|---|---|
| `/api/tools` | GET | Full tool catalog: names, descriptions, JSON-schema args |
| `/api/tool/:name` | POST | Call one tool; request body = tool arguments JSON |

Auth: `Authorization: Bearer $SKILL_API_KEY`.

### Examples

```bash
KEY="$SKILL_API_KEY"; BASE="https://mstodo.godgodgame.com"

# Discover the catalog
curl -sS -H "Authorization: Bearer $KEY" "$BASE/api/tools" | jq '.tools[].name'

# Call a tool
curl -sS -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{}' "$BASE/api/tool/whoami"

curl -sS -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"list_id":"<LIST_ID>","$top":50}' "$BASE/api/tool/list_tasks"
```

## Response contract

The tool's own JSON passes through verbatim as the HTTP body:

- success: `{ "ok": true, ... }` (HTTP 200)
- tool-level failure: `{ "ok": false, "reason": "...", ... }` (still HTTP 200 —
  read `.ok`/`.reason`, don't branch on status)
- facade-level failures are non-200: `401` bad key, `404` unknown tool, `405`
  wrong method, `400` bad JSON body, `413` body too large, `502` MCP transport
  failure (`detail` carries the JSON-RPC error).

`GET /api/tools` returns `{ "ok": true, "tools": [ { name, description,
inputSchema, annotations, ... } ] }` (MCP `tools/list` result).

## How it works

Each facade request opens a fresh McpAgent Durable Object session
(name `skill-facade:<uuid>`) and drives it over the SDK's `handleMcpMessage`
RPC: `initialize → notifications/initialized → tools/call|tools/list`. Tools
authenticate with the owner's Microsoft tokens from KV and refresh exactly as
on the MCP route — no Microsoft OAuth is exposed to facade callers. The OAuth
provider layer (`/authorize`, `/token`, `/register`, `/mcp`) is untouched; the
facade routes live before `oauthProvider.fetch` in `src/index.ts`.

## Standalone re-auth & status page (browser)

- `GET /` — status page: Microsoft connection state (masked identity), token
  expiry, and the re-auth link. Full identity only with a valid bearer key.
- `GET /api/login` — 302 to Microsoft consent (PKCE, single-use state).
  Unauthenticated by design; the `OWNER_EMAIL` gate rejects non-owners before
  any state is stored.
- Callback reuses the **same** redirect URI as the upstream MCP flow
  (`/auth/microsoft/callback`) — `src/auth/handler.ts` branches on a sentinel
  state row and delegates to `completeFacadeLogin`. Only ONE Azure redirect
  URI is needed for both flows (avoids known MSA multi-URI quirks).

Recovery path when the refresh token dies (password change, revoked consent):
open `/` → click re-auth → done. Identity changes wipe all per-identity cached
state, same as the upstream `/authorize` flow.

## Configuration

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | npx wrangler secret put SKILL_API_KEY
```

Rotating the key is just re-running the command (takes effect immediately).
When the secret is unset every request is rejected (fail closed).

## Files (upstream-sync footprint)

- `src/api/handler.ts` — new; the whole facade (routing, auth, handshake, unwrap)
- `src/api/handler.ts` also declares `SKILL_API_KEY?` on `Env` via interface
  merging so `src/types.ts` stays untouched
- `src/index.ts` — 3 lines: import + dispatch `/api/*` before `oauthProvider.fetch`
- `test/api-facade.test.ts` — new; 14 tests (auth, routing, handshake order,
  pass-through semantics)

Future upstream merges should only ever conflict on the three `src/index.ts`
lines; keep the `facadeHandler.fetch` dispatch before `oauthProvider.fetch`
and the merge is trivial.
