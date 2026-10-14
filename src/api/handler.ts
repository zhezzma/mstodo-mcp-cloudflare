// REST facade over the MCP tool surface (src/mcp/agent.ts).
//
// WHY: agent skills (and plain curl) speak HTTP+JSON, not MCP. This facade
// exposes the full MCP tool surface as two boring endpoints so skills can
// drive it without an MCP client:
//   GET  /api/tools        → tools/list (the whole catalog, schemas included)
//   POST /api/tool/:name   → tools/call (body = tool arguments JSON)
//
// AUTH: Authorization: Bearer $SKILL_API_KEY (a Worker secret; compared
// constant-time via SHA-256 + crypto.subtle.timingSafeEqual). When the secret
// is not configured every request is rejected (fail closed) and an error is
// logged with setup instructions.
//
// TRANSPORT: instead of re-speaking MCP streamable-HTTP (session ids + SSE
// bridging), each request opens a FRESH McpAgent DO session (unique DO name,
// `skill-facade:<uuid>`) and drives it over the SDK's handleMcpMessage RPC:
//   initialize → notifications/initialized → tools/call | tools/list
// The handshake is cheap (local DO RPC) and a fresh session per request keeps
// semantics identical to upstream's serve() path — no shared-session state.
// Tools authenticate with the owner's Microsoft tokens from KV, exactly like
// the MCP route; no OAuth client token is involved for facade callers.
//
// UPSTREAM-SYNC: this file is entirely new. The only touch point in upstream
// code is the three-line route dispatch in src/index.ts (before
// oauthProvider.fetch). SKILL_API_KEY is declared here via interface merging
// so src/types.ts stays untouched.
//
// Response body convention: the tool's own JSON passes through verbatim —
// tools return {ok:true,...} on success and {ok:false,reason,...} on failure
// (see observability/instrument.ts errResponse). HTTP status reflects the
// FACADE layer only (401 auth, 404 unknown tool, 405 method, 413 body, 502
// MCP transport failure); tool-level errors stay HTTP 200 inside the body so
// callers read `.ok`.

import { log } from "../log";

// Interface merging: SKILL_API_KEY joins Env without touching src/types.ts.
declare global {
  interface Env {
    SKILL_API_KEY?: string;
  }
}

type JsonRpcResponse = {
  jsonrpc: "2.0";
  id?: number | string | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
};

// Injectable for tests: sends one JSON-RPC message to the MCP server, returns
// its response message (requests) or undefined (notifications).
export type McpRpc = (
  message: Record<string, unknown>,
) => Promise<JsonRpcResponse | JsonRpcResponse[] | undefined>;

const MCP_PROTOCOL_VERSION = "2025-06-18";
const CLIENT_INFO = { name: "mstodo-skill-facade", version: "1.0.0" } as const;
const DO_SESSION_PREFIX = "skill-facade:";
// Tool arguments can carry base64 file attachments (Graph caps a file at
// 25 MiB ≈ 34 MB base64); cap generously below the Workers request limit.
const MAX_BODY_BYTES = 64 * 1024 * 1024;
const TOOL_NAME_RE = /^[a-z][a-z0-9_]*$/;

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function parseBearer(req: Request): string | null {
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.get("authorization") ?? "");
  return m ? m[1].trim() : null;
}

// Hash-then-compare: SHA-256 fixes the length (no length leak), then Workers'
// crypto.subtle.timingSafeEqual compares constant-time. Explicit constant-time
// fallback loop for runtimes without the API.
export async function tokensMatch(provided: string, expected: string): Promise<boolean> {
  const enc = new TextEncoder();
  const a = await crypto.subtle.digest("SHA-256", enc.encode(provided));
  const b = await crypto.subtle.digest("SHA-256", enc.encode(expected));
  const tse = crypto.subtle as SubtleCrypto & {
    timingSafeEqual?: (a: ArrayBuffer, b: ArrayBuffer) => boolean;
  };
  if (typeof tse.timingSafeEqual === "function") return tse.timingSafeEqual(a, b);
  const va = new Uint8Array(a);
  const vb = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < va.length; i++) diff |= (va[i] ?? 0) ^ (vb[i] ?? 0);
  return diff === 0;
}

export async function authorized(req: Request, env: Env): Promise<boolean> {
  const expected = env.SKILL_API_KEY;
  if (!expected) {
    log.error("api_facade_key_missing", {
      hint: "Configure the facade key: npx wrangler secret put SKILL_API_KEY",
    });
    return false;
  }
  const provided = parseBearer(req);
  return provided !== null && (await tokensMatch(provided, expected));
}

// Real dispatcher: a fresh McpAgent DO session per facade request, driven via
// the SDK's handleMcpMessage RPC (bypasses the OAuthProvider — the OAuth
// grant/session layer is irrelevant because tools read tokens from KV).
export function createDoRpc(env: Env): McpRpc {
  const stub = env.TODO_INDEX.get(
    env.TODO_INDEX.idFromName(`${DO_SESSION_PREFIX}${crypto.randomUUID()}`),
  );
  return async (message) => {
    const res = (await stub.handleMcpMessage(
      message as unknown as Parameters<typeof stub.handleMcpMessage>[0],
    )) as JsonRpcResponse | JsonRpcResponse[] | undefined;
    return res ?? undefined;
  };
}

function isSingleResponse(
  m: JsonRpcResponse | JsonRpcResponse[] | undefined,
): m is JsonRpcResponse {
  return m !== undefined && !Array.isArray(m) && (m.result !== undefined || m.error !== undefined);
}

// Full handshake: initialize → notifications/initialized → the actual call.
// Returns the final JSON-RPC response for `method`; wraps any handshake
// failure into a synthetic JSON-RPC error so callers branch on one shape.
async function rpcWithHandshake(
  rpc: McpRpc,
  method: string,
  params: unknown,
): Promise<JsonRpcResponse> {
  const initRes = await rpc({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: CLIENT_INFO,
    },
  });
  if (!isSingleResponse(initRes) || initRes.error || initRes.result === undefined) {
    log.error("api_facade_init_failed", { detail: JSON.stringify(initRes ?? null).slice(0, 300) });
    return {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32603, message: "facade: MCP initialize failed", data: initRes ?? null },
    };
  }
  await rpc({ jsonrpc: "2.0", method: "notifications/initialized" });
  const res = await rpc({
    jsonrpc: "2.0",
    id: 2,
    method,
    params: params as Record<string, unknown>,
  });
  if (!isSingleResponse(res)) {
    log.error("api_facade_no_response", { method });
    return {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32603, message: `facade: no MCP response for ${method}` },
    };
  }
  return res;
}

// Pass the tool's own JSON through as the facade body when possible — callers
// read ok/reason straight off the tool payload (single source of truth). Any
// non-JSON content falls back to the raw content blocks.
export function unwrapToolResult(
  tool: string,
  result: unknown,
): { body: unknown; isError: boolean } {
  const r = (result ?? {}) as {
    content?: { type: string; text?: string }[];
    isError?: boolean;
  };
  const first = r.content?.[0];
  if (first && first.type === "text" && typeof first.text === "string") {
    try {
      const parsed: unknown = JSON.parse(first.text);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return { body: parsed, isError: r.isError === true };
      }
    } catch {
      // not JSON — fall through to raw blocks
    }
  }
  return {
    body: { ok: !r.isError, tool, content: r.content ?? [] },
    isError: r.isError === true,
  };
}

export default {
  // Same contract as the upload/download/webhook handlers: a Response for
  // paths we own, null so the caller's routing (OAuth provider) continues.
  async fetch(req: Request, env: Env): Promise<Response | null> {
    const url = new URL(req.url);
    const isTools = url.pathname === "/api/tools";
    const toolPrefix = "/api/tool/";
    const isToolCall = url.pathname.startsWith(toolPrefix);
    if (!isTools && !isToolCall) return null;

    const started = Date.now();
    if (!(await authorized(req, env))) {
      log.warn("api_facade_auth_rejected", { path: url.pathname });
      return json({ ok: false, error: "unauthorized" }, 401);
    }

    if (isTools) {
      if (req.method !== "GET") return json({ ok: false, error: "method_not_allowed" }, 405);
      const res = await rpcWithHandshake(createDoRpc(env), "tools/list", {});
      if (res.error) {
        return json({ ok: false, error: "mcp_error", detail: res.error }, 502);
      }
      const tools = (res.result as { tools?: unknown } | null)?.tools ?? [];
      log.info("api_facade", { path: url.pathname, durationMs: Date.now() - started });
      return json({ ok: true, tools });
    }

    if (req.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
    const name = decodeURIComponent(url.pathname.slice(toolPrefix.length));
    if (!TOOL_NAME_RE.test(name)) {
      return json({ ok: false, error: "unknown_tool", tool: name || null }, 404);
    }

    const contentLength = Number(req.headers.get("content-length") ?? "0");
    if (contentLength > MAX_BODY_BYTES) {
      return json({ ok: false, error: "body_too_large" }, 413);
    }
    const raw = await req.text();
    let args: unknown = {};
    if (raw.length > 0) {
      try {
        args = JSON.parse(raw);
        if (args === null || typeof args !== "object" || Array.isArray(args)) {
          return json({ ok: false, error: "invalid_json_body", hint: "body must be a JSON object" }, 400);
        }
      } catch {
        return json({ ok: false, error: "invalid_json_body" }, 400);
      }
    }

    const res = await rpcWithHandshake(createDoRpc(env), "tools/call", {
      name,
      arguments: args,
    });
    if (res.error) {
      // MCP SDK reports an unknown tool as JSON-RPC -32602 ("Unknown tool: x").
      const status = res.error.code === -32602 ? 404 : 502;
      log.warn("api_facade_tool_error", { tool: name, code: res.error.code });
      return json({ ok: false, error: "mcp_error", detail: res.error }, status);
    }
    const { body } = unwrapToolResult(name, res.result);
    log.info("api_facade", { tool: name, durationMs: Date.now() - started });
    return json(body);
  },
};
