import { env as rawEnv, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import facadeHandler from "../src/api/handler";
import { STATE_KEY_PREFIX } from "../src/auth/microsoft";

// The test pool types env as Cloudflare.Env; cast once (see upload-handler.test.ts).
const env = rawEnv as unknown as Env;

function req(path: string, init: RequestInit = {}): Request {
  return new Request(`https://mstodo.example${path}`, init);
}

const TOKENS_KEY = "tokens:owner";
const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
  vi.restoreAllMocks();
});

async function signIn(): Promise<void> {
  await env.TODO_CACHE.put(
    TOKENS_KEY,
    JSON.stringify({
      access_token: "AT",
      refresh_token: "RT",
      expires_at: Date.now() + 3_600_000,
      scope: "Tasks.ReadWrite",
      obtained_at: Date.now(),
    }),
  );
}

// --- status page (GET /) -----------------------------------------------------

describe("status page", () => {
  it("shows not-connected state when no tokens are stored", async () => {
    await env.TODO_CACHE.delete(TOKENS_KEY);
    const res = (await facadeHandler.fetch(req("/"), env))!;
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("未连接 Microsoft");
    expect(body).toContain("/api/login");
  });

  it("shows connected state with masked mail (no key) and full mail (valid key)", async () => {
    await signIn();
    await env.TODO_CACHE.put(
      "identity:owner",
      JSON.stringify({
        id: "u1",
        displayName: "Owner",
        mail: "owner@example.com",
        userPrincipalName: "owner@example.com",
        first_seen: 0,
        last_seen: 0,
      }),
    );
    const anon = (await facadeHandler.fetch(req("/"), env))!;
    const anonBody = await anon.text();
    expect(anonBody).toContain("已连接 Microsoft");
    expect(anonBody).toContain("ow***@example.com");
    expect(anonBody).not.toContain("owner@example.com");

    const keyedEnv = { ...env, SKILL_API_KEY: "k" } as unknown as Env;
    const keyed = (
      await facadeHandler.fetch(req("/", { headers: { authorization: "Bearer k" } }), keyedEnv)
    )!;
    expect((await keyed.text())).toContain("owner@example.com");
  });
});

// --- standalone login flow -----------------------------------------------------

describe("standalone login", () => {
  it("GET /api/login redirects to Entra and stores a one-shot state row", async () => {
    const res = (await facadeHandler.fetch(req("/api/login"), env))!;
    expect(res.status).toBe(302);
    const loc = res.headers.get("location")!;
    expect(loc).toContain("https://login.microsoftonline.com/");
    expect(loc).toContain("client_id=test-client");
    expect(loc).toContain("code_challenge_method=S256");
    const state = new URL(loc).searchParams.get("state")!;
    const row = await env.OAUTH_KV.get(`${STATE_KEY_PREFIX}${state}`, "json");
    expect(row).not.toBeNull();
  });

  it("callback rejects provider errors and unknown/expired state", async () => {
    const err = (await facadeHandler.fetch(req("/api/login/callback?error=access_denied"), env))!;
    expect(err.status).toBe(400);

    const bad = (
      await facadeHandler.fetch(req("/api/login/callback?code=c&state=nope"), env)
    )!;
    expect(bad.status).toBe(400);
  });

  it("full happy path: login → consent → callback stores tokens + identity", async () => {
    await env.TODO_CACHE.delete(TOKENS_KEY);
    // 1. start login, capture state
    const start = (await facadeHandler.fetch(req("/api/login"), env))!;
    const state = new URL(start.headers.get("location")!).searchParams.get("state")!;

    // 2. mock Entra token endpoint + Graph /me
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("login.microsoftonline.com")) {
        return new Response(
          JSON.stringify({
            token_type: "Bearer",
            scope: "Tasks.ReadWrite offline_access User.Read",
            expires_in: 3600,
            access_token: "NEW_AT",
            refresh_token: "NEW_RT",
          }),
          { status: 200 },
        );
      }
      if (url === "https://graph.microsoft.com/v1.0/me") {
        return new Response(
          JSON.stringify({
            id: "u1",
            displayName: "Owner",
            mail: "test-owner@example.com",
            userPrincipalName: "test-owner@example.com",
          }),
          { status: 200 },
        );
      }
      throw new Error(`unexpected fetch: ${url}`);
    }) as unknown as typeof fetch;

    // 3. callback
    const cb = (
      await facadeHandler.fetch(req(`/api/login/callback?code=authcode&state=${state}`), env)
    )!;
    expect(cb.status).toBe(200);
    expect(await cb.text()).toContain("授权完成");

    // 4. tokens + identity persisted
    const tokens = (await env.TODO_CACHE.get(TOKENS_KEY, "json")) as Record<string, unknown>;
    expect(tokens.access_token).toBe("NEW_AT");
    expect(tokens.refresh_token).toBe("NEW_RT");
    const identity = (await env.TODO_CACHE.get("identity:owner", "json")) as Record<string, unknown>;
    expect(identity.mail).toBe("test-owner@example.com");

    // 5. state row was consumed (single-use)
    expect(await env.OAUTH_KV.get(`${STATE_KEY_PREFIX}${state}`)).toBeNull();
  });

  it("callback refuses state rows minted by the upstream MCP authorize flow", async () => {
    // A row with real MCP oauth_req_info (not our sentinel) must be rejected.
    await env.OAUTH_KV.put(
      `${STATE_KEY_PREFIX}mcpstate`,
      JSON.stringify({
        oauth_req_info_b64: btoa(JSON.stringify({ clientId: "claude" })),
        code_verifier: "v",
        created_at: Date.now(),
      }),
    );
    const res = (
      await facadeHandler.fetch(req("/api/login/callback?code=c&state=mcpstate"), env)
    )!;
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("状态不匹配");
  });
});
