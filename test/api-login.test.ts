import { env as rawEnv } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import facadeHandler from "../src/api/handler";
import AuthHandler from "../src/auth/handler";
import { STATE_KEY_PREFIX } from "../src/auth/microsoft";

// The test pool types env as Cloudflare.Env; cast once (see upload-handler.test.ts).
const env = rawEnv as unknown as Env;

function req(path: string, init: RequestInit = {}): Request {
  return new Request(`https://mstodo.example${path}`, init);
}

const TOKENS_KEY = "tokens:owner";
// vitest pool binding (see vitest.config.ts) — facadeCallbackUri() is pinned
// to SERVICE_BASE_URL so this is the redirect URI in test flows.
const SERVICE_ORIGIN = "https://mstodo-mcp.example.workers.dev";

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
    expect(await keyed.text()).toContain("owner@example.com");
  });
});

// --- standalone login flow -----------------------------------------------------

describe("standalone login", () => {
  it("GET /api/login redirects to Entra with the SHARED upstream callback URI", async () => {
    const res = (await facadeHandler.fetch(req("/api/login"), env))!;
    expect(res.status).toBe(302);
    const loc = res.headers.get("location")!;
    expect(loc).toContain("https://login.microsoftonline.com/");
    expect(loc).toContain("client_id=test-client");
    expect(loc).toContain("code_challenge_method=S256");
    const params = new URL(loc).searchParams;
    expect(params.get("redirect_uri")).toBe(`${SERVICE_ORIGIN}/auth/microsoft/callback`);
    // state row stored for the shared callback to branch on
    const state = params.get("state")!;
    const row = (await env.OAUTH_KV.get(`${STATE_KEY_PREFIX}${state}`, "json")) as Record<
      string,
      unknown
    >;
    expect(row).not.toBeNull();
    expect(atob(String(row!.oauth_req_info_b64))).toBe("facade-login");
  });

  it("the old dedicated callback route is gone (falls through to OAuth layer)", async () => {
    expect(await facadeHandler.fetch(req("/api/login/callback"), env)).toBeNull();
  });

  it("shared callback: provider error → 400", async () => {
    const res = await AuthHandler.fetch(
      req("/auth/microsoft/callback?error=access_denied&error_description=nope"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("shared callback: unknown/expired state → 400", async () => {
    const res = await AuthHandler.fetch(
      req("/auth/microsoft/callback?code=c&state=nope"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("full happy path: /api/login → consent → SHARED callback stores tokens + identity", async () => {
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

    // 3. complete via the SHARED upstream callback (sentinel row branches to facade)
    const cb = await AuthHandler.fetch(
      req(`/auth/microsoft/callback?code=authcode&state=${state}`),
      env,
    );
    expect(cb.status).toBe(200);
    expect(await cb.text()).toContain("授权完成");

    // 4. tokens + identity persisted
    const tokens = (await env.TODO_CACHE.get(TOKENS_KEY, "json")) as Record<string, unknown>;
    expect(tokens.access_token).toBe("NEW_AT");
    expect(tokens.refresh_token).toBe("NEW_RT");
    const identity = (await env.TODO_CACHE.get("identity:owner", "json")) as Record<
      string,
      unknown
    >;
    expect(identity.mail).toBe("test-owner@example.com");

    // 5. state row was consumed (single-use)
    expect(await env.OAUTH_KV.get(`${STATE_KEY_PREFIX}${state}`)).toBeNull();
  });

  it("exchange failure surfaces the AADSTS summary on the error page", async () => {
    const start = (await facadeHandler.fetch(req("/api/login"), env))!;
    const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
    globalThis.fetch = vi.fn(async () =>
      new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "AADSTS50196: loop detected.",
          error_codes: [50196],
          correlation_id: "abc-123",
        }),
        { status: 400 },
      ),
    ) as unknown as typeof fetch;
    const cb = await AuthHandler.fetch(
      req(`/auth/microsoft/callback?code=authcode&state=${state}`),
      env,
    );
    expect(cb.status).toBe(502);
    const body = await cb.text();
    expect(body).toContain("invalid_grant");
    expect(body).toContain("50196");
  });
});
