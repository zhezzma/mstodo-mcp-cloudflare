import { describe, expect, it, vi } from "vitest";
import facadeHandler, { tokensMatch, unwrapToolResult } from "../src/api/handler";

// --- scripted fake MCP RPC layer -------------------------------------------
// The facade's only external dependency is handleMcpMessage on the TODO_INDEX
// DO. A scripted stub lets us test every branch (handshake, tools/list,
// tools/call, JSON-RPC errors) without touching Graph or real MCP sessions.

type Msg = Record<string, unknown> & { method?: string; id?: unknown };

const INIT_OK = {
  jsonrpc: "2.0",
  id: 1,
  result: {
    protocolVersion: "2025-06-18",
    capabilities: { tools: {} },
    serverInfo: { name: "mstodo-mcp", version: "test" },
  },
};

function makeEnv(script: (m: Msg) => unknown, key: string | null | undefined = "test-key") {
  const calls: Msg[] = [];
  const stub = {
    handleMcpMessage: vi.fn(async (message: Msg) => {
      calls.push(message);
      return script(message);
    }),
  };
  const env = {
    ...(key === null ? {} : { SKILL_API_KEY: key }),
    TODO_INDEX: { idFromName: (n: string) => n, get: () => stub },
  } as unknown as Env;
  return { env, calls };
}

function okScript(toolResult: unknown) {
  return (m: Msg) => {
    if (m.method === "initialize") return INIT_OK;
    if (m.method === "notifications/initialized") return undefined;
    if (m.method === "tools/list") {
      return { jsonrpc: "2.0", id: 2, result: { tools: [{ name: "whoami" }] } };
    }
    if (m.method === "tools/call") return { jsonrpc: "2.0", id: 2, result: toolResult };
    return undefined;
  };
}

function textResult(payload: unknown, isError = false) {
  return { content: [{ type: "text", text: JSON.stringify(payload) }], isError };
}

function req(path: string, init: RequestInit = {}): Request {
  return new Request(`https://mstodo.example${path}`, init);
}

function authReq(path: string, key = "test-key", init: RequestInit = {}): Request {
  return req(path, {
    ...init,
    headers: { authorization: `Bearer ${key}`, ...(init.headers ?? {}) },
  });
}

// --- routing -----------------------------------------------------------------

describe("facade routing", () => {
  it("returns null for non-/api paths (caller routing continues)", async () => {
    const { env } = makeEnv(okScript(textResult({ ok: true })));
    expect(await facadeHandler.fetch(req("/health"), env)).toBeNull();
    expect(await facadeHandler.fetch(req("/mcp"), env)).toBeNull();
    expect(await facadeHandler.fetch(req("/api"), env)).toBeNull();
  });

  it("rejects requests without / with wrong bearer key", async () => {
    const { env } = makeEnv(okScript(textResult({ ok: true })));
    const noKey = await facadeHandler.fetch(req("/api/tools"), env);
    expect(noKey?.status).toBe(401);
    const wrong = await facadeHandler.fetch(authReq("/api/tools", "nope"), env);
    expect(wrong?.status).toBe(401);
  });

  it("fails closed when SKILL_API_KEY is not configured", async () => {
    const { env } = makeEnv(okScript(textResult({ ok: true })), null);
    const res = await facadeHandler.fetch(authReq("/api/tools"), env);
    expect(res?.status).toBe(401);
  });

  it("enforces methods: GET on tool call, POST on tools list", async () => {
    const { env } = makeEnv(okScript(textResult({ ok: true })));
    expect((await facadeHandler.fetch(authReq("/api/tool/whoami"), env))?.status).toBe(405);
    expect(
      (await facadeHandler.fetch(authReq("/api/tools", "test-key", { method: "POST" }), env))?.status,
    ).toBe(405);
  });

  it("rejects malformed tool names with 404", async () => {
    const { env } = makeEnv(okScript(textResult({ ok: true })));
    for (const name of ["UPPER", "foo-bar", "1bad", ""]) {
      const res = await facadeHandler.fetch(authReq(`/api/tool/${name}`, undefined, { method: "POST" }), env);
      expect(res?.status, name).toBe(404);
    }
  });

  it("rejects invalid JSON bodies", async () => {
    const { env } = makeEnv(okScript(textResult({ ok: true })));
    const bad = await facadeHandler.fetch(
      authReq("/api/tool/whoami", "test-key", { method: "POST", body: "{" }),
      env,
    );
    expect(bad?.status).toBe(400);
    const arr = await facadeHandler.fetch(
      authReq("/api/tool/whoami", "test-key", { method: "POST", body: "[1]" }),
      env,
    );
    expect(arr?.status).toBe(400);
  });
});

// --- MCP handshake -----------------------------------------------------------

describe("facade MCP handshake", () => {
  it("initialize → notifications/initialized → tools/call, in order", async () => {
    const { env, calls } = makeEnv(okScript(textResult({ ok: true })));
    const res = await facadeHandler.fetch(
      authReq("/api/tool/whoami", "test-key", { method: "POST" }),
      env,
    );
    expect(res?.status).toBe(200);
    expect(calls.map((c) => c.method)).toEqual([
      "initialize",
      "notifications/initialized",
      "tools/call",
    ]);
    // notifications must not carry an id
    expect(calls[1]).not.toHaveProperty("id");
    expect(calls[2]?.params).toMatchObject({ name: "whoami", arguments: {} });
  });

  it("returns 502 when initialize fails", async () => {
    const { env } = makeEnv(() => ({ jsonrpc: "2.0", id: 1, error: { code: -32603, message: "boom" } }));
    const res = await facadeHandler.fetch(
      authReq("/api/tool/whoami", "test-key", { method: "POST" }),
      env,
    );
    expect(res?.status).toBe(502);
  });

  it("maps MCP unknown-tool error (-32602) to 404", async () => {
    const { env } = makeEnv((m) => {
      if (m.method === "initialize") return INIT_OK;
      if (m.method === "notifications/initialized") return undefined;
      return {
        jsonrpc: "2.0",
        id: 2,
        error: { code: -32602, message: "Unknown tool: nope" },
      };
    });
    const res = await facadeHandler.fetch(
      authReq("/api/tool/nope", "test-key", { method: "POST" }),
      env,
    );
    expect(res?.status).toBe(404);
  });
});

// --- payload pass-through ----------------------------------------------------

describe("facade payloads", () => {
  it("passes tool JSON through verbatim (success and business error alike)", async () => {
    const okEnv = makeEnv(okScript(textResult({ ok: true, lists: [{ id: "L1" }] })));
    const okRes = await facadeHandler.fetch(
      authReq("/api/tool/list_lists", "test-key", { method: "POST" }),
      okEnv.env,
    );
    expect(await okRes?.json()).toEqual({ ok: true, lists: [{ id: "L1" }] });

    const errEnv = makeEnv(okScript(textResult({ ok: false, reason: "not_authenticated" }, true)));
    const errRes = await facadeHandler.fetch(
      authReq("/api/tool/list_lists", "test-key", { method: "POST" }),
      errEnv.env,
    );
    // tool-level failure stays HTTP 200; body carries the tool's own verdict
    expect(errRes?.status).toBe(200);
    expect(await errRes?.json()).toEqual({ ok: false, reason: "not_authenticated" });
  });

  it("serves the tool catalog from GET /api/tools", async () => {
    const { env } = makeEnv(okScript(textResult({ ok: true })));
    const res = await facadeHandler.fetch(authReq("/api/tools"), env);
    expect(res?.status).toBe(200);
    expect(await res?.json()).toEqual({ ok: true, tools: [{ name: "whoami" }] });
  });
});

// --- pure helpers ------------------------------------------------------------

describe("tokensMatch", () => {
  it("compares correctly", async () => {
    expect(await tokensMatch("secret", "secret")).toBe(true);
    expect(await tokensMatch("secret", "secreT")).toBe(false);
    expect(await tokensMatch("", "secret")).toBe(false);
  });
});

describe("unwrapToolResult", () => {
  it("unwraps JSON text blocks", () => {
    expect(unwrapToolResult("t", textResult({ ok: true, x: 1 }))).toEqual({
      body: { ok: true, x: 1 },
      isError: false,
    });
  });

  it("falls back to raw blocks for non-JSON text", () => {
    const res = unwrapToolResult("t", { content: [{ type: "text", text: "plain string" }] });
    expect(res.body).toEqual({ ok: true, tool: "t", content: [{ type: "text", text: "plain string" }] });
  });
});
