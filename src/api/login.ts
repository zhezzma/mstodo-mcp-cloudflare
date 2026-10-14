// Standalone Microsoft re-authentication flow + public status page.
//
// WHY: upstream's /authorize bundles Microsoft sign-in INTO an MCP-client
// OAuth round (parseAuthRequest → completeAuthorization), so re-auth requires
// reconnecting an MCP client. The facade/skill path has no MCP client, so when
// the stored refresh token dies (password change, revoked consent, account
// switch) there was no recovery path. This module adds one that a bare browser
// can drive:
//
//   GET /                    → status page (connected? token expiry? login link)
//   GET /api/login           → create PKCE state, 302 to Microsoft consent
//   GET /api/login/callback  → exchange code, OWNER gate, store tokens/identity
//
// Security model: / and /api/login are unauthenticated BY DESIGN — initiating
// login only ever lands a stranger on Microsoft's consent screen, and the
// upstream OWNER_EMAIL gate (isOwner) rejects any non-owner account before any
// state is persisted. State rows are single-use, TTL'd (STATE_TTL_SEC), and
// stored in OAUTH_KV under the upstream key scheme.
//
// UPSTREAM-SYNC: this file is new; it reuses auth/microsoft.ts protocol
// helpers as-is. No upstream file is edited beyond the facade's existing
// 3-line dispatch in src/index.ts (login routes hang off the facade handler).

import { log } from "../log";
import {
  buildAuthorizeUrl,
  computeCodeChallenge,
  decodeJwtClaims,
  exchangeCode,
  fetchMe,
  generateCodeVerifier,
  generateStateToken,
  isOwner,
  loadIdentity,
  loadTokens,
  putAuthState,
  storeIdentity,
  storeTokens,
  takeAuthState,
  tokensFromResponse,
  wipeIdentityScopedState,
  TokenExchangeError,
  type AuthStateRow,
  type MeIdentity,
} from "../auth/microsoft";
import { tokensMatch } from "./handler";

const LOGIN_CALLBACK_PATH = "/api/login/callback";

// Sentinel stored in AuthStateRow.oauth_req_info_b64 — upstream's callback
// expects base64(MCP-oauthReqInfo) there; the facade callback owns its own
// rows and never feeds this to completeAuthorization.
const FACADE_LOGIN_SENTINEL = "facade-login";

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

function esc(s: string): string {
  const map: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };
  return s.replace(/[&<>"']/g, (c) => map[c] ?? c);
}

function page(title: string, body: string, status = 200): Response {
  return html(
    `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · mstodo-mcp</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: ui-sans-serif, system-ui, "PingFang SC", "Microsoft YaHei", sans-serif;
         background: #0d1117; color: #e6edf3; max-width: 640px; margin: 8vh auto; padding: 0 24px; }
  h1 { font-size: 1.4rem; } .card { background: #161b22; border: 1px solid #30363d;
       border-radius: 10px; padding: 20px 24px; margin: 16px 0; }
  .ok { color: #3fb950; } .bad { color: #f85149; } .muted { color: #8b949e; }
  code { background: #21262d; padding: 2px 6px; border-radius: 4px; }
  a.btn { display: inline-block; background: #238636; color: #fff; text-decoration: none;
          padding: 10px 18px; border-radius: 6px; font-weight: 600; }
  a { color: #58a6ff; }
  dl { display: grid; grid-template-columns: auto 1fr; gap: 6px 16px; }
  dt { color: #8b949e; } dd { margin: 0; }
</style></head>
<body><h1>Microsoft To Do · mstodo-mcp</h1>${body}</body></html>`,
    status,
  );
}

function maskMail(mail: string | null): string {
  if (!mail) return "(未知)";
  const at = mail.indexOf("@");
  if (at <= 0) return "***";
  const name = mail.slice(0, at);
  const shown = name.slice(0, Math.min(2, name.length));
  return `${shown}${"***"}${mail.slice(at)}`;
}

function fmtExpiry(expiresAt: number, timeZone: string): string {
  const remainMin = Math.round((expiresAt - Date.now()) / 60000);
  const when = new Intl.DateTimeFormat("zh-CN", {
    timeZone,
    hour: "2-digit",
    minute: "2-digit",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date(expiresAt));
  return remainMin >= 0 ? `${when}（约 ${remainMin} 分钟后到期）` : `${when}（已到期，等待自动刷新）`;
}

/** GET / — public status page. Full identity only with a valid bearer key. */
export async function handleStatusPage(req: Request, env: Env): Promise<Response> {
  const [tokens, identity] = await Promise.all([loadTokens(env), loadIdentity(env)]);

  const key = req.headers.get("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1]?.trim() ?? null;
  const fullDetail = key !== null && !!env.SKILL_API_KEY && (await tokensMatch(key, env.SKILL_API_KEY));

  let authCard: string;
  if (!tokens) {
    authCard = `<div class="card">
  <p class="bad">● 未连接 Microsoft</p>
  <p class="muted">尚未完成授权，或凭据已被清除。工具调用会返回 <code>not_authenticated</code>。</p>
  <p><a class="btn" href="/api/login">使用 Microsoft 账户授权</a></p>
</div>`;
  } else {
    const tz = String(env.TIMEZONE ?? "UTC");
    const who = identity
      ? fullDetail
        ? `${esc(identity.displayName)}（${esc(identity.mail ?? identity.userPrincipalName)}）`
        : `${esc(identity.displayName)}（${esc(maskMail(identity.mail))}）`
      : "已存储令牌但无身份记录";
    authCard = `<div class="card">
  <p class="ok">● 已连接 Microsoft</p>
  <dl>
    <dt>账号</dt><dd>${who}</dd>
    <dt>令牌到期</dt><dd>${esc(fmtExpiry(tokens.expires_at, tz))}</dd>
  </dl>
  <p class="muted">令牌由 Worker 自动刷新；正常情况下无需人工干预。若工具持续报
  <code>not_authenticated</code> 或刷新失败，点下方按钮重新授权。</p>
  <p><a href="/api/login">重新授权 / 更换账号 →</a></p>
</div>`;
  }

  return page(
    "状态",
    `${authCard}
<div class="card muted">
  <dl>
    <dt>健康检查</dt><dd><a href="/health">/health</a></dd>
    <dt>技能门面</dt><dd><code>GET /api/tools</code> · <code>POST /api/tool/:name</code>（Bearer SKILL_API_KEY）</dd>
    <dt>MCP 端点</dt><dd><code>/mcp</code>（OAuth 保护，不变）</dd>
  </dl>
</div>`,
  );
}

/** GET /api/login — begin a standalone Microsoft authorization round. */
export async function handleLoginStart(req: Request, env: Env): Promise<Response> {
  if (req.method !== "GET") return html("method not allowed", 405);

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await computeCodeChallenge(codeVerifier);
  const stateToken = generateStateToken();
  const row: AuthStateRow = {
    oauth_req_info_b64: btoa(FACADE_LOGIN_SENTINEL),
    code_verifier: codeVerifier,
    created_at: Date.now(),
  };
  await putAuthState(env, stateToken, row);

  const authorizeUrl = buildAuthorizeUrl(env, {
    redirectUri: new URL(req.url).origin + LOGIN_CALLBACK_PATH,
    state: stateToken,
    codeChallenge,
  });
  log.info("facade_login_start", { statePrefix: stateToken.slice(0, 8) });
  return Response.redirect(authorizeUrl, 302);
}

/** GET /api/login/callback — finish the round: exchange, owner gate, store. */
export async function handleLoginCallback(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const stateToken = url.searchParams.get("state");
  const oauthError = url.searchParams.get("error");

  if (oauthError) {
    const desc = url.searchParams.get("error_description") ?? "";
    log.warn("facade_login_callback_error", { error: oauthError, description: desc.slice(0, 200) });
    return page("授权失败", `<div class="card"><p class="bad">微软授权被取消或失败</p>
<p><code>${esc(oauthError)}</code>: ${esc(desc.slice(0, 300))}</p>
<p><a href="/">← 返回状态页</a></p></div>`, 400);
  }
  if (!code || !stateToken) {
    return page("无效回调", `<div class="card"><p class="bad">缺少 code 或 state 参数</p>
<p><a href="/api/login">重新发起授权</a></p></div>`, 400);
  }

  const state = await takeAuthState(env, stateToken);
  if (!state) {
    return page("状态过期", `<div class="card"><p class="bad">授权状态已过期或不存在（状态有效期 10 分钟）</p>
<p><a href="/api/login">重新发起授权</a></p></div>`, 400);
  }
  if (atob(state.oauth_req_info_b64) !== FACADE_LOGIN_SENTINEL) {
    // A state row created by upstream's MCP /authorize must not be consumed here.
    return page("状态不匹配", `<div class="card"><p class="bad">该状态属于其他授权流程</p>
<p><a href="/api/login">重新发起授权</a></p></div>`, 400);
  }

  const redirectUri = new URL(req.url).origin + LOGIN_CALLBACK_PATH;
  let token;
  try {
    token = await exchangeCode(env, { code, codeVerifier: state.code_verifier, redirectUri });
  } catch (e) {
    if (e instanceof TokenExchangeError) {
      log.warn("facade_login_exchange_failed", { reason: e.reason });
      return page("令牌交换失败", `<div class="card"><p class="bad"><code>${esc(e.reason)}</code></p>
<p class="muted">常见原因：redirect URI 未在 Azure 应用注册中添加（<code>${esc(redirectUri)}</code>）、
client_secret 失效、或授权码已被使用。</p>
<p><a href="/api/login">重试</a> · <a href="/">状态页</a></p></div>`, 502);
    }
    throw e;
  }

  let me: MeIdentity;
  try {
    me = await fetchMe(token.access_token);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    log.warn("facade_login_me_failed", { message });
    return page("身份探测失败", `<div class="card"><p class="bad">无法从 Microsoft Graph 读取 /me</p>
<p><code>${esc(message.slice(0, 200))}</code></p></div>`, 502);
  }
  if (!isOwner(env, me)) {
    log.warn("facade_login_owner_gate", { upn: me.userPrincipalName });
    return page("未授权", `<div class="card"><p class="bad">此服务只允许单一所有者。</p>
<p>当前登录账号 <code>${esc(me.userPrincipalName)}</code> 不是配置的所有者，未保存任何状态。</p></div>`, 403);
  }

  const prevIdentity = await loadIdentity(env);
  const identityChanged = prevIdentity !== null && prevIdentity.id !== me.id;
  if (identityChanged) {
    log.warn("facade_login_identity_change", { prev: prevIdentity.id, next: me.id });
    await wipeIdentityScopedState(env);
  }

  const now = Date.now();
  await storeTokens(env, tokensFromResponse(token, token.refresh_token ?? "", now));

  const claims = decodeJwtClaims(token.access_token);
  const tid = typeof claims?.tid === "string" ? claims.tid : null;
  await storeIdentity(env, {
    id: me.id,
    displayName: me.displayName,
    mail: me.mail,
    userPrincipalName: me.userPrincipalName,
    first_seen: prevIdentity?.id === me.id ? prevIdentity.first_seen : now,
    last_seen: now,
    ...(tid ? { anchorMailbox: `${me.id}@${tid}` } : {}),
  });
  log.info("facade_login_complete", { id: me.id, identity_changed: identityChanged });

  return page(
    "授权完成",
    `<div class="card">
  <p class="ok">✅ 授权完成，令牌已保存</p>
  <dl>
    <dt>账号</dt><dd>${esc(me.displayName)}（${esc(me.mail ?? me.userPrincipalName)}）</dd>
  </dl>
  <p class="muted">技能门面与 MCP 端点现在都可以正常使用了。</p>
  <p><a class="btn" href="/">查看状态</a></p>
</div>`,
  );
}
