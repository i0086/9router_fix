// TLS-impersonating HTTP client for opencode.ai's free tier.
//
// The free gate keys on the TLS ClientHello, not on headers: a request that
// passes from the OpenCode CLI is refused with 429 FreeUsageLimitError when the
// same body/headers ride Node's OpenSSL fingerprint, and passes again once the
// cipher list matches. Measured 2026-10-26 on one process, one egress IP, three
// transports: node fetch/https/http2 all 429, Bun's BoringSSL fetch 200.
// JA4's cipher hash identifies the list (Bun: 5b57614c22b0), so the match is on
// the cipher-list hash and nothing else — reordering the same list still passes.
//
// wreq-js is an optional dependency with prebuilt binaries for a fixed set of
// platforms (no FreeBSD, for one). When it cannot load, requests fall back to
// undici with the same cipher list: Node's OpenSSL honours `ciphers` for the
// ClientHello, and that list alone passes the gate (verified 2026-11-21:
// undici+cipherList 200, undici default 429 FreeUsageLimitError).
// That only holds on OpenSSL >= 3.5. Older OpenSSL (FreeBSD base 3.0) sends a
// ClientHello the gate refuses whatever the cipher list, so there the fallback
// goes through the Go forwarder in ./opencodeTlsHelper.js instead.

import { loadRuntimeDep } from "./lazyRuntime.js";
import { opensslNeedsHelper, resolveHelperPath, getHelper, stopHelper, helperFetch } from "./opencodeTlsHelper.js";

// BoringSSL/Chrome-family cipher list the upstream accepts, in the order Bun
// sends it. Only the list's hash is compared, so this must stay verbatim.
const OPENCODE_CIPHER_LIST = [
  "TLS_AES_128_GCM_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-CHACHA20-POLY1305",
  "ECDHE-ECDSA-AES128-SHA",
  "ECDHE-RSA-AES128-SHA",
  "ECDHE-ECDSA-AES256-SHA",
  "ECDHE-RSA-AES256-SHA",
  "AES128-GCM-SHA256",
  "AES256-GCM-SHA384",
  "AES128-SHA",
  "AES256-SHA",
].join(":");

const DEFAULT_TIMEOUT_MS = 120000;

// Same happy-eyeballs settings as proxyFetch's dispatchers.
const NATIVE_CONNECT = { autoSelectFamily: true, autoSelectFamilyAttemptTimeout: 250 };
// undici's ProxyAgent tunnels http/https proxies only.
const NATIVE_PROXY_PROTOCOLS = new Set(["http:", "https:"]);

// A wreq-js session pins one proxy at creation ("Session proxy cannot be
// changed after creation"), so the cache must be keyed by proxy URL: a proxy
// switch hands out a fresh session instead of silently reusing the old one's
// tunnel. The key "" is the no-proxy (direct) session.
const sessionsByProxy = new Map();
const SESSIONS_MAX = 8;

export class OpencodeTlsUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = "OpencodeTlsUnavailableError";
  }
}

function normalizeProxyKey(proxyUrl) {
  const raw = typeof proxyUrl === "string" ? proxyUrl.trim() : "";
  if (!raw) return "";
  try {
    // Credentials are part of the identity (auth context isolates pools), but
    // must never surface in logs or error text. Keep only scheme://host:port.
    const parsed = new URL(raw);
    return `${parsed.protocol}//${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}`;
  } catch {
    return raw; // unverifiable — treat the raw string as its own key
  }
}

async function buildSession(proxyUrl) {
  const wreq = await loadRuntimeDep("wreq-js");
  if (typeof wreq.createSession !== "function") {
    throw new Error("wreq-js runtime is missing createSession");
  }
  const session = await wreq.createSession({
    emulation: { tlsOptions: { cipherList: OPENCODE_CIPHER_LIST } },
    // wreq-js natively tunnels http/https/socks5 proxies at the transport
    // layer, so the impersonated TLS handshake still happens through the
    // proxy — not next to it.
    ...(proxyUrl ? { proxy: proxyUrl } : {}),
  });
  return Object.assign(session, { __proxyKey: normalizeProxyKey(proxyUrl) });
}

async function loadSession(proxyUrl = "") {
  const key = normalizeProxyKey(proxyUrl);
  if (!sessionsByProxy.has(key)) {
    if (sessionsByProxy.size >= SESSIONS_MAX) {
      // Evict oldest: a rotated-out pool identity should not hold connections.
      const oldestKey = sessionsByProxy.keys().next().value;
      const oldest = sessionsByProxy.get(oldestKey);
      sessionsByProxy.delete(oldestKey);
      oldest?.then?.((session) => session.close?.()).catch(() => {});
    }
    const promise = buildSession(proxyUrl).catch((error) => {
      sessionsByProxy.delete(key);
      throw error;
    });
    sessionsByProxy.set(key, promise);
  }
  return sessionsByProxy.get(key);
}

// Fallback transport: one undici dispatcher per proxy key ("" = direct).
const nativeDispatchers = new Map();
let undiciModule = null;
let nativeFallbackLogged = false;
let helperMissingLogged = false;

async function loadNativeDispatcher(proxyUrl, timeoutMs) {
  const key = `${normalizeProxyKey(proxyUrl)}::${timeoutMs}`;
  const cached = nativeDispatchers.get(key);
  if (cached) return cached;
  undiciModule ??= await import("undici");
  const { Agent, ProxyAgent } = undiciModule;
  let dispatcher;
  if (proxyUrl) {
    let protocol = "";
    try { protocol = new URL(proxyUrl).protocol; } catch { /* handled below */ }
    if (!NATIVE_PROXY_PROTOCOLS.has(protocol)) {
      // Never fall back to a direct connection when a proxy was selected.
      throw new Error(`proxy scheme ${protocol || "(unparseable)"} needs wreq-js; only http/https proxies work without it`);
    }
    dispatcher = new ProxyAgent({
      uri: proxyUrl,
      connect: NATIVE_CONNECT,
      requestTls: { ciphers: OPENCODE_CIPHER_LIST },
      headersTimeout: timeoutMs,
    });
  } else {
    dispatcher = new Agent({
      connect: { ...NATIVE_CONNECT, ciphers: OPENCODE_CIPHER_LIST },
      headersTimeout: timeoutMs,
    });
  }
  if (nativeDispatchers.size >= SESSIONS_MAX) {
    const oldestKey = nativeDispatchers.keys().next().value;
    nativeDispatchers.get(oldestKey)?.close?.().catch?.(() => {});
    nativeDispatchers.delete(oldestKey);
  }
  nativeDispatchers.set(key, dispatcher);
  return dispatcher;
}

let loopbackDispatcher = null;

async function viaHelper(bin, url, init, { signal, timeoutMs, proxyUrl }) {
  undiciModule ??= await import("undici");
  loopbackDispatcher ??= new undiciModule.Agent({ headersTimeout: timeoutMs, bodyTimeout: 0 });
  const helper = await getHelper(bin);
  const res = await helperFetch(undiciModule.fetch, helper, url, init, { signal, proxyUrl, dispatcher: loopbackDispatcher });
  if (!proxyUrl) return res;
  const headers = new Headers(res.headers);
  headers.set("x-9r-proxy-via", normalizeProxyKey(proxyUrl) || "helper-proxy");
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

async function nativeTlsFetch(url, init, { signal, timeoutMs, proxyUrl }) {
  if (opensslNeedsHelper()) {
    const bin = resolveHelperPath();
    if (bin) return viaHelper(bin, url, init, { signal, timeoutMs, proxyUrl });
    if (!helperMissingLogged) {
      helperMissingLogged = true;
      console.warn(
        `[OpenCode] Node links OpenSSL ${process.versions.openssl} (< 3.5), whose ClientHello the free tier refuses. ` +
        "Build open-sse/services/opencodeTlsHelper (go build) and set OPENCODE_TLS_HELPER, or place it at <DATA_DIR>/runtime/bin/opencode-tls-helper"
      );
    }
  }
  const dispatcher = await loadNativeDispatcher(proxyUrl, timeoutMs);
  const res = await undiciModule.fetch(url, {
    method: init.method || "GET",
    headers: init.headers,
    body: init.body,
    redirect: "follow",
    signal,
    dispatcher,
  });
  if (!proxyUrl) return res;
  const headers = new Headers(res.headers);
  headers.set("x-9r-proxy-via", normalizeProxyKey(proxyUrl) || "undici-proxy");
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

/** Drop the cached session(s) so the next call builds a fresh one. */
export function resetOpencodeTlsSession() {
  const pending = [...sessionsByProxy.values()];
  sessionsByProxy.clear();
  for (const promise of pending) promise?.then?.((session) => session.close?.()).catch(() => {});
  for (const dispatcher of nativeDispatchers.values()) dispatcher?.close?.().catch?.(() => {});
  nativeDispatchers.clear();
  loopbackDispatcher?.close?.().catch?.(() => {});
  loopbackDispatcher = null;
  stopHelper();
}

/**
 * Fetch through the impersonated-TLS session. Returns a native Response so
 * downstream `.body` / `.text()` / `.json()` consumers keep working unchanged.
 *
 * Streaming is preserved: the response body is handed over as the live
 * ReadableStream, never buffered.
 *
 * `proxyUrl` routes the whole connection (TCP + impersonated TLS) through the
 * selected proxy. wreq-js owns the transport, so no undici dispatcher is
 * involved. Omit it for the direct path.
 */
export async function opencodeTlsFetch(url, init = {}, { signal, timeoutMs = DEFAULT_TIMEOUT_MS, proxyUrl = "" } = {}) {
  let session;
  try {
    session = await loadSession(proxyUrl);
  } catch (wreqError) {
    const wreqReason = wreqError instanceof Error ? wreqError.message : "unknown";
    if (!nativeFallbackLogged) {
      nativeFallbackLogged = true;
      console.warn(`[OpenCode] wreq-js unavailable (${wreqReason}); using the native TLS fallback with the OpenCode cipher list`);
    }
    try {
      return await nativeTlsFetch(url, init, { signal, timeoutMs, proxyUrl });
    } catch (error) {
      if (error?.name === "AbortError" || signal?.aborted) throw error;
      throw new OpencodeTlsUnavailableError(
        `wreq-js unavailable (${wreqReason}) and the Node TLS fallback failed (${error instanceof Error ? error.message : "unknown"})`
      );
    }
  }

  const options = {
    method: init.method || "GET",
    headers: init.headers,
    redirect: "follow",
    timeout: timeoutMs,
  };
  if (init.body !== undefined) options.body = init.body;
  if (signal) options.signal = signal;

  const res = await session.fetch(url, options);
  const headers = {};
  res.headers?.forEach?.((value, key) => {
    headers[key] = value;
  });
  // Transport-level proof, not selection-level: this is only set after the
  // session that actually holds the proxy tunnel returned a response. The
  // value never carries credentials (normalizeProxyKey strips them).
  if (proxyUrl) headers["x-9r-proxy-via"] = session.__proxyKey || "wreq-js-proxy";
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

export const __test__ = { OPENCODE_CIPHER_LIST, normalizeProxyKey, sessionsByProxy, nativeDispatchers };
