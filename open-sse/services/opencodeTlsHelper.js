// Runs the Go loopback forwarder in ./opencodeTlsHelper/ for the OpenCode free tier.
//
// Needed only when wreq-js cannot load AND Node links OpenSSL < 3.5 (FreeBSD
// base ships 3.0). That OpenSSL's ClientHello is refused even with the right
// cipher list (it appends TLS_EMPTY_RENEGOTIATION_INFO_SCSV and sends an older
// extension set), and no Node TLS option fixes it. The Go forwarder replays the
// hello Node + OpenSSL 3.5 sends, which the gate accepts.
//
// Binary lookup: OPENCODE_TLS_HELPER, then <DATA_DIR>/runtime/bin/opencode-tls-helper.
// Build: cd open-sse/services/opencodeTlsHelper && CGO_ENABLED=0 go build -trimpath -o <path> .
// (cross-compile for FreeBSD with GOOS=freebsd GOARCH=amd64).

import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { getWritableDataDir } from "../utils/writableDataDir.js";

const START_TIMEOUT_MS = 10000;
const BIN_NAME = process.platform === "win32" ? "opencode-tls-helper.exe" : "opencode-tls-helper";

/** True when this Node's OpenSSL appends the renegotiation SCSV (anything below 3.5). */
export function opensslNeedsHelper(version = process.versions.openssl) {
  const m = /^(\d+)\.(\d+)/.exec(String(version || ""));
  if (!m) return false;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  return major < 3 || (major === 3 && minor < 5);
}

export function resolveHelperPath() {
  const candidates = [
    process.env.OPENCODE_TLS_HELPER,
    path.join(getWritableDataDir(), "runtime", "bin", BIN_NAME),
  ].filter(Boolean);
  for (const p of candidates) {
    try {
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch { /* try next */ }
  }
  return null;
}

let helperPromise = null;

function startHelper(bin) {
  const token = crypto.randomBytes(32).toString("hex");
  return new Promise((resolve, reject) => {
    const child = spawn(bin, [], {
      env: { ...process.env, OPENCODE_TLS_TOKEN: token },
      // stdin stays open: the helper exits when it closes (parent gone).
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("opencode TLS helper did not start"));
    }, START_TIMEOUT_MS);
    const onExit = (code) => {
      clearTimeout(timer);
      reject(new Error(`opencode TLS helper exited (${code})${err ? `: ${err.trim().slice(0, 200)}` : ""}`));
    };
    child.on("error", (e) => { clearTimeout(timer); reject(e); });
    child.on("exit", onExit);
    child.stderr.on("data", (c) => { err += c; });
    child.stdout.on("data", (c) => {
      out += c;
      const m = out.match(/PORT (\d+)/);
      if (!m) return;
      clearTimeout(timer);
      child.off("exit", onExit);
      // A later crash drops the cached handle so the next request restarts it.
      child.once("exit", () => { helperPromise = null; });
      child.unref();
      child.stdout.unref?.();
      child.stderr.unref?.();
      child.stdin.unref?.();
      resolve({ child, port: Number(m[1]), token });
    });
  });
}

export function getHelper(bin) {
  helperPromise ??= startHelper(bin).catch((error) => {
    helperPromise = null;
    throw error;
  });
  return helperPromise;
}

export function stopHelper() {
  const pending = helperPromise;
  helperPromise = null;
  pending?.then(({ child }) => child.kill()).catch(() => {});
}

/**
 * Send one request through the helper. `fetchImpl` is undici's fetch (loopback,
 * plain http). Returns the helper's response, or throws when the helper itself
 * reported an error (marked by X-9r-Helper-Error).
 */
export async function helperFetch(fetchImpl, helper, url, init, { signal, proxyUrl, dispatcher }) {
  const headers = new Headers(init.headers || {});
  headers.set("X-9r-Helper-Token", helper.token);
  headers.set("X-9r-Target", String(url));
  if (proxyUrl) headers.set("X-9r-Proxy", proxyUrl);
  const res = await fetchImpl(`http://127.0.0.1:${helper.port}/`, {
    method: init.method || "GET",
    headers,
    body: init.body,
    redirect: "manual",
    signal,
    dispatcher,
  });
  if (res.headers.get("x-9r-helper-error")) {
    const msg = (await res.text().catch(() => "")).trim().slice(0, 300);
    throw new Error(`opencode TLS helper: ${msg || res.status}`);
  }
  return res;
}
