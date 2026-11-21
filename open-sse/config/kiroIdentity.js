/**
 * The Kiro IDE identity 9router presents to Kiro's runtime / CodeWhisperer.
 *
 * Kiro refuses old clients by their user agent ("This version of Kiro is no
 * longer supported. Please update to the latest version of Kiro to continue.").
 * The format below is what Kiro IDE 1.4.121 (agent KAS 0.66.89, Electron's
 * Node 24.22.1) sends from its KiroRuntime AWS SDK client, as documented by
 * magpie's Kiro plugin (magpie-community/plugins, packages/kiro/index.mjs):
 *
 *   User-Agent:       aws-sdk-js/1.0.0 ua/2.1 os/<os>#<release> lang/js md/nodejs#<node>
 *                     api/kiroruntime#1.0.0 m/N KiroIDE-<ver>-<machineId>-KAS/<kas> acp-client/kiro-ide
 *   x-amz-user-agent: aws-sdk-js/1.0.0 KiroIDE-<ver>-<machineId>-KAS/<kas> acp-client/kiro-ide
 *
 * When Kiro raises its minimum again, bump the defaults or override at runtime
 * with KIRO_IDE_VERSION / KIRO_IDE_KAS_VERSION / KIRO_IDE_NODE_VERSION.
 */

import { createHash } from "crypto";

export const KIRO_IDE_VERSION = process.env.KIRO_IDE_VERSION || "1.4.121";
export const KIRO_IDE_KAS_VERSION = process.env.KIRO_IDE_KAS_VERSION || "0.66.89";
export const KIRO_IDE_NODE_VERSION = process.env.KIRO_IDE_NODE_VERSION || "24.22.1";
// A fixed desktop OS keeps every account's fingerprint the same shape
// regardless of where 9router runs (FreeBSD, Docker, ...).
const KIRO_IDE_OS = "darwin";
const KIRO_IDE_OS_RELEASE = "25.6.0";

/**
 * Stable per-account machine id (the IDE sends node-machine-id's sha256).
 * Seeded per credential so the same account always looks like one install
 * and different accounts never share one.
 */
export function kiroMachineId(credentials) {
  const seed =
    credentials?.providerSpecificData?.clientId
    || credentials?.refreshToken
    || credentials?.providerSpecificData?.profileArn
    || credentials?.accessToken
    || credentials?.apiKey
    || "kiro-anonymous";
  return createHash("sha256").update(String(seed)).digest("hex");
}

/** The IDE's own app token, appended to both user agents. */
export function kiroIdeApp(machineId) {
  return `KiroIDE-${KIRO_IDE_VERSION}-${machineId}-KAS/${KIRO_IDE_KAS_VERSION} acp-client/kiro-ide`;
}

/** User-Agent + x-amz-user-agent + client attribution, as Kiro IDE sends them. */
export function buildKiroIdeUserAgentHeaders(credentials) {
  const app = kiroIdeApp(kiroMachineId(credentials));
  return {
    "User-Agent":
      `aws-sdk-js/1.0.0 ua/2.1 os/${KIRO_IDE_OS}#${KIRO_IDE_OS_RELEASE} lang/js ` +
      `md/nodejs#${KIRO_IDE_NODE_VERSION} api/kiroruntime#1.0.0 m/N ${app}`,
    "X-Amz-User-Agent": `aws-sdk-js/1.0.0 ${app}`,
    "x-amzn-kiro-client-attribution": "kiro-ide",
  };
}
