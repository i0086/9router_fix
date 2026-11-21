import { describe, it, expect } from "vitest";
import { buildKiroIdeUserAgentHeaders, KIRO_IDE_VERSION, KIRO_IDE_KAS_VERSION } from "../../open-sse/config/kiroIdentity.js";
import { KiroExecutor } from "../../open-sse/executors/kiro.js";

// Kiro answers 400 "This version of Kiro is no longer supported" to the old
// "kiro-ide/1.0.0" user agent. Every Kiro call must present the IDE identity.
const creds = { accessToken: "a", refreshToken: "r1", providerSpecificData: { clientId: "client-1" } };

describe("Kiro IDE identity", () => {
  it("builds the IDE's SDK user agent with a per-account machine id", () => {
    const h = buildKiroIdeUserAgentHeaders(creds);
    const app = new RegExp(`KiroIDE-${KIRO_IDE_VERSION.replace(/\./g, "\\.")}-[0-9a-f]{64}-KAS/${KIRO_IDE_KAS_VERSION.replace(/\./g, "\\.")} acp-client/kiro-ide$`);
    expect(h["User-Agent"]).toMatch(/^aws-sdk-js\/1\.0\.0 ua\/2\.1 os\/\S+ lang\/js md\/nodejs#\S+ api\/kiroruntime#1\.0\.0 m\/N /);
    expect(h["User-Agent"]).toMatch(app);
    expect(h["X-Amz-User-Agent"]).toMatch(app);
    expect(h["x-amzn-kiro-client-attribution"]).toBe("kiro-ide");
  });

  it("keeps one machine id per account and different ids across accounts", () => {
    const a = buildKiroIdeUserAgentHeaders(creds)["X-Amz-User-Agent"];
    expect(buildKiroIdeUserAgentHeaders(creds)["X-Amz-User-Agent"]).toBe(a);
    const other = { ...creds, providerSpecificData: { clientId: "client-2" } };
    expect(buildKiroIdeUserAgentHeaders(other)["X-Amz-User-Agent"]).not.toBe(a);
  });

  it("chat requests no longer send the retired kiro-ide/1.0.0 agent", () => {
    const headers = new KiroExecutor().buildHeaders(creds, true, "https://runtime.us-east-1.kiro.dev/generateAssistantResponse");
    expect(headers["User-Agent"]).not.toContain("kiro-ide/1.0.0");
    expect(headers["X-Amz-User-Agent"]).not.toContain("kiro-ide/1.0.0");
    expect(headers["User-Agent"]).toContain(`KiroIDE-${KIRO_IDE_VERSION}-`);
    // No duplicate lower-case variant that would be merged into the same header.
    expect(Object.keys(headers).filter((k) => k.toLowerCase() === "x-amz-user-agent")).toHaveLength(1);
  });
});
