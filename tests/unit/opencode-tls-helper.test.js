import { describe, it, expect, vi, beforeEach } from "vitest";

// Old OpenSSL (FreeBSD base 3.0) sends a ClientHello the OpenCode free gate
// refuses whatever the cipher list, so without wreq-js the client must route
// through the Go helper there, and stay on undici on OpenSSL >= 3.5.
const { loadRuntimeDepMock, undiciMock, helperMock } = vi.hoisted(() => ({
  loadRuntimeDepMock: vi.fn(),
  undiciMock: {
    fetch: vi.fn(),
    Agent: vi.fn(function Agent(opts) { this.opts = opts; this.close = async () => {}; }),
    ProxyAgent: vi.fn(function ProxyAgent(opts) { this.opts = opts; this.close = async () => {}; }),
  },
  helperMock: {
    opensslNeedsHelper: vi.fn(),
    resolveHelperPath: vi.fn(),
    getHelper: vi.fn(),
    stopHelper: vi.fn(),
    helperFetch: vi.fn(),
  },
}));

vi.mock("../../open-sse/services/lazyRuntime.js", () => ({ loadRuntimeDep: loadRuntimeDepMock }));
vi.mock("undici", () => undiciMock);
vi.mock("../../open-sse/services/opencodeTlsHelper.js", () => helperMock);

describe("opencodeTlsClient helper routing", () => {
  beforeEach(() => {
    vi.resetModules();
    loadRuntimeDepMock.mockReset().mockRejectedValue(new Error("Unsupported platform: freebsd-x64"));
    undiciMock.fetch.mockReset().mockResolvedValue(new Response("ok", { status: 200 }));
    undiciMock.Agent.mockClear();
    for (const fn of Object.values(helperMock)) fn.mockReset();
    helperMock.getHelper.mockResolvedValue({ port: 4242, token: "t".repeat(64) });
    helperMock.helperFetch.mockResolvedValue(new Response("data: ok\n\n", { status: 200 }));
  });

  it("uses the helper on OpenSSL < 3.5 when the binary is present", async () => {
    helperMock.opensslNeedsHelper.mockReturnValue(true);
    helperMock.resolveHelperPath.mockReturnValue("/opt/opencode-tls-helper");
    const { opencodeTlsFetch } = await import("../../open-sse/services/opencodeTlsClient.js");

    const res = await opencodeTlsFetch("https://opencode.ai/a", { method: "POST", body: "{}" }, { proxyUrl: "http://u:p@proxy.local:8080" });

    expect(helperMock.getHelper).toHaveBeenCalledWith("/opt/opencode-tls-helper");
    const [, , url, init, opts] = helperMock.helperFetch.mock.calls[0];
    expect(url).toBe("https://opencode.ai/a");
    expect(init).toEqual(expect.objectContaining({ method: "POST", body: "{}" }));
    expect(opts.proxyUrl).toBe("http://u:p@proxy.local:8080");
    expect(res.headers.get("x-9r-proxy-via")).toBe("http://proxy.local:8080");
    // The helper owns the upstream TLS: no undici upstream dispatcher with ciphers.
    expect(undiciMock.Agent.mock.calls.every(([o]) => !o?.connect?.ciphers)).toBe(true);
  });

  it("stays on undici with the cipher list on OpenSSL >= 3.5", async () => {
    helperMock.opensslNeedsHelper.mockReturnValue(false);
    const { opencodeTlsFetch, __test__ } = await import("../../open-sse/services/opencodeTlsClient.js");

    await opencodeTlsFetch("https://opencode.ai/a", {});

    expect(helperMock.helperFetch).not.toHaveBeenCalled();
    expect(undiciMock.Agent.mock.calls[0][0].connect.ciphers).toBe(__test__.OPENCODE_CIPHER_LIST);
  });

  it("falls back to undici (and warns) on old OpenSSL without a helper binary", async () => {
    helperMock.opensslNeedsHelper.mockReturnValue(true);
    helperMock.resolveHelperPath.mockReturnValue(null);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { opencodeTlsFetch } = await import("../../open-sse/services/opencodeTlsClient.js");

    await opencodeTlsFetch("https://opencode.ai/a", {});

    expect(helperMock.helperFetch).not.toHaveBeenCalled();
    expect(undiciMock.fetch).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls.some(([m]) => String(m).includes("opencode-tls-helper"))).toBe(true);
    warn.mockRestore();
  });
});

describe("opensslNeedsHelper", () => {
  it("flags OpenSSL below 3.5 only", async () => {
    const actual = await vi.importActual("../../open-sse/services/opencodeTlsHelper.js");
    expect(actual.opensslNeedsHelper("3.0.20")).toBe(true);
    expect(actual.opensslNeedsHelper("1.1.1w")).toBe(true);
    expect(actual.opensslNeedsHelper("3.4.1")).toBe(true);
    expect(actual.opensslNeedsHelper("3.5.2")).toBe(false);
    expect(actual.opensslNeedsHelper("4.0.0")).toBe(false);
    expect(actual.opensslNeedsHelper("")).toBe(false);
  });
});
