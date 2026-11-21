import { describe, it, expect, vi, beforeEach } from "vitest";

// The free gate keys on the TLS ClientHello: on one process and egress IP the
// same body/headers answered 429 over Node's OpenSSL fingerprint and 200 over
// the cipher list below. These tests pin the wiring, not the upstream.
const { createSessionMock, loadRuntimeDepMock, undiciMock } = vi.hoisted(() => ({
  createSessionMock: vi.fn(),
  loadRuntimeDepMock: vi.fn(),
  undiciMock: {
    fetch: vi.fn(),
    Agent: vi.fn(function Agent(opts) { this.opts = opts; this.close = async () => {}; }),
    ProxyAgent: vi.fn(function ProxyAgent(opts) { this.opts = opts; this.close = async () => {}; }),
  },
}));

vi.mock("../../open-sse/services/lazyRuntime.js", () => ({
  loadRuntimeDep: loadRuntimeDepMock,
}));

vi.mock("undici", () => undiciMock);

describe("opencodeTlsClient", () => {
  beforeEach(async () => {
    vi.resetModules();
    createSessionMock.mockReset();
    loadRuntimeDepMock.mockReset();
    loadRuntimeDepMock.mockResolvedValue({ createSession: createSessionMock });
    undiciMock.fetch.mockReset();
    undiciMock.Agent.mockClear();
    undiciMock.ProxyAgent.mockClear();
  });

  it("uses the cipher list the upstream accepts and sends ALPN-negotiated requests", async () => {
    const response = new Response("data: ok\n\n", {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    });
    const fetchMock = vi.fn().mockResolvedValue(response);
    createSessionMock.mockResolvedValue({ fetch: fetchMock, close: vi.fn() });

    const { opencodeTlsFetch, __test__ } = await import("../../open-sse/services/opencodeTlsClient.js");
    const result = await opencodeTlsFetch("https://opencode.ai/inference/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });

    expect(createSessionMock).toHaveBeenCalledTimes(1);
    const options = createSessionMock.mock.calls[0][0];
    expect(options.emulation.tlsOptions.cipherList).toBe(__test__.OPENCODE_CIPHER_LIST);
    // BoringSSL family list: AES-128-GCM first plus the legacy CBC entries the
    // upstream fingerprints on. Dropping any of them is refused upstream.
    expect(__test__.OPENCODE_CIPHER_LIST.split(":")).toHaveLength(17);
    expect(__test__.OPENCODE_CIPHER_LIST.startsWith("TLS_AES_128_GCM_SHA256")).toBe(true);

    expect(fetchMock).toHaveBeenCalledWith(
      "https://opencode.ai/inference/v1/chat/completions",
      expect.objectContaining({ method: "POST", body: "{}" })
    );
    expect(result.status).toBe(200);
    expect(result.headers.get("content-type")).toBe("text/event-stream");
  });

  it("reuses one session across requests", async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response("ok", { status: 200 }));
    createSessionMock.mockResolvedValue({ fetch: fetchMock, close: vi.fn() });

    const { opencodeTlsFetch } = await import("../../open-sse/services/opencodeTlsClient.js");
    await opencodeTlsFetch("https://opencode.ai/a", {});
    await opencodeTlsFetch("https://opencode.ai/b", {});

    expect(createSessionMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("falls back to undici with the same cipher list when wreq-js is unavailable", async () => {
    // e.g. FreeBSD: wreq-js ships no binary for the platform.
    loadRuntimeDepMock.mockRejectedValue(new Error("Unsupported platform: freebsd-x64"));
    undiciMock.fetch.mockResolvedValue(new Response("data: ok\n\n", { status: 200 }));

    const { opencodeTlsFetch, __test__ } = await import("../../open-sse/services/opencodeTlsClient.js");
    const result = await opencodeTlsFetch("https://opencode.ai/a", { method: "POST", body: "{}" });

    expect(result.status).toBe(200);
    expect(undiciMock.Agent).toHaveBeenCalledTimes(1);
    expect(undiciMock.Agent.mock.calls[0][0].connect.ciphers).toBe(__test__.OPENCODE_CIPHER_LIST);
    expect(undiciMock.fetch.mock.calls[0][1]).toEqual(expect.objectContaining({ method: "POST", body: "{}" }));
  });

  it("routes the fallback through an http proxy with the cipher list on the tunnelled TLS", async () => {
    loadRuntimeDepMock.mockRejectedValue(new Error("Unsupported platform: freebsd-x64"));
    undiciMock.fetch.mockResolvedValue(new Response("ok", { status: 200 }));

    const { opencodeTlsFetch, __test__ } = await import("../../open-sse/services/opencodeTlsClient.js");
    const result = await opencodeTlsFetch("https://opencode.ai/a", {}, { proxyUrl: "http://user:pw@proxy.local:8080" });

    expect(undiciMock.ProxyAgent).toHaveBeenCalledTimes(1);
    const options = undiciMock.ProxyAgent.mock.calls[0][0];
    expect(options.uri).toBe("http://user:pw@proxy.local:8080");
    expect(options.requestTls.ciphers).toBe(__test__.OPENCODE_CIPHER_LIST);
    expect(undiciMock.Agent).not.toHaveBeenCalled();
    // Credentials never leak into the proof header.
    expect(result.headers.get("x-9r-proxy-via")).toBe("http://proxy.local:8080");
  });

  it("refuses a socks proxy in the fallback instead of leaving over the direct IP", async () => {
    loadRuntimeDepMock.mockRejectedValue(new Error("Unsupported platform: freebsd-x64"));

    const { opencodeTlsFetch, OpencodeTlsUnavailableError } = await import(
      "../../open-sse/services/opencodeTlsClient.js"
    );

    await expect(
      opencodeTlsFetch("https://opencode.ai/a", {}, { proxyUrl: "socks5://proxy.local:1080" })
    ).rejects.toBeInstanceOf(OpencodeTlsUnavailableError);
    expect(undiciMock.fetch).not.toHaveBeenCalled();
    expect(undiciMock.Agent).not.toHaveBeenCalled();
  });

  it("forwards the abort signal so a cancelled stream stops upstream", async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response("ok", { status: 200 }));
    createSessionMock.mockResolvedValue({ fetch: fetchMock, close: vi.fn() });

    const { opencodeTlsFetch } = await import("../../open-sse/services/opencodeTlsClient.js");
    const controller = new AbortController();
    await opencodeTlsFetch("https://opencode.ai/a", {}, { signal: controller.signal });

    expect(fetchMock.mock.calls[0][1].signal).toBe(controller.signal);
  });
});
