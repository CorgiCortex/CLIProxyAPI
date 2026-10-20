import http from "node:http";
import { chromium } from "playwright";
import { TokenPool } from "./pool.mjs";

// Use a real isolated browser runtime for the public verification SDK. No SDK
// rewriting, account cookies, OAuth credentials, or inference payloads are accepted.
const context = await chromium.launchPersistentContext(process.env.ZCODE_BROWSER_PROFILE || "/tmp/zcode-browser", {
  headless: true,
  ...(process.env.ZCODE_BROWSER_EXECUTABLE ? { executablePath: process.env.ZCODE_BROWSER_EXECUTABLE } : {}),
  ...(process.env.ZCODE_CAPTCHA_PROXY ? { proxy: { server: process.env.ZCODE_CAPTCHA_PROXY } } : {}),
  locale: "en-US",
  timezoneId: "Asia/Shanghai",
  viewport: { width: 1280, height: 800 },
});
let stopping = false;
const pool = new TokenPool(async (version, signal) => {
  signal?.throwIfAborted();
  const page = await context.newPage();
  const abort = () => { void page.close().catch(error => console.error("captcha_page_close_failed", error.name)); };
  signal?.addEventListener("abort", abort, { once: true });
  try {
    // This synthetic document has the official origin while loading only the
    // verification SDK, avoiding the application's unrelated login/UI code.
    await page.route("https://zcode.z.ai/__cliproxy_verification__", route => route.fulfill({
      contentType: "text/html",
      body: '<!doctype html><html><body><div id="captcha"></div><button id="verify">Verify</button></body></html>',
    }));
    await page.goto("https://zcode.z.ai/__cliproxy_verification__", { timeout: 30000 });
    const response = await context.request.get(
      `https://zcode.z.ai/api/v1/client/configs?app_version=${encodeURIComponent(version)}&platform=linux-x64`,
      { timeout: 30000 },
    );
    if (!response.ok()) throw new Error("verification_config_unavailable");
    const config = (await response.json())?.data?.configs?.captcha;
    if (!config?.enabled || !config.sceneId || !config.prefix || !config.region) throw new Error("verification_config_invalid");
    await page.addScriptTag({ url: "https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js" });
    const result = await page.evaluate(config => new Promise((resolve, reject) => {
      window.initAliyunCaptcha({
        SceneId: config.sceneId,
        prefix: config.prefix,
        region: config.region,
        mode: "popup",
        language: "en",
        element: "#captcha",
        button: "#verify",
        getInstance(instance) {
          try { instance.startTracelessVerification(); } catch { reject(new Error("verification_start_failed")); }
        },
        success(result) {
          if (result?.verifyResult === false) { reject(new Error("verification_rejected")); return; }
          resolve(result);
        },
        fail() { reject(new Error("verification_rejected")); },
        onError() { reject(new Error("verification_sdk_failed")); },
      });
    }), config);
    const verifyParam = typeof result === "string" ? result : result?.verifyParam ?? result?.data ?? result?.param;
    return { verifyParam, region: config.region };
  } finally {
    signal?.removeEventListener("abort", abort);
    await page.close();
  }
});

const server = http.createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json");
  if (req.method === "GET" && req.url === "/healthz") {
    res.writeHead(stopping ? 503 : 200).end(JSON.stringify({ ready: !stopping, pending: pool.pending }));
    return;
  }
  if (req.method !== "POST" || req.url !== "/v1/token" || stopping) {
    res.writeHead(404).end('{"error":"not_found"}');
    return;
  }
  const controller = new AbortController();
  // Verification parameter acquisition is the only time-bounded operation.
  const timer = setTimeout(() => controller.abort(), 40000);
  const onClose = () => { if (!res.writableEnded) controller.abort(); };
  res.on("close", onClose);
  try {
    let raw = "";
    for await (const chunk of req) {
      raw += chunk;
      if (raw.length > 4096) { res.writeHead(413).end('{"error":"request_too_large"}'); return; }
    }
    const input = JSON.parse(raw);
    if (Object.keys(input).some(key => key !== "app_version") ||
        typeof input.app_version !== "string" || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(input.app_version)) {
      res.writeHead(400).end('{"error":"invalid_request"}');
      return;
    }
    const token = await pool.take(input.app_version, controller.signal);
    if (!res.destroyed) res.writeHead(200).end(JSON.stringify(token));
  } catch (error) {
    // SDK errors can embed verification material. Keep diagnostics categorical.
    console.error(JSON.stringify({ event: "verification_failed", category: error.name, pending: pool.pending }));
    if (!res.destroyed) res.writeHead(503, { "Retry-After": "15" }).end('{"error":"verification_unavailable"}');
  } finally {
    clearTimeout(timer);
    res.off("close", onClose);
  }
});
server.listen(Number(process.env.PORT || 8318), "127.0.0.1");
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, async () => {
    stopping = true;
    server.close();
    await context.close();
  });
}
