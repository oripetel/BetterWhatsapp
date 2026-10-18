// BetterWhatsapp launcher. Attaches to WhatsApp Desktop's WebView2 over the local DevTools port and
// injects inject.js into the WhatsApp page and every worker it starts, before
// their scripts run. Stays alive while WhatsApp runs; exits when it closes.
//
// usage: node launcher.mjs --port <n>
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const args = Object.fromEntries(process.argv.slice(2).join(" ").split("--").filter(Boolean).map((s) => s.trim().split(/\s+/)));
const port = Number(args.port || 9333);
const DEBUG = "debug" in args; // also log page errors and navigations
const LOGO = "data:image/png;base64," + fs.readFileSync(path.join(here, "..", "assets", "logo-64.png")).toString("base64");
const PAYLOAD = fs.readFileSync(path.join(here, "inject.js"), "utf8").replace("__BW_LOGO__", LOGO);
const WA = "https://web.whatsapp.com";
const log = (...a) => console.log(new Date().toISOString(), ...a);

async function wsUrl() {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/json/version`);
      return (await r.json()).webSocketDebuggerUrl;
    } catch { await new Promise((r) => setTimeout(r, 500)); }
  }
  throw new Error(`no DevTools endpoint on port ${port}`);
}

const ws = new WebSocket(await wsUrl());
let nextId = 1;
const pending = new Map();
function send(method, params = {}, sessionId) {
  const id = nextId++;
  ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  return new Promise((res, rej) => pending.set(id, { res, rej, method }));
}
const quiet = (p) => p.catch((e) => log("cdp error:", e.message));

const sessions = new Map(); // sessionId -> { type, url }
const attachedPages = new Set(); // page targetIds we asked to attach to
const injectedPages = new Set(); // page targetIds carrying the payload
let reloadedOnce = false;

// Browser-level auto-attach does not pick up a page WebView2 creates after we
// connect, so attach to new page targets explicitly.
function maybeAttachPage(info) {
  if (info.type !== "page" || attachedPages.has(info.targetId)) return;
  attachedPages.add(info.targetId);
  quiet(send("Target.attachToTarget", { targetId: info.targetId, flatten: true }));
}

async function onAttached({ sessionId, targetInfo, waitingForDebugger }) {
  const { type, url } = targetInfo;
  sessions.set(sessionId, { type, url });
  if (type === "page") {
    // A page can arrive twice (our attachToTarget + its own auto-attach).
    if (injectedPages.has(targetInfo.targetId)) {
      if (waitingForDebugger) await quiet(send("Runtime.runIfWaitingForDebugger", {}, sessionId));
      return;
    }
    injectedPages.add(targetInfo.targetId);
    return onPage(sessionId, url, waitingForDebugger);
  }
  const ours = url.startsWith(WA) && !url.includes("/sw.js");
  if (!ours) {
    if (waitingForDebugger) await quiet(send("Runtime.runIfWaitingForDebugger", {}, sessionId));
    return;
  }
  log("attached", type, url.slice(0, 90), waitingForDebugger ? "(paused)" : "");
  await quiet(send("Runtime.enable", {}, sessionId));
  // Workers spawned by this target attach paused so we can inject first.
  await quiet(send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, sessionId));
  await quiet(send("Runtime.evaluate", { expression: PAYLOAD }, sessionId));
  if (waitingForDebugger) await quiet(send("Runtime.runIfWaitingForDebugger", {}, sessionId));
}

async function onPage(sessionId, url, waitingForDebugger) {
  log("attached page", url.slice(0, 90) || "(blank)");
  await quiet(send("Runtime.enable", {}, sessionId));
  await quiet(send("Page.enable", {}, sessionId));
  // The payload checks its own origin, so it is safe on any document.
  await quiet(send("Page.addScriptToEvaluateOnNewDocument", { source: PAYLOAD }, sessionId));
  await quiet(send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, sessionId));
  if (waitingForDebugger) await quiet(send("Runtime.runIfWaitingForDebugger", {}, sessionId));
  else if (url.startsWith(WA) && !reloadedOnce) {
    // WhatsApp booted before we got here: reload so the hooks go in early.
    reloadedOnce = true;
    log("reloading WhatsApp page for early injection");
    await quiet(send("Page.reload", {}, sessionId));
  }
}

// The page can commit its WhatsApp navigation before addScriptToEvaluateOnNewDocument
// is registered (it attaches while still blank). After every top-level load,
// check the payload is there and reload once more if it isn't.
let rescueReloads = 0;
function checkPayload(sessionId) {
  setTimeout(async () => {
    try {
      const r = await send("Runtime.evaluate", { expression: "!!(globalThis.__betterWhatsapp && globalThis.__betterWhatsapp.ready)", returnByValue: true }, sessionId);
      if (r.result.value || rescueReloads >= 2) return;
      rescueReloads++;
      log("payload missing after load; reloading WhatsApp page");
      await send("Page.reload", {}, sessionId);
    } catch (e) { log("payload check failed:", e.message); }
  }, 2500);
}

ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id) {
    const p = pending.get(msg.id);
    pending.delete(msg.id);
    if (p) msg.error ? p.rej(new Error(`${p.method}: ${msg.error.message}`)) : p.res(msg.result);
    return;
  }
  if (msg.method === "Target.targetCreated" || msg.method === "Target.targetInfoChanged") maybeAttachPage(msg.params.targetInfo);
  else if (msg.method === "Target.attachedToTarget") onAttached(msg.params).catch((e) => log("attach failed:", e.message));
  else if (msg.method === "Target.detachedFromTarget") sessions.delete(msg.params.sessionId);
  else if (msg.method === "Page.frameNavigated" && !msg.params.frame.parentId && msg.params.frame.url.startsWith(WA)) {
    if (DEBUG) log("[nav] Navigated", msg.params.frame.url.slice(0, 80));
    checkPayload(msg.sessionId);
  }
  else if (DEBUG && msg.method === "Runtime.exceptionThrown") {
    const d = msg.params.exceptionDetails;
    log(`[${sessions.get(msg.sessionId)?.type || "?"}] EXC`, (d.exception?.description || d.text || "").slice(0, 500));
  } else if (DEBUG && /^Page\.frame(RequestedNavigation|ScheduledNavigation)$/.test(msg.method)) {
    const p = msg.params;
    if (!p.frame?.parentId) log("[nav]", msg.method.slice(10), p.reason || "", (p.url || p.frame?.url || "").slice(0, 80));
  } else if (msg.method === "Runtime.consoleAPICalled") {
    const a = msg.params.args || [];
    if (DEBUG && (msg.params.type === "error" || msg.params.type === "warning")) {
      log(`[${sessions.get(msg.sessionId)?.type || "?"}] console.${msg.params.type}`, a.map((x) => x.value ?? x.description ?? "").join(" ").slice(0, 500));
    }
    if (a[0]?.value === "[BetterWhatsapp]") {
      const s = sessions.get(msg.sessionId);
      log(`[${s?.type || "?"}]`, a.slice(1).map((x) => x.value ?? x.description ?? "").join(" "));
    }
  }
};
ws.onclose = () => { log("WhatsApp closed; exiting"); process.exit(0); };
ws.onerror = (e) => log("ws error", e.message || "");

await new Promise((r) => (ws.readyState === 1 ? r() : (ws.onopen = r)));
log("connected on port", port);
await send("Target.setDiscoverTargets", { discover: true }); // replays existing targets as targetCreated
