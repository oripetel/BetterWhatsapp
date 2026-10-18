// BetterWhatsapp payload (anti-delete). Injected over CDP into the WhatsApp Desktop
// WebView2 page and into its web workers, before WhatsApp's own scripts run.
//
// Capture: wraps WAWebDBProcessRevokeMsgs (the code that turns a message row
// into a "revoked" stub). Right before WhatsApp applies a delete-for-everyone,
// the original row is read from WhatsApp's message table and written to our own
// IndexedDB ("wa-antidelete"), AES-GCM encrypted with a non-extractable key.
// In the page, the photo / video / voice note itself is then fetched through
// WhatsApp's own download manager and stored the same way.
//
// Display: wraps the WAWebMessageRevoked bubble and the chat-list preview text
// so a revoked message we preserved shows its original content plus a badge.
//
// Control: a card under the profile photo in the "You" settings drawer
// (WAWebMeTabFlow) toggles the mod and opens a list of every saved message.
//
// Nothing here sends anything anywhere. Message content is never logged.
(() => {
  "use strict";
  // Re-injecting (development) replaces the previous copy cleanly.
  const prev = globalThis.__betterWhatsapp;
  if (prev) {
    if (typeof prev.dispose !== "function") return;
    try { prev.dispose(); } catch {}
  }
  // Documents only: touching `location` in a worker that is still paused at
  // start blocks the evaluation (WhatsApp then times out and reloads). The
  // launcher only injects into web.whatsapp.com workers anyway.
  if (typeof document !== "undefined" && location.origin !== "https://web.whatsapp.com") return;
  const AD = (globalThis.__betterWhatsapp = { version: 2, patched: [] });
  const undo = []; // run by dispose(), newest first

  const TAG = "[BetterWhatsapp]";
  // The launcher swaps this for a data: URL of assets/logo-64.png.
  const LOGO = "__BW_LOGO__";
  const hasLogo = LOGO.startsWith("data:");
  const log = (...a) => { try { console.log(TAG, ...a); } catch {} };
  const isPage = typeof document !== "undefined";

  // ---------------------------------------------------------------- storage
  const DB_NAME = "wa-antidelete"; // pre-rename name, kept so saved messages survive
  const DB_VERSION = 2;
  const STORE = "msgs"; // { k, o, t, iv, ct } — ct = encrypted record JSON
  const KEYS = "keys"; // "k" -> CryptoKey, "settings" -> settings object
  const MEDIA = "media"; // { k, iv, ct, mime, size } — ct = encrypted file bytes
  const MAX_MEDIA = 64 * 1024 * 1024;
  const reqP = (r) => new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
  const txDone = (tx) => new Promise((res, rej) => { tx.oncomplete = res; tx.onerror = tx.onabort = () => rej(tx.error); });

  let dbP;
  function openDb() {
    return (dbP ||= new Promise((res, rej) => {
      const q = indexedDB.open(DB_NAME, DB_VERSION);
      q.onupgradeneeded = () => {
        const d = q.result;
        if (!d.objectStoreNames.contains(STORE)) d.createObjectStore(STORE, { keyPath: "k" }).createIndex("origId", "o");
        if (!d.objectStoreNames.contains(KEYS)) d.createObjectStore(KEYS);
        if (!d.objectStoreNames.contains(MEDIA)) d.createObjectStore(MEDIA, { keyPath: "k" });
      };
      q.onsuccess = () => {
        const d = q.result;
        d.onversionchange = () => { d.close(); dbP = null; };
        res(d);
      };
      q.onerror = () => { dbP = null; rej(q.error); };
      q.onblocked = () => log("database upgrade is waiting for an older copy of the mod to close");
    }));
  }
  undo.push(() => { if (dbP) dbP.then((d) => d.close()).catch(() => {}); dbP = null; });

  let keyP;
  function getKey() {
    return (keyP ||= (async () => {
      const d = await openDb();
      const existing = await reqP(d.transaction(KEYS).objectStore(KEYS).get("k"));
      if (existing) return existing;
      const fresh = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      // The page and the worker can race here; whoever commits first wins.
      const tx = d.transaction(KEYS, "readwrite");
      const st = tx.objectStore(KEYS);
      const again = await reqP(st.get("k"));
      if (!again) st.put(fresh, "k");
      await txDone(tx);
      return again || fresh;
    })().catch((err) => { keyP = null; throw err; }));
  }

  // JSON that survives ArrayBuffers / typed arrays (media keys, hashes).
  const b64 = (u8) => { let s = ""; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const toJson = (v) => JSON.stringify(v, function (k, x) {
    const raw = this[k];
    if (Object.prototype.toString.call(raw) === "[object ArrayBuffer]") return { $b: b64(new Uint8Array(raw)) };
    if (ArrayBuffer.isView(raw)) return { $b: b64(new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength)) };
    if (typeof x === "bigint") return String(x);
    return x;
  });
  const fromJson = (s) => JSON.parse(s, (k, x) => (x && typeof x === "object" && typeof x.$b === "string" && Object.keys(x).length === 1 ? unb64(x.$b) : x));
  const toArrayBuffer = (v) => (ArrayBuffer.isView(v) ? v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength) : v);

  async function encryptBytes(bytes) {
    const key = await getKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return { iv, ct: await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes) };
  }
  async function decryptBytes(row) {
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: row.iv }, await getKey(), row.ct);
  }
  const encryptRecord = (obj) => encryptBytes(new TextEncoder().encode(toJson(obj)));
  const decryptRecord = async (row) => fromJson(new TextDecoder().decode(await decryptBytes(row)));

  async function saveRecords(recs) {
    if (!recs.length) return;
    const rows = [];
    for (const r of recs) {
      const { iv, ct } = await encryptRecord(r);
      rows.push({ k: r.k, o: r.origId, t: r.capturedAt || Date.now(), iv, ct });
    }
    const d = await openDb();
    const tx = d.transaction(STORE, "readwrite");
    for (const row of rows) tx.objectStore(STORE).put(row);
    await txDone(tx);
    // No BroadcastChannel to the page: creating one in WhatsApp's worker makes
    // the app reload in a loop. The page reads misses from IndexedDB instead.
    for (const r of recs) cache.set(r.k, r);
    emit();
  }

  async function loadRecord(k) {
    const d = await openDb();
    const row = await reqP(d.transaction(STORE).objectStore(STORE).get(k));
    return row ? decryptRecord(row) : null;
  }

  async function saveMedia(k, bytes, mime) {
    const { iv, ct } = await encryptBytes(bytes);
    const d = await openDb();
    const tx = d.transaction(MEDIA, "readwrite");
    tx.objectStore(MEDIA).put({ k, iv, ct, mime, size: bytes.byteLength });
    await txDone(tx);
  }
  async function loadMediaBlob(k) {
    const d = await openDb();
    const row = await reqP(d.transaction(MEDIA).objectStore(MEDIA).get(k));
    return row ? new Blob([await decryptBytes(row)], { type: row.mime || "" }) : null;
  }

  async function deleteRecords(keys) {
    const d = await openDb();
    const tx = d.transaction([STORE, MEDIA], "readwrite");
    for (const k of keys) { tx.objectStore(STORE).delete(k); tx.objectStore(MEDIA).delete(k); }
    await txDone(tx);
    for (const k of keys) { cache.delete(k); forgetMediaUrl(k); }
    emit();
  }
  async function clearAll() {
    const d = await openDb();
    const tx = d.transaction([STORE, MEDIA], "readwrite");
    tx.objectStore(STORE).clear();
    tx.objectStore(MEDIA).clear();
    await txDone(tx);
    for (const k of [...cache.keys()]) forgetMediaUrl(k);
    cache.clear();
    emit();
  }

  // --------------------------------------------------------------- settings
  // Kept in IndexedDB rather than localStorage so the worker sees them too.
  const DEFAULTS = { enabled: true, reveal: true, media: true };
  let settings = { ...DEFAULTS };
  async function readSettings() {
    try {
      const d = await openDb();
      const s = await reqP(d.transaction(KEYS).objectStore(KEYS).get("settings"));
      settings = { ...DEFAULTS, ...(s || {}) };
    } catch {}
    return settings;
  }
  async function setSetting(name, value) {
    settings = { ...settings, [name]: value };
    emit();
    try {
      const d = await openDb();
      const tx = d.transaction(KEYS, "readwrite");
      tx.objectStore(KEYS).put(settings, "settings");
      await txDone(tx);
    } catch (err) { log("settings not saved:", err && err.message); }
    if (name === "media" && value) for (const r of cache.values()) queueMedia(r);
  }
  AD.settings = () => ({ ...settings });

  // ------------------------------------------------------- in-memory store
  const cache = new Map(); // post-revoke msg key string -> record
  const listeners = new Set();
  let version = 0;
  function emit() { version++; for (const fn of listeners) { try { fn(); } catch {} } }
  const subscribe = (fn) => { listeners.add(fn); return () => listeners.delete(fn); };
  AD.cache = cache;

  // Cache miss (record written by the worker after our initial load): read it
  // from IndexedDB, retrying once in case the write is still in flight.
  const lookedUp = new Map();
  function ensureLoaded(k) {
    if (!k || cache.has(k)) return;
    const n = lookedUp.get(k) || 0;
    if (n >= 2) return;
    lookedUp.set(k, n + 1);
    setTimeout(() => loadRecord(k).then((r) => {
      if (!r) return;
      if (r.v !== 2) r = upgradeRecord(r);
      cache.set(r.k, r);
      emit();
      queueMedia(r);
    }).catch(() => {}), n ? 1500 : 0);
  }

  function stats() {
    let n = 0, withMedia = 0, bytes = 0, last = 0;
    for (const r of cache.values()) {
      n++;
      if (r.media && r.media.state === "saved") { withMedia++; bytes += r.media.size || 0; }
      last = Math.max(last, r.capturedAt || 0);
    }
    return { n, withMedia, bytes, last };
  }

  // ---------------------------------------------------------------- capture
  const req = (name) => globalThis.require(name); // default export if any, else exports
  const ns = (name) => (globalThis.importNamespace ? globalThis.importNamespace(name) : globalThis.require(name));

  function withTimeout(p, ms) {
    return Promise.race([p, new Promise((res) => setTimeout(() => res("timeout"), ms))]);
  }

  // Rows keep body/caption/filename/etc. inside msgRowOpaqueData (a protobuf);
  // WhatsApp's own serializer moves them back onto the row. On failure the
  // opaque bytes stay in the record so a later version can expand them.
  function expandRow(row) {
    const copy = { ...row };
    if (copy.msgRowOpaqueData == null) return copy;
    copy.msgRowOpaqueData = toArrayBuffer(copy.msgRowOpaqueData);
    try {
      ns("WAWebDBMessageSerialization").movFieldFromOpaqueDataBackToMsg(copy);
      delete copy.msgRowOpaqueData;
    } catch (err) { log("expand failed:", err && err.message); }
    return copy;
  }

  // Drop the ~80 empty columns every row carries.
  function compact(row) {
    const o = {};
    for (const [k, v] of Object.entries(row)) {
      if (v == null || v === "" || (Array.isArray(v) && !v.length)) continue;
      o[k] = v;
    }
    return o;
  }

  const widStr = (w) => (w == null ? null : typeof w === "string" ? w : w._serialized || (w.user && w.server ? `${w.user}@${w.server}` : String(w)));

  // Message key strings look like "<fromMe>_<chat>_<id>[_<participant>]".
  function fillMeta(rec) {
    const m = rec.msg || {};
    if (rec.chat == null) {
      const parts = String(widStr(m.id) || rec.origId || "").split("_");
      rec.fromMe = parts[0] === "true";
      rec.chat = parts[1] || null;
    }
    if (rec.sender === undefined) rec.sender = widStr(m.author) || (rec.fromMe ? null : widStr(m.from));
    if (rec.sentAt == null) rec.sentAt = m.t ?? null;
    return rec;
  }

  const MEDIA_TYPES = new Set(["image", "video", "ptv", "ptt", "audio", "document", "sticker"]);
  const hasMedia = (m) => !!(m && MEDIA_TYPES.has(m.type) && m.directPath && m.mediaKey);

  // Records written by version 1 kept the raw row (often with the text still
  // inside msgRowOpaqueData) and no metadata.
  function upgradeRecord(r) {
    const next = fillMeta({ ...r, v: 2, msg: compact(expandRow(r.msg || {})) });
    next.media = hasMedia(next.msg) ? { state: "pending" } : null;
    return next;
  }

  async function captureBeforeRevoke(items) {
    if (!Array.isArray(items) || !items.length) return;
    if (!(await readSettings()).enabled) return;
    const Table = ns("WAWebSchemaMessage").getMessageTable();
    const Lid = ns("WAWebLidMigrationUtils");
    const Revoke = ns("WAWebRevoke");
    const MsgKey = req("WAWebMsgKey");
    const ids = items.map((e) => String(e.revokeMsgKey));
    const alt = items.map((e) => { try { const a = Lid.getAlternateMsgKey(e.revokeMsgKey); return a ? String(a) : ""; } catch { return ""; } });
    const rows = await Table.bulkGet([...ids, ...alt]); // decrypted rows
    const n = items.length;
    const recs = [];
    items.forEach((e, i) => {
      const orig = rows[i] || rows[n + i];
      if (!orig || orig.type === "revoked") return;
      let after;
      try { after = String(Revoke.getMsgKeyAfterRevoke({ originalKey: MsgKey.from(orig.id), revokeKey: e.newMsgKey })); } catch { return; }
      const msg = compact(expandRow(orig));
      recs.push(fillMeta({
        v: 2,
        k: after,
        origId: String(orig.id),
        subtype: e.subtype || "sender_revoke",
        revokedBy: e.sender ? String(e.sender) : null,
        revokedAt: e.revokeTimestamp ?? null,
        capturedAt: Date.now(),
        msg,
        media: hasMedia(msg) ? { state: "pending" } : null,
      }));
    });
    await saveRecords(recs);
    log(`preserved ${recs.length}/${n} deleted message(s)`);
    for (const r of recs) queueMedia(r);
  }

  // ------------------------------------------------------------------ media
  // Page only: fetch the file through WhatsApp's own download manager (it
  // serves from WhatsApp's cache when the media was already opened).
  const mediaJobs = new Map(); // k -> Promise
  function queueMedia(rec, force) {
    if (!isPage || !rec || !rec.media || mediaJobs.has(rec.k)) return;
    if (rec.media.state === "saved") return;
    if (!force && (!settings.media || rec.media.state !== "pending")) return;
    const job = fetchMedia(rec).finally(() => { mediaJobs.delete(rec.k); emit(); });
    mediaJobs.set(rec.k, job);
    emit();
  }

  function mediaTypeOf(m) {
    try { const t = ns("WAWebMmsMediaTypes").msgToMediaType({ type: m.type, isGif: !!m.isGif }); if (t) return t; } catch {}
    return m.type === "video" && m.isGif ? "gif" : m.type;
  }

  async function fetchMedia(rec) {
    const m = rec.msg;
    let media;
    try {
      if (m.size > MAX_MEDIA) media = { state: "skipped" };
      else {
        const buf = await downloadBytes(m);
        const mime = m.mimetype || (m.type === "sticker" ? "image/webp" : "");
        await saveMedia(rec.k, buf, mime);
        media = { state: "saved", size: buf.byteLength, mime };
      }
    } catch (err) {
      media = { state: "failed", error: String((err && (err.name || err.message)) || "error").slice(0, 80) };
      log("media not saved:", media.error);
    }
    const cur = cache.get(rec.k);
    if (cur) await saveRecords([{ ...cur, media }]);
  }

  function downloadBytes(m) {
    const Qpl = ns("WAWebStartMediaDownloadQpl");
    return ns("WAWebDownloadManager").downloadManager.downloadAndMaybeDecrypt({
      directPath: m.directPath,
      encFilehash: m.encFilehash,
      filehash: m.filehash,
      mediaKey: m.mediaKey,
      mediaKeyTimestamp: m.mediaKeyTimestamp,
      mimetype: m.mimetype,
      type: mediaTypeOf(m),
      signal: new AbortController().signal,
      userDownloadAttemptCount: 0,
      downloadQpl: Qpl.startMediaDownloadQpl({ entryPoint: "DownloadRichResponseMedia" }),
    });
  }

  const mediaUrls = new Map(); // k -> Promise<string|null>
  const mediaUrlReady = new Map(); // k -> string|null
  function getMediaUrl(k) {
    if (!mediaUrls.has(k)) {
      mediaUrls.set(k, loadMediaBlob(k).then((b) => {
        const u = b ? URL.createObjectURL(b) : null;
        mediaUrlReady.set(k, u);
        return u;
      }).catch(() => null));
    }
    return mediaUrls.get(k);
  }
  function forgetMediaUrl(k) {
    const u = mediaUrlReady.get(k);
    if (u) URL.revokeObjectURL(u);
    mediaUrls.delete(k);
    mediaUrlReady.delete(k);
  }
  undo.push(() => { for (const k of [...mediaUrls.keys()]) forgetMediaUrl(k); });

  // Diagnostics: runs the capture pipeline (read → expand → encrypt → decrypt)
  // on an existing message without storing it. Returns shape info only.
  AD.selfTest = async (msgId) => {
    const [row] = await ns("WAWebSchemaMessage").getMessageTable().bulkGet([String(msgId)]);
    if (!row) return { found: false };
    const expanded = compact(expandRow(row));
    const back = await decryptRecord(await encryptRecord({ msg: expanded }));
    const d = describe(back.msg);
    let mediaBytes = null;
    if (hasMedia(back.msg)) { try { mediaBytes = (await downloadBytes(back.msg)).byteLength; } catch (err) { mediaBytes = "error: " + (err && (err.name || err.message)); } }
    return { found: true, type: back.msg.type, textLen: (d.text || "").length, sameBody: back.msg.body === expanded.body, hasThumb: looksLikeJpegB64(d.thumb), hasMedia: hasMedia(back.msg), mediaBytes };
  };

  // --------------------------------------------------------- patch helpers
  // Every replaced export remembers the original so dispose() can put it back
  // and a re-injected copy never wraps a wrapper.
  function replaceExport(obj, key, make) {
    let orig = obj[key];
    if (typeof orig !== "function") return false;
    if (orig.__adOrig) orig = orig.__adOrig;
    const next = make(orig);
    next.__adOrig = orig;
    obj[key] = next;
    undo.push(() => { if (obj[key] === next) obj[key] = orig; });
    return true;
  }

  function wrapRevokeFn(orig) {
    return function (items) {
      const self = this, args = arguments;
      return withTimeout(captureBeforeRevoke(items).catch((err) => log("capture failed:", err && err.message)), 3000)
        .then(() => orig.apply(self, args));
    };
  }

  function patchCapture(exportsObj) {
    const a = replaceExport(exportsObj, "processRevokeMsgs", wrapRevokeFn);
    const b = replaceExport(exportsObj, "processRevokeMsgsAndGetCleanupEligibleKeys", wrapRevokeFn);
    if (a || b) { AD.patched.push("capture"); log("capture hook installed", isPage ? "(page)" : "(worker)"); }
  }

  // ------------------------------------------------------------ formatting
  // Follows WhatsApp's UI language. Resolved on first use: at document start
  // there is no <html> element yet.
  let lang = null;
  function uiLang() {
    if (lang) return lang;
    const el = isPage ? document.documentElement : null;
    if (!el || !el.lang) return "en";
    return (lang = /^he\b/i.test(el.lang) ? "he" : "en");
  }
  const STR = {
    en: {
      dir: "ltr",
      title: "BetterWhatsapp",
      feature: "Anti-Delete",
      active: "On",
      paused: "Paused. New deletions aren't saved",
      nSaved: (n) => `${n} saved`,
      last: (t) => `last ${t}`,
      reveal: "Show deleted content",
      saveMedia: "Save photos & voice notes",
      viewer: "Deleted messages",
      deleted: "Deleted",
      deletedByAdmin: "Deleted by admin",
      deletedForEveryone: "Deleted for everyone",
      by: (n) => `by ${n}`,
      unrecoverable: "This message's text couldn't be recovered",
      savingMedia: "Saving media…",
      mediaFailed: "Couldn't save the media",
      mediaOff: "Media not kept",
      tooLarge: "Too large to keep",
      retry: "Retry",
      saveNow: "Keep it",
      search: "Search deleted messages",
      all: "All",
      text: "Text",
      media: "Media",
      openChat: "Open chat",
      copy: "Copy",
      copied: "Copied",
      remove: "Remove",
      download: "Download",
      export: "Export",
      clearAll: "Clear all",
      confirmClear: (n) => `Delete all ${n} saved messages? This can't be undone.`,
      cancel: "Cancel",
      deleteAll: "Delete all",
      close: "Close",
      emptyTitle: "No deleted messages yet",
      emptyBody: "When someone deletes a message for everyone, the copy kept on this PC shows up here.",
      noMatches: "Nothing matches your search",
      today: "Today",
      yesterday: "Yesterday",
      sent: (t) => `sent ${t}`,
      you: "You",
      foot: (s) => [`${s.n} saved`, s.withMedia ? `${fmtBytes(s.bytes)} of media` : null].filter(Boolean).join(" · "),
      photo: "Photo", video: "Video", gif: "GIF", sticker: "Sticker", voice: "Voice message", audio: "Audio",
      document: "Document", location: "Location", contact: "Contact", poll: "Poll", message: "Message",
    },
    he: {
      dir: "rtl",
      title: "BetterWhatsapp",
      feature: "אנטי-מחיקה",
      active: "פעיל",
      paused: "מושהה. הודעות שנמחקות לא נשמרות",
      nSaved: (n) => `${n} נשמרו`,
      last: (t) => `אחרונה ${t}`,
      reveal: "הצגת תוכן שנמחק",
      saveMedia: "שמירת תמונות והקלטות",
      viewer: "הודעות שנמחקו",
      deleted: "נמחקה",
      deletedByAdmin: "נמחקה ע\"י מנהל",
      deletedForEveryone: "נמחקה אצל כולם",
      by: (n) => `ע"י ${n}`,
      unrecoverable: "לא ניתן לשחזר את הטקסט של ההודעה",
      savingMedia: "שומר מדיה…",
      mediaFailed: "שמירת המדיה נכשלה",
      mediaOff: "המדיה לא נשמרה",
      tooLarge: "גדול מדי לשמירה",
      retry: "נסה שוב",
      saveNow: "שמור",
      search: "חיפוש בהודעות שנמחקו",
      all: "הכל",
      text: "טקסט",
      media: "מדיה",
      openChat: "פתח צ'אט",
      copy: "העתק",
      copied: "הועתק",
      remove: "הסר",
      download: "הורדה",
      export: "ייצוא",
      clearAll: "מחק הכל",
      confirmClear: (n) => `למחוק את כל ${n} ההודעות השמורות? אי אפשר לבטל.`,
      cancel: "ביטול",
      deleteAll: "מחק הכל",
      close: "סגירה",
      emptyTitle: "עוד אין הודעות שנמחקו",
      emptyBody: "כשמישהו מוחק הודעה אצל כולם, העותק שנשמר במחשב הזה יופיע כאן.",
      noMatches: "לא נמצאו תוצאות",
      today: "היום",
      yesterday: "אתמול",
      sent: (t) => `נשלחה ${t}`,
      you: "את/ה",
      foot: (s) => [`${s.n} נשמרו`, s.withMedia ? `${fmtBytes(s.bytes)} מדיה` : null].filter(Boolean).join(" · "),
      photo: "תמונה", video: "סרטון", gif: "GIF", sticker: "סטיקר", voice: "הודעה קולית", audio: "שמע",
      document: "מסמך", location: "מיקום", contact: "איש קשר", poll: "סקר", message: "הודעה",
    },
  };
  const T = new Proxy({}, { get: (_, k) => STR[uiLang()][k] });

  const toMs = (t) => (t == null ? null : t < 1e12 ? t * 1000 : t);
  const fmtTime = (ms) => {
    if (!ms) return "";
    const d = new Date(ms), now = new Date();
    const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    if (d.toDateString() === now.toDateString()) return time;
    return d.toLocaleDateString([], { day: "numeric", month: "short" }) + " " + time;
  };
  const fmtFull = (ms) => (ms ? new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "");
  function fmtBytes(n) {
    if (!n) return "0 KB";
    if (n < 1024 * 1024) return `${Math.max(1, Math.round(n / 1024))} KB`;
    return `${(n / 1024 / 1024).toFixed(n < 10 * 1024 * 1024 ? 1 : 0)} MB`;
  }
  const fmtDuration = (s) => (s ? `${Math.floor(s / 60)}:${String(Math.round(s % 60)).padStart(2, "0")}` : "");
  function dayLabel(ms) {
    const d = new Date(ms), today = new Date();
    const y = new Date(today); y.setDate(today.getDate() - 1);
    if (d.toDateString() === today.toDateString()) return T.today;
    if (d.toDateString() === y.toDateString()) return T.yesterday;
    return d.toLocaleDateString([], { weekday: "long", day: "numeric", month: "long", year: d.getFullYear() === today.getFullYear() ? undefined : "numeric" });
  }

  function describe(m) {
    const t = m.type;
    const cap = typeof m.caption === "string" ? m.caption : "";
    const body = typeof m.body === "string" ? m.body : "";
    const dur = m.duration ? ` · ${fmtDuration(Number(m.duration))}` : "";
    switch (t) {
      case "chat": return { icon: "", text: body };
      case "image": return { icon: "📷", label: T.photo, text: cap, thumb: body };
      case "video": case "ptv": return { icon: "🎥", label: (m.isGif ? T.gif : T.video) + dur, text: cap, thumb: body };
      case "sticker": return { icon: "🏷️", label: T.sticker, text: "" };
      case "ptt": return { icon: "🎤", label: T.voice + dur, text: "" };
      case "audio": return { icon: "🎵", label: T.audio + dur, text: "" };
      case "document": return { icon: "📄", label: m.filename || T.document, text: cap };
      case "location": return { icon: "📍", label: T.location, text: [m.loc, m.lat != null ? `${m.lat}, ${m.lng}` : ""].filter(Boolean).join("\n") };
      case "vcard": case "multi_vcard": return { icon: "👤", label: m.vcardFormattedName || T.contact, text: "" };
      case "poll_creation": return { icon: "📊", label: T.poll, text: [m.pollName, ...(m.pollOptions || []).map((o) => "• " + (o.name ?? ""))].filter(Boolean).join("\n") };
      default: return { icon: "💬", label: t || T.message, text: cap || (body.length < 4000 && !/^[A-Za-z0-9+/=]{200,}$/.test(body) ? body : "") };
    }
  }
  const looksLikeJpegB64 = (s) => typeof s === "string" && s.startsWith("/9j/") && s.length > 200;
  const recText = (rec) => describe(rec.msg || {}).text || "";

  function previewText(rec) {
    const d = describe(rec.msg || {});
    return ["🚫", d.icon, d.label && !d.text ? d.label : "", d.text].filter(Boolean).join(" ").replace(/\s+/g, " ").slice(0, 200);
  }

  // Names are looked up live (contacts get renamed); the ids are the fallback.
  function collections() { try { return req("WAWebCollections"); } catch { return {}; } }
  const isGroupId = (id) => typeof id === "string" && id.endsWith("@g.us");
  function chatName(rec) {
    const { Chat, Contact } = collections();
    try { const c = Chat && Chat.get(rec.chat); if (c && c.formattedTitle) return c.formattedTitle; } catch {}
    try { const c = Contact && Contact.get(rec.chat); if (c) return c.formattedName || c.pushname || c.name; } catch {}
    return rec.chat ? rec.chat.split("@")[0] : "?";
  }
  function senderName(rec) {
    if (rec.fromMe) return T.you;
    if (!rec.sender) return "";
    const { Contact } = collections();
    try { const c = Contact && Contact.get(rec.sender); if (c) return c.formattedName || c.pushname || c.name || rec.sender.split("@")[0]; } catch {}
    return rec.msg && rec.msg.notifyName ? rec.msg.notifyName : rec.sender.split("@")[0];
  }

  // ------------------------------------------------------------------ UI kit
  const ICONS = {
    shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
    shieldOff: '<path d="m2 2 20 20"/><path d="M5 5a1 1 0 0 0-1 1v7c0 5 3.5 7.5 7.67 8.94a1 1 0 0 0 .67.01c2.35-.82 4.48-1.97 5.86-3.71"/><path d="M9.31 3.65a12.25 12.25 0 0 0 1.93-1.37 1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1v7c0 .43-.03.85-.08 1.26"/>',
    eye: '<path d="M2.06 12.35a1 1 0 0 1 0-.7 10.75 10.75 0 0 1 19.88 0 1 1 0 0 1 0 .7 10.75 10.75 0 0 1-19.88 0"/><circle cx="12" cy="12" r="3"/>',
    image: '<rect width="18" height="18" x="3" y="3" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.09-3.09a2 2 0 0 0-2.82 0L6 21"/>',
    history: '<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/>',
    chevron: '<path d="m9 18 6-6-6-6"/>',
    ban: '<circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    trash: '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
    copy: '<rect width="13" height="13" x="9" y="9" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    chat: '<path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
    file: '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/>',
    retry: '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1"/>',
    inbox: '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
  };

  const CSS = `
.wad-host{display:block}
.wad-card{margin:-26px 12px 0;padding:14px 4px 6px;border-radius:16px;background:var(--WDS-surface-emphasized,#1d1f1f);border:1px solid var(--WDS-lines-divider,rgba(127,127,127,.2));color:var(--WDS-content-default,#111);font-size:14px;line-height:20px;text-align:start;cursor:default}
.wad-card-head{display:flex;align-items:center;gap:12px;padding:0 12px 12px}
.wad-tile{flex:none;display:grid;place-items:center;width:40px;height:40px;border-radius:12px;background:var(--WDS-accent-deemphasized,#103529);color:var(--WDS-accent,#21c063);transition:background .2s,color .2s}
.wad-off .wad-tile{background:var(--WDS-surface-highlight,rgba(127,127,127,.15));color:var(--WDS-content-deemphasized,#888)}
.wad-logo{flex:none;width:40px;height:40px;border-radius:11px;transition:filter .2s,opacity .2s}
.wad-logo.small{width:32px;height:32px;border-radius:9px}
.wad-logo.off{filter:grayscale(1);opacity:.6}
.wad-head-text{flex:1;min-width:0}
.wad-title{font-size:16px;line-height:21px;font-weight:500}
.wad-sub{font-size:13px;line-height:18px;color:var(--WDS-content-deemphasized,#888);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.wad-sub b{font-weight:500;color:var(--WDS-accent,#21c063)}
.wad-off .wad-sub b{color:var(--WDS-secondary-warning,#d29b1d)}
.wad-rows{border-top:1px solid var(--WDS-lines-divider,rgba(127,127,127,.2));padding-top:4px}
.wad-row{display:flex;align-items:center;gap:14px;width:100%;min-height:44px;padding:6px 12px;border:0;border-radius:10px;background:none;color:inherit;font:inherit;text-align:start;cursor:pointer;box-sizing:border-box}
.wad-row:hover{background:var(--WDS-surface-highlight,rgba(127,127,127,.12))}
.wad-row:focus-visible{outline:2px solid var(--WDS-accent,#21c063);outline-offset:-2px}
.wad-row>svg{flex:none;color:var(--WDS-content-deemphasized,#888)}
.wad-row-label{flex:1;min-width:0;font-size:14.5px}
.wad-count{flex:none;min-width:20px;height:20px;padding:0 6px;border-radius:10px;box-sizing:border-box;background:var(--WDS-accent,#21c063);color:var(--WDS-content-on-accent,#0a0a0a);font-size:12px;line-height:20px;font-weight:600;text-align:center}
.wad-chev{flex:none;color:var(--WDS-content-deemphasized,#888)}
[dir=rtl] .wad-chev{transform:scaleX(-1)}
.wad-switch{position:relative;flex:none;width:36px;height:20px;border-radius:10px;border:0;padding:0;background:var(--WDS-surface-pressed,#999);cursor:pointer}
.wad-switch>span{position:absolute;top:3px;inset-inline-start:3px;width:14px;height:14px;border-radius:50%;background:#fff;transition:inset-inline-start .15s}
.wad-switch[aria-checked=true]{background:var(--WDS-accent,#21c063)}
.wad-switch[aria-checked=true]>span{inset-inline-start:19px}

.wad-preserved{min-width:150px;max-width:100%}
.wad-pillrow{margin:1px 0 5px}
.wad-pill{display:inline-flex;align-items:center;gap:4px;padding:1px 8px 1px 6px;border-radius:999px;background:rgba(var(--WDS-secondary-negative-RGB,251,80,97),.16);color:var(--WDS-secondary-negative,#e0384b);font-size:12px;line-height:18px;font-weight:500;white-space:nowrap;user-select:none}
.wad-pill>svg{flex:none}
.wad-media{display:block;width:100%;max-width:300px;max-height:340px;object-fit:cover;border-radius:8px;margin:2px 0 4px;background:rgba(0,0,0,.18);cursor:zoom-in}
video.wad-media{cursor:default;object-fit:contain;background:#000}
.wad-lowres{filter:blur(.4px) saturate(.9);cursor:default}
.wad-sticker{width:140px;height:140px;object-fit:contain;background:none;cursor:default}
.wad-audio{display:block;width:270px;max-width:100%;height:40px;margin:2px 0 4px}
body.dark .wad-audio,body.dark video.wad-media{color-scheme:dark}
.wad-doc{display:flex;align-items:center;gap:10px;min-width:220px;max-width:320px;padding:8px 10px;margin:2px 0 4px;border-radius:8px;background:rgba(var(--WDS-surface-highlight-RGB,127,127,127),.1);box-sizing:border-box}
.wad-doc>svg{flex:none;opacity:.8}
.wad-doc-name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:14px}
.wad-doc-meta{font-size:12px;opacity:.65}
.wad-label{font-size:13.5px;opacity:.8;margin:0 0 2px}
.wad-status{display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-size:12px;line-height:16px;color:var(--WDS-systems-bubble-content-deemphasized,var(--WDS-content-deemphasized,#888));margin:0 0 4px}
.wad-link{background:none;border:0;padding:0;color:var(--WDS-content-action-emphasized,#008069);font:inherit;font-weight:500;cursor:pointer}
.wad-link:hover{text-decoration:underline}
.wad-muted{font-style:italic;color:var(--WDS-systems-bubble-content-deemphasized,var(--WDS-content-deemphasized,#888))}
.wad-text{white-space:pre-wrap;overflow-wrap:anywhere}
.wad-spin{flex:none;width:11px;height:11px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:wad-spin .8s linear infinite}
@keyframes wad-spin{to{transform:rotate(360deg)}}

.wad-overlay{position:fixed;inset:0;z-index:100000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.55);animation:wad-fade .15s ease-out;font-family:inherit}
.wad-modal{display:flex;flex-direction:column;width:min(640px,calc(100vw - 32px));height:min(780px,calc(100vh - 48px));border-radius:18px;overflow:hidden;background:var(--WDS-surface-elevated-default,#fff);color:var(--WDS-content-default,#111);box-shadow:0 24px 64px rgba(0,0,0,.45);animation:wad-pop .2s cubic-bezier(.16,1,.3,1);font-size:14px;line-height:20px}
@keyframes wad-fade{from{opacity:0}}
@keyframes wad-pop{from{opacity:0;transform:translateY(8px) scale(.98)}}
.wad-mhead{padding:16px 20px 10px;border-bottom:1px solid var(--WDS-lines-divider,rgba(127,127,127,.2))}
.wad-mtitle-row{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.wad-mtitle{flex:1;display:flex;align-items:center;gap:10px;font-size:19px;line-height:26px;font-weight:500}
.wad-mtitle .wad-tile{width:34px;height:34px;border-radius:10px}
.wad-mcount{font-size:14px;font-weight:400;color:var(--WDS-content-deemphasized,#888)}
.wad-iconbtn{display:grid;place-items:center;flex:none;width:36px;height:36px;border:0;border-radius:50%;background:none;color:var(--WDS-content-deemphasized,#888);cursor:pointer;text-decoration:none}
.wad-iconbtn:hover{background:var(--WDS-surface-highlight,rgba(127,127,127,.12));color:var(--WDS-content-default,#111)}
.wad-search{display:flex;align-items:center;gap:10px;height:40px;padding:0 6px 0 14px;border-radius:20px;background:var(--WDS-surface-elevated-emphasized,rgba(127,127,127,.12));color:var(--WDS-content-deemphasized,#888)}
.wad-search:focus-within{box-shadow:inset 0 0 0 2px var(--WDS-accent,#21c063)}
.wad-search input{flex:1;min-width:0;height:100%;border:0;outline:0;background:none;color:var(--WDS-content-default,#111);font:inherit;font-size:15px}
.wad-search input::placeholder{color:var(--WDS-content-deemphasized,#888)}
.wad-search .wad-iconbtn{width:30px;height:30px}
.wad-chips{display:flex;gap:8px;margin-top:12px}
.wad-chip{height:32px;padding:0 14px;border-radius:16px;border:1px solid var(--WDS-lines-divider,rgba(127,127,127,.3));background:none;color:var(--WDS-content-deemphasized,#666);font:inherit;font-size:14px;cursor:pointer}
.wad-chip:hover{background:var(--WDS-surface-highlight,rgba(127,127,127,.1))}
.wad-chip[aria-pressed=true]{border-color:transparent;background:var(--WDS-components-filter-surface-selected,var(--WDS-accent-deemphasized,#d9fdd3));color:var(--WDS-accent,#008069);font-weight:500}
.wad-mlist{flex:1;overflow-y:auto;padding:0 10px 12px;overscroll-behavior:contain}
.wad-day{position:sticky;top:0;z-index:1;display:flex;justify-content:center;padding:10px 0 6px;pointer-events:none}
.wad-day span{padding:4px 12px;border-radius:8px;background:var(--WDS-surface-elevated-emphasized,#eee);color:var(--WDS-content-deemphasized,#666);font-size:12.5px;box-shadow:0 1px 2px rgba(0,0,0,.15)}
.wad-item{display:flex;gap:12px;padding:10px 10px 8px;border-radius:12px}
.wad-item:hover,.wad-item:focus-within{background:var(--WDS-surface-highlight,rgba(127,127,127,.08))}
.wad-avatar{flex:none;display:grid;place-items:center;width:42px;height:42px;border-radius:50%;overflow:hidden;font-size:15px;font-weight:500}
.wad-avatar img{width:100%;height:100%;object-fit:cover}
.wad-item-main{flex:1;min-width:0}
.wad-item-top{display:flex;align-items:baseline;gap:8px}
.wad-item-chat{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:15.5px;font-weight:500}
.wad-item-time{flex:none;font-size:12px;color:var(--WDS-secondary-negative,#e0384b)}
.wad-item-meta{font-size:13px;color:var(--WDS-content-deemphasized,#888);margin:1px 0 6px}
.wad-item-body{display:inline-block;max-width:100%;padding:6px 9px 7px;border-radius:0 10px 10px 10px;background:var(--WDS-systems-bubble-surface-incoming,#fff);box-shadow:0 1px .5px rgba(0,0,0,.13);box-sizing:border-box}
[dir=rtl] .wad-item-body{border-radius:10px 0 10px 10px}
.wad-item-body.mine{background:var(--WDS-systems-bubble-surface-outgoing,#d9fdd3)}
.wad-item-body .wad-media{max-width:260px;max-height:260px}
.wad-clamp{display:-webkit-box;-webkit-line-clamp:8;-webkit-box-orient:vertical;overflow:hidden;cursor:pointer}
.wad-actions{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;opacity:0;transition:opacity .12s}
.wad-item:hover .wad-actions,.wad-item:focus-within .wad-actions{opacity:1}
.wad-btn{display:inline-flex;align-items:center;gap:6px;height:30px;padding:0 12px;border:0;border-radius:15px;background:var(--WDS-surface-elevated-emphasized,rgba(127,127,127,.12));color:var(--WDS-content-default,#111);font:inherit;font-size:13px;cursor:pointer;white-space:nowrap}
.wad-btn:hover{background:var(--WDS-surface-pressed,rgba(127,127,127,.2))}
.wad-btn:disabled{opacity:.45;cursor:default}
.wad-btn.danger{color:var(--WDS-secondary-negative,#e0384b)}
.wad-btn.solid-danger{background:var(--WDS-secondary-negative,#e0384b);color:#fff;font-weight:500}
.wad-btn.solid-danger:hover{filter:brightness(1.08)}
.wad-mfoot{display:flex;align-items:center;gap:8px;padding:12px 16px 12px 20px;border-top:1px solid var(--WDS-lines-divider,rgba(127,127,127,.2));min-height:56px;box-sizing:border-box}
.wad-foot-info{flex:1;min-width:0;font-size:13px;color:var(--WDS-content-deemphasized,#888)}
.wad-foot-warn{flex:1;min-width:0;font-size:13.5px}
.wad-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;height:100%;padding:24px;text-align:center}
.wad-empty .wad-tile{width:64px;height:64px;border-radius:20px;margin-bottom:10px}
.wad-empty-title{font-size:17px;font-weight:500}
.wad-empty-body{max-width:340px;color:var(--WDS-content-deemphasized,#888)}
.wad-lightbox{background:rgba(0,0,0,.88);cursor:zoom-out}
.wad-lightbox img{max-width:94vw;max-height:90vh;border-radius:6px;box-shadow:0 10px 40px rgba(0,0,0,.5)}
`;

  function ensureStyle() {
    if (!isPage || document.getElementById("wad-style")) return;
    const s = document.createElement("style");
    s.id = "wad-style";
    s.textContent = CSS;
    (document.head || document.documentElement).appendChild(s);
  }
  if (isPage) undo.push(() => { const s = document.getElementById("wad-style"); if (s) s.remove(); });

  let React, h;
  function ui() {
    if (!React) { React = req("react"); h = React.createElement; }
    ensureStyle();
  }
  const useStore = () => React.useSyncExternalStore(subscribe, () => version);

  function Icon({ n, size = 20, className }) {
    return h("svg", { viewBox: "0 0 24 24", width: size, height: size, fill: "none", stroke: "currentColor", strokeWidth: 1.9, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": true, className, dangerouslySetInnerHTML: { __html: ICONS[n] } });
  }

  // WhatsApp's own switch when it's loaded, a lookalike otherwise.
  function Switch(props) {
    let WDS = null;
    try { WDS = req("WDSSwitch.react"); } catch {}
    if (typeof WDS === "function") return h(WDS, { value: props.value, onChange: props.onChange, "aria-label": props.label });
    return h("button", { type: "button", role: "switch", "aria-checked": !!props.value, "aria-label": props.label, className: "wad-switch", onClick: () => props.onChange(!props.value) }, h("span"));
  }

  // A crash in our UI must never take WhatsApp's tree down with it.
  let Boundary;
  function boundary() {
    return (Boundary ||= class extends React.Component {
      constructor(p) { super(p); this.state = { err: null }; }
      static getDerivedStateFromError(err) { return { err }; }
      componentDidCatch(err) { log("ui error:", err && err.message); }
      render() { return this.state.err ? (this.props.fallback ?? null) : this.props.children; }
    });
  }
  const safe = (el, fallback, key) => h(boundary(), { fallback, key }, el);

  const stop = (e) => e.stopPropagation();

  // ------------------------------------------------------- shared pieces
  function useMediaUrl(rec) {
    const ok = !!(rec.media && rec.media.state === "saved");
    const [url, setUrl] = React.useState(() => (ok ? mediaUrlReady.get(rec.k) || null : null));
    React.useEffect(() => {
      if (!ok || url) return;
      let live = true;
      getMediaUrl(rec.k).then((u) => { if (live) setUrl(u); });
      return () => { live = false; };
    }, [rec.k, ok, url]);
    return ok ? url : null;
  }

  function MediaStatus({ rec }) {
    const st = rec.media && rec.media.state;
    if (!st || st === "saved") return null;
    const busy = mediaJobs.has(rec.k);
    const act = (label, icon) => h("button", { type: "button", className: "wad-link", onClick: (e) => { stop(e); queueMedia(rec, true); } }, label);
    let body;
    if (busy || (st === "pending" && settings.media)) body = [h("span", { key: "s", className: "wad-spin" }), T.savingMedia];
    else if (st === "pending") body = [T.mediaOff, " · ", act(T.saveNow)];
    else if (st === "failed") body = [T.mediaFailed, " · ", act(T.retry)];
    else if (st === "skipped") body = [T.tooLarge];
    else return null;
    return h("div", { className: "wad-status" }, ...body);
  }

  function MediaView({ rec }) {
    const m = rec.msg || {};
    const d = describe(m);
    const url = useMediaUrl(rec);
    const thumb = looksLikeJpegB64(d.thumb) ? "data:image/jpeg;base64," + d.thumb : null;
    React.useEffect(() => { if (rec.media && rec.media.state === "pending" && settings.media) queueMedia(rec); }, [rec]);
    let main = null;
    switch (m.type) {
      case "image": {
        const src = url || thumb;
        if (src) main = h("img", { src, alt: "", className: "wad-media" + (url ? "" : " wad-lowres"), onClick: (e) => { stop(e); if (url) openOverlay({ kind: "lightbox", src: url }); } });
        break;
      }
      case "sticker":
        if (url) main = h("img", { src: url, alt: "", className: "wad-media wad-sticker" });
        break;
      case "video": case "ptv":
        if (url) main = h("video", { src: url, controls: true, preload: "metadata", loop: !!m.isGif, poster: thumb || undefined, className: "wad-media", onClick: stop, onMouseDown: stop });
        else if (thumb) main = h("img", { src: thumb, alt: "", className: "wad-media wad-lowres" });
        break;
      case "ptt": case "audio":
        if (url) main = h("audio", { src: url, controls: true, preload: "metadata", className: "wad-audio", onClick: stop, onMouseDown: stop });
        break;
      case "document":
        main = h("div", { className: "wad-doc" },
          h(Icon, { n: "file", size: 26 }),
          h("div", { className: "wad-doc-name", title: m.filename || "" }, m.filename || T.document, h("div", { className: "wad-doc-meta" }, [m.size ? fmtBytes(m.size) : "", (m.mimetype || "").split(";")[0]].filter(Boolean).join(" · "))),
          url ? h("a", { href: url, download: m.filename || "file", className: "wad-iconbtn", title: T.download, onClick: stop }, h(Icon, { n: "download" })) : null);
        break;
    }
    const label = !main && d.label ? h("div", { className: "wad-label" }, `${d.icon} ${d.label}`) : null;
    return h(React.Fragment, null, main, label, h(MediaStatus, { rec }));
  }

  // ------------------------------------------------------------------ bubble
  function DeletedPill({ rec }) {
    const admin = rec.subtype === "admin_revoke";
    const at = toMs(rec.revokedAt) || rec.capturedAt;
    let by = null;
    if (admin && rec.revokedBy) { try { const c = collections().Contact.get(rec.revokedBy); by = c && (c.formattedName || c.pushname); } catch {} }
    const title = [admin ? T.deletedByAdmin : T.deletedForEveryone, by ? T.by(by) : null, fmtFull(at)].filter(Boolean).join(" · ");
    return h("div", { className: "wad-pillrow" },
      h("span", { className: "wad-pill", title, "data-antidelete": "badge" }, h(Icon, { n: "ban", size: 13 }), `${admin ? T.deletedByAdmin : T.deleted} · ${fmtTime(at)}`));
  }

  function Preserved(props) {
    const { rec } = props;
    const m = rec.msg || {};
    const d = describe(m);
    const Bubble = req("WAWebMessageTextBubble.react");
    let Spacer = null;
    try { Spacer = req("WAWebMessageSpacerText.react"); } catch {}
    const nothing = !d.text && !d.label && !rec.media;
    const textEl = nothing
      ? h("span", { className: "wad-muted" }, T.unrecoverable)
      : h("span", { dir: "auto", className: "wad-text" }, d.text || "");
    return h(Bubble, {
      msgKey: props.msgKey, displayType: props.displayType, displayAuthor: props.displayAuthor,
      children: h("div", { "data-antidelete": "preserved", className: "wad-preserved" },
        h(DeletedPill, { rec }),
        h(MediaView, { rec }),
        Spacer ? h(Spacer, { msgKey: props.msgKey, children: textEl }) : h("div", null, textEl)),
    });
  }

  function patchBubble(exportsObj) {
    const ok = replaceExport(exportsObj, "default", (Orig) => {
      function BetterWhatsappRevoked(props) {
        ui();
        useStore();
        const k = props.msgKey != null ? String(props.msgKey) : "";
        const rec = settings.reveal ? cache.get(k) : null;
        React.useEffect(() => { if (!rec && settings.reveal) { ensureLoaded(k); const t = setTimeout(() => ensureLoaded(k), 50); return () => clearTimeout(t); } }, [k, rec]);
        return rec ? safe(h(Preserved, { ...props, rec }), h(Orig, props)) : h(Orig, props);
      }
      BetterWhatsappRevoked.displayName = "BetterWhatsappRevoked";
      return BetterWhatsappRevoked;
    });
    if (ok) { AD.patched.push("bubble"); log("bubble hook installed"); }
  }

  function patchPreview(exportsObj) {
    const ok = replaceExport(exportsObj, "default", (orig) => function (e) {
      try {
        const id = e && e.msg && e.msg.id;
        const rec = id != null && settings.reveal ? cache.get(String(id)) : null;
        if (rec) return previewText(rec);
        if (id != null && settings.reveal) ensureLoaded(String(id));
      } catch {}
      return orig.apply(this, arguments);
    });
    if (ok) AD.patched.push("preview");
  }

  function Logo({ off, small }) {
    if (!hasLogo) return h("div", { className: "wad-tile" }, h(Icon, { n: off ? "shieldOff" : "shield", size: small ? 19 : 22 }));
    return h("img", { src: LOGO, alt: "", className: "wad-logo" + (small ? " small" : "") + (off ? " off" : "") });
  }

  // ------------------------------------------------------ settings drawer
  function DrawerCard() {
    useStore();
    const s = settings;
    const st = stats();
    const sub = s.enabled
      ? [h("b", { key: "on" }, T.active), st.n ? ` · ${T.nSaved(st.n)}` : "", st.last ? ` · ${T.last(fmtTime(st.last))}` : ""]
      : [h("b", { key: "off" }, T.paused)];
    const toggleRow = (icon, label, key) => h("div", {
      key, className: "wad-row", role: "button", tabIndex: 0,
      onClick: () => setSetting(key, !s[key]),
      onKeyDown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSetting(key, !s[key]); } },
    },
      h(Icon, { n: icon }),
      h("span", { className: "wad-row-label" }, label),
      h("span", { onClick: stop, style: { display: "flex" } }, h(Switch, { value: s[key], label, onChange: (v) => setSetting(key, v) })));
    return h("div", { className: "wad-card" + (s.enabled ? "" : " wad-off"), dir: T.dir, "data-antidelete": "card", onKeyDown: stop },
      h("div", { className: "wad-card-head" },
        h(Logo, { off: !s.enabled }),
        h("div", { className: "wad-head-text" },
          h("div", { className: "wad-title" }, T.title),
          h("div", { className: "wad-sub" }, `${T.feature} · `, ...sub)),
        h(Switch, { value: s.enabled, label: T.feature, onChange: (v) => setSetting("enabled", v) })),
      h("div", { className: "wad-rows" },
        toggleRow("eye", T.reveal, "reveal"),
        toggleRow("image", T.saveMedia, "media"),
        h("button", { type: "button", className: "wad-row", onClick: () => openOverlay({ kind: "viewer" }) },
          h(Icon, { n: "history" }),
          h("span", { className: "wad-row-label" }, T.viewer),
          st.n ? h("span", { className: "wad-count" }, st.n) : null,
          h(Icon, { n: "chevron", className: "wad-chev" }))));
  }

  // Renders next to WhatsApp's "You" drawer and portals the card into the gap
  // under the profile photo. The drawer re-renders and swaps sub-pages, so the
  // host node is re-placed whenever the DOM changes while the drawer is open.
  function DrawerSlot() {
    const RD = req("ReactDOM");
    const [host, setHost] = React.useState(null);
    React.useEffect(() => {
      const el = document.createElement("div");
      el.className = "wad-host";
      let raf = 0;
      const place = () => {
        raf = 0;
        const fr = document.querySelector('[data-testid="me-tab-drawer"] [data-testid="menu-controller-focus-receiver"]');
        const header = fr && fr.firstElementChild;
        const list = header && header.nextElementSibling;
        if (!header || header === el || !list || !list.querySelector('[role="listitem"]')) { if (el.isConnected) el.remove(); return; }
        if (header.lastElementChild !== el) header.appendChild(el);
      };
      const mo = new MutationObserver(() => { if (!raf) raf = requestAnimationFrame(place); });
      mo.observe(document.body, { childList: true, subtree: true });
      place();
      setHost(el);
      return () => { mo.disconnect(); if (raf) cancelAnimationFrame(raf); el.remove(); };
    }, []);
    return host ? RD.createPortal(safe(h(DrawerCard)), host) : null;
  }

  function patchMeTab(exportsObj) {
    const ok = replaceExport(exportsObj, "MeTabFlow", (Orig) => {
      function BetterWhatsappMeTabFlow(props) {
        ui();
        return h(React.Fragment, null, h(Orig, props), safe(h(DrawerSlot)));
      }
      BetterWhatsappMeTabFlow.displayName = "BetterWhatsappMeTabFlow";
      return BetterWhatsappMeTabFlow;
    });
    if (ok) { AD.patched.push("drawer"); log("drawer hook installed"); }
  }

  // ------------------------------------------------------------ overlays
  // The viewer and the photo lightbox live in their own React root on <body>,
  // so they stay open after the settings drawer closes.
  let overlay = null;
  let overlayRoot = null;
  function openOverlay(v) {
    ui();
    if (!overlayRoot) {
      const el = document.createElement("div");
      el.id = "wad-overlay-root";
      document.body.appendChild(el);
      overlayRoot = req("ReactDOM").createRoot(el);
      overlayRoot.render(safe(h(OverlayHost)));
      undo.push(() => { try { overlayRoot.unmount(); } catch {} el.remove(); overlayRoot = null; });
    }
    overlay = v;
    emit();
  }
  function closeOverlay() { overlay = overlay && overlay.back ? overlay.back : null; emit(); }

  function OverlayHost() {
    useStore();
    React.useEffect(() => {
      if (!overlay) return;
      // WhatsApp listens for keys on the document; keep ours to ourselves.
      const onKey = (e) => {
        if (e.key === "Escape") { e.preventDefault(); closeOverlay(); }
        e.stopPropagation();
      };
      document.addEventListener("keydown", onKey, true);
      return () => document.removeEventListener("keydown", onKey, true);
    }, [overlay]);
    if (!overlay) return null;
    if (overlay.kind === "lightbox") {
      return h("div", { className: "wad-overlay wad-lightbox", onClick: closeOverlay },
        h("img", { src: overlay.src, alt: "" }));
    }
    return h(Viewer);
  }

  const AVATAR_COLORS = ["green", "teal", "cobalt", "purple", "pink", "orange", "yellow", "sky-blue", "brown", "red"];
  function Avatar({ rec, name }) {
    const [broken, setBroken] = React.useState(false);
    let img = null;
    try { const p = req("WAWebProfilePicThumbCollection").ProfilePicThumbCollection.get(rec.chat); img = p && (p.img || p.imgFull); } catch {}
    let hsh = 0;
    for (const ch of String(rec.chat || "")) hsh = (hsh * 31 + ch.charCodeAt(0)) | 0;
    const c = AVATAR_COLORS[Math.abs(hsh) % AVATAR_COLORS.length];
    const initials = String(name || "").replace(/[^\p{L} ]/gu, "").trim().split(/\s+/).slice(0, 2).map((w) => w[0] || "").join("").toUpperCase();
    return h("div", { className: "wad-avatar", style: { background: `var(--WDS-components-profile-photo-surface-${c}, #ccc)`, color: `var(--WDS-components-profile-photo-content-${c}, var(--WDS-content-default))` } },
      img && !broken ? h("img", { src: img, alt: "", onError: () => setBroken(true) }) : initials || h(Icon, { n: "user", size: 22 }));
  }

  async function openChat(rec) {
    try {
      const { Chat, Msg } = collections();
      const chat = Chat && Chat.get(rec.chat);
      if (!chat) return;
      overlay = null;
      emit();
      const Cmd = req("WAWebCmd").Cmd;
      const msg = Msg && Msg.get(rec.k);
      if (msg) {
        try {
          return await Cmd.openChatAt({ chat, msgContext: ns("WAWebChatMessageSearch").getSearchContext({ chat, msgKey: msg.id }) });
        } catch {}
      }
      await Cmd.openChatBottom({ chat });
    } catch (err) { log("open chat failed:", err && err.message); }
  }

  function exportAll() {
    const rows = [...cache.values()].sort((a, b) => (a.capturedAt || 0) - (b.capturedAt || 0)).map((r) => {
      const m = r.msg || {};
      return {
        chat: chatName(r), chatId: r.chat, sender: senderName(r) || null, fromMe: !!r.fromMe,
        sentAt: r.sentAt ? new Date(toMs(r.sentAt)).toISOString() : null,
        deletedAt: new Date(toMs(r.revokedAt) || r.capturedAt).toISOString(),
        deletedBy: r.subtype === "admin_revoke" ? "admin" : "sender",
        type: m.type, text: recText(r) || null, filename: m.filename || null,
        mediaSaved: !!(r.media && r.media.state === "saved"),
      };
    });
    const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), messages: rows }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `whatsapp-deleted-messages-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  }

  function Item({ rec }) {
    const [copied, setCopied] = React.useState(false);
    const [open, setOpen] = React.useState(false);
    const text = recText(rec);
    const d = describe(rec.msg || {});
    const deletedAt = toMs(rec.revokedAt) || rec.capturedAt;
    const name = chatName(rec);
    const who = rec.fromMe ? T.you : isGroupId(rec.chat) ? senderName(rec) : null;
    const nothing = !text && !d.label && !rec.media;
    const copy = () => {
      navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1400); }).catch(() => {});
    };
    return h("div", { className: "wad-item" },
      h(Avatar, { rec, name }),
      h("div", { className: "wad-item-main" },
        h("div", { className: "wad-item-top" },
          h("span", { className: "wad-item-chat", dir: "auto", title: name }, name),
          h("span", { className: "wad-item-time", title: `${rec.subtype === "admin_revoke" ? T.deletedByAdmin : T.deletedForEveryone} · ${fmtFull(deletedAt)}` }, `${T.deleted} ${fmtTime(deletedAt)}`)),
        h("div", { className: "wad-item-meta" }, [who, rec.sentAt ? T.sent(fmtTime(toMs(rec.sentAt))) : null].filter(Boolean).join(" · ")),
        h("div", { className: "wad-item-body" + (rec.fromMe ? " mine" : "") },
          h(MediaView, { rec }),
          text ? h("div", { dir: "auto", className: "wad-text" + (open ? "" : " wad-clamp"), onClick: () => setOpen(true) }, text) : null,
          nothing ? h("div", { className: "wad-muted" }, T.unrecoverable) : null),
        h("div", { className: "wad-actions" },
          collections().Chat && collections().Chat.get(rec.chat) ? h("button", { type: "button", className: "wad-btn", onClick: () => openChat(rec) }, h(Icon, { n: "chat", size: 16 }), T.openChat) : null,
          text ? h("button", { type: "button", className: "wad-btn", onClick: copy }, h(Icon, { n: copied ? "check" : "copy", size: 16 }), copied ? T.copied : T.copy) : null,
          h("button", { type: "button", className: "wad-btn danger", onClick: () => deleteRecords([rec.k]).catch(() => {}) }, h(Icon, { n: "trash", size: 16 }), T.remove))));
  }

  const isMediaRec = (r) => !!r.media || MEDIA_TYPES.has((r.msg || {}).type);

  function Viewer() {
    const [q, setQ] = React.useState("");
    const [filter, setFilter] = React.useState("all");
    const [confirm, setConfirm] = React.useState(false);
    const st = stats();
    const all = [...cache.values()].sort((a, b) => (b.capturedAt || 0) - (a.capturedAt || 0));
    const ql = q.trim().toLowerCase();
    const shown = all.filter((r) => {
      if (filter === "text" && isMediaRec(r)) return false;
      if (filter === "media" && !isMediaRec(r)) return false;
      if (!ql) return true;
      const m = r.msg || {};
      return [recText(r), chatName(r), senderName(r), m.filename].join("\n").toLowerCase().includes(ql);
    });
    const groups = [];
    for (const r of shown) {
      const label = dayLabel(r.capturedAt || 0);
      if (!groups.length || groups[groups.length - 1].label !== label) groups.push({ label, recs: [] });
      groups[groups.length - 1].recs.push(r);
    }
    const empty = !all.length
      ? h("div", { className: "wad-empty" },
          h("div", { className: "wad-tile" }, h(Icon, { n: "inbox", size: 30 })),
          h("div", { className: "wad-empty-title" }, T.emptyTitle),
          h("div", { className: "wad-empty-body" }, T.emptyBody))
      : h("div", { className: "wad-empty" }, h("div", { className: "wad-empty-body" }, T.noMatches));
    return h("div", { className: "wad-overlay", onMouseDown: (e) => { if (e.target === e.currentTarget) closeOverlay(); } },
      h("div", { className: "wad-modal", role: "dialog", "aria-modal": true, "aria-label": T.viewer, dir: T.dir },
        h("div", { className: "wad-mhead" },
          h("div", { className: "wad-mtitle-row" },
            h("div", { className: "wad-mtitle" },
              h(Logo, { small: true }),
              T.viewer,
              st.n ? h("span", { className: "wad-mcount" }, st.n) : null),
            h("button", { type: "button", className: "wad-iconbtn", onClick: closeOverlay, "aria-label": T.close, title: T.close }, h(Icon, { n: "x" }))),
          h("label", { className: "wad-search" },
            h(Icon, { n: "search", size: 18 }),
            h("input", { value: q, onChange: (e) => setQ(e.target.value), placeholder: T.search, autoFocus: true, dir: "auto", spellCheck: false }),
            q ? h("button", { type: "button", className: "wad-iconbtn", onClick: () => setQ(""), "aria-label": T.close }, h(Icon, { n: "x", size: 16 })) : null),
          h("div", { className: "wad-chips" },
            ["all", "text", "media"].map((f) => h("button", { key: f, type: "button", className: "wad-chip", "aria-pressed": filter === f, onClick: () => setFilter(f) }, T[f])))),
        h("div", { className: "wad-mlist" },
          shown.length
            ? groups.map((g) => h(React.Fragment, { key: g.label },
                h("div", { className: "wad-day" }, h("span", null, g.label)),
                g.recs.map((r) => safe(h(Item, { rec: r }), null, r.k))))
            : empty),
        h("div", { className: "wad-mfoot" },
          confirm
            ? [h("span", { key: "w", className: "wad-foot-warn" }, T.confirmClear(st.n)),
               h("button", { key: "c", type: "button", className: "wad-btn", onClick: () => setConfirm(false) }, T.cancel),
               h("button", { key: "d", type: "button", className: "wad-btn solid-danger", onClick: () => { setConfirm(false); clearAll().catch(() => {}); } }, T.deleteAll)]
            : [h("span", { key: "i", className: "wad-foot-info" }, st.n ? T.foot(st) : ""),
               h("button", { key: "e", type: "button", className: "wad-btn", disabled: !st.n, onClick: exportAll }, h(Icon, { n: "download", size: 16 }), T.export),
               h("button", { key: "x", type: "button", className: "wad-btn danger", disabled: !st.n, onClick: () => setConfirm(true) }, h(Icon, { n: "trash", size: 16 }), T.clearAll)])));
  }
  AD.openViewer = () => openOverlay({ kind: "viewer" });
  // Development helpers (used to exercise the media path on demand).
  AD._debug = { saveRecords, queueMedia, deleteRecords, compact, expandRow, fillMeta, hasMedia };

  // ------------------------------------------------------ module hooking
  // WhatsApp defines modules with __d(name, deps, factory, flags); the factory
  // fills its 7th argument (exports). We patch that object right after the
  // factory runs, before the module system snapshots exports.default.
  const PATCHES = {
    WAWebDBProcessRevokeMsgs: patchCapture,
    ...(isPage ? { WAWebMessageRevoked: patchBubble, WAWebFormatRevokedMsgText: patchPreview, "WAWebMeTabFlow.react": patchMeTab } : {}),
  };

  function wrapDefine(define) {
    if (typeof define !== "function") return define;
    if (define.__adOrig) define = define.__adOrig;
    const w = function (name, deps, factory, ...rest) {
      const patch = PATCHES[name];
      if (patch && typeof factory === "function") {
        const f = factory;
        factory = function () {
          const ret = f.apply(this, arguments);
          try { patch(arguments[6]); } catch (err) { log("patch failed", name, err && err.message); }
          return ret;
        };
        Object.defineProperty(factory, "length", { value: f.length }); // runtime reads factory.length
      }
      return define.call(this, name, deps, factory, ...rest); // strict mode: `arguments` wouldn't see the new factory
    };
    w.__adOrig = define;
    return w;
  }

  const lateStart = typeof globalThis.__d === "function";
  let current = wrapDefine(globalThis.__d);
  Object.defineProperty(globalThis, "__d", {
    configurable: true,
    get() { return current; },
    set(v) { current = wrapDefine(v); },
  });
  undo.push(() => {
    const raw = current && current.__adOrig ? current.__adOrig : current;
    Object.defineProperty(globalThis, "__d", { configurable: true, writable: true, value: raw });
  });

  // Injected after WhatsApp already booted: patch the live exports of modules
  // that are already defined. The runtime also caches `default` separately,
  // so that copy is updated too.
  function patchLoaded() {
    let map = null;
    try { map = req("__debug").modulesMap; } catch {}
    for (const [name, patch] of Object.entries(PATCHES)) {
      try {
        const entry = map && map[name];
        const exp = entry ? entry.exports : name === "WAWebDBProcessRevokeMsgs" ? ns(name) : null;
        if (entry && !entry.factoryFinished) {
          // Defined but not run yet: wrap the pending factory instead.
          if (typeof entry.factory === "function" && !entry.factory.__adOrig) {
            const f = entry.factory;
            const w = function () {
              const ret = f.apply(this, arguments);
              try { patch(arguments[6]); } catch (err) { log("patch failed", name, err && err.message); }
              return ret;
            };
            Object.defineProperty(w, "length", { value: f.length });
            w.__adOrig = f;
            entry.factory = w;
            undo.push(() => { if (entry.factory === w) entry.factory = f; });
          }
          continue;
        }
        if (!exp) continue;
        const before = exp.default;
        patch(exp);
        if (entry && "defaultExport" in entry && exp.default !== before) {
          const prevDefault = entry.defaultExport;
          entry.defaultExport = exp.default;
          undo.push(() => { entry.defaultExport = prevDefault; });
        }
      } catch {}
    }
  }
  if (lateStart) {
    patchLoaded();
    if (!AD.patched.includes("capture")) {
      let tries = 0;
      const t = setInterval(() => {
        tries++;
        try { patchCapture(ns("WAWebDBProcessRevokeMsgs")); clearInterval(t); } catch { if (tries > 10) clearInterval(t); }
      }, 1000);
      undo.push(() => clearInterval(t));
    }
  }

  async function loadAll() {
    await readSettings();
    const d = await openDb();
    const rows = await reqP(d.transaction(STORE).objectStore(STORE).getAll());
    const upgraded = [];
    for (const row of rows) {
      let r;
      try { r = await decryptRecord(row); } catch { continue; }
      if (r.v !== 2) { r = upgradeRecord(r); upgraded.push(r); }
      cache.set(r.k, r);
    }
    if (upgraded.length) { await saveRecords(upgraded); log(`upgraded ${upgraded.length} saved message(s)`); }
    emit();
    for (const r of cache.values()) queueMedia(r);
    return cache.size;
  }

  AD.dispose = () => {
    for (const fn of undo.reverse()) { try { fn(); } catch {} }
    listeners.clear();
    if (globalThis.__betterWhatsapp === AD) delete globalThis.__betterWhatsapp;
  };

  if (isPage) loadAll().then((n) => log(`loaded ${n} preserved message(s)`)).catch((err) => log("load failed", err && err.message));
  else readSettings();
  AD.ready = true;
  log("payload ready", isPage ? "(page)" : "(worker)", lateStart ? "late" : "early");
})();
