# Architecture

How BetterWhatsapp gets into WhatsApp Desktop and what it changes.

## Injection

WhatsApp Desktop (Store app `5319275A.WhatsAppDesktop`) is a .NET shell around
WebView2 running the WhatsApp Web bundle.

1. `scripts/start.ps1` briefly sets `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=<random>`
   for the user, starts WhatsApp, and clears the variable as soon as the port is up.
   (The per-app policy key under `HKCU\Software\Policies` would be cleaner, but it
   needs admin rights.)
2. `src/launcher.mjs` connects over CDP, using Node 24's built-in WebSocket with no
   dependencies. It injects `inject.js` into the WhatsApp page and its workers
   before their scripts run. It reloads the page once if the page booted first,
   and exits when WhatsApp closes.
3. `src/inject.js` hooks WhatsApp's module system (`__d`) and patches these modules
   as they load:
   - `WAWebDBProcessRevokeMsgs.processRevokeMsgs` (+ `…AndGetCleanupEligibleKeys`):
     before WhatsApp turns the row into a `revoked` stub, it reads the original
     row from the message table and stores it. The text, caption and other
     content fields sit in the `msgRowOpaqueData` protobuf, so the row is first
     expanded with WhatsApp's own
     `WAWebDBMessageSerialization.movFieldFromOpaqueDataBackToMsg`.
   - `WAWebMessageRevoked` (the "This message was deleted" bubble): shows the
     preserved content.
   - `WAWebFormatRevokedMsgText`: the chat-list preview.
   - `WAWebMeTabFlow.react` (the "You" drawer): renders the control card through
     a React portal into the gap under the profile photo.
   - Media: right after a capture, the page fetches the file with WhatsApp's own
     `WAWebDownloadManager.downloadManager.downloadAndMaybeDecrypt` (served from
     WhatsApp's cache if the media was already opened) and stores it encrypted.

## Storage

Records live in the WebView2 profile's IndexedDB `wa-antidelete` (the pre-rename name, kept so saved messages carry over; version 2):
`msgs` (one record per deleted message, keyed by the post-revoke message key),
`media` (the file bytes) and `keys` (the AES key and the settings). Records and
media are AES-GCM encrypted with a non-extractable key stored in the same
database. A record keeps the chat, sender, sent/deleted times and the message row
with its empty columns dropped. If the row's protobuf can't be expanded, the raw
bytes are kept so a later version can retry. Version 1 records are upgraded on
load, which also recovers text that version 1 left inside the protobuf.

## Debugging

Logs: `%LOCALAPPDATA%\BetterWhatsapp\launcher.log`. Run with
`node src/launcher.mjs --port <n> --debug` to also log page errors and navigations.
`__betterWhatsapp.selfTest(msgId)` in the page runs the read → expand → encrypt →
decrypt pipeline on an existing message (and downloads its media without
storing it) and returns only its shape. `__betterWhatsapp.openViewer()` opens the
list. Evaluating `inject.js` again in the page replaces the running copy
(`dispose()`), which is handy for development.


## Gotchas

- Creating a `BroadcastChannel` in WhatsApp's worker makes the app reload in a loop.
- Reading `location` in a worker that is still paused at start blocks
  `Runtime.evaluate`. The worker never resumes and WhatsApp reloads.
- At document start there is no `<html>` element. Anything that reads
  `document.documentElement` during init throws and the hooks never install.
  The launcher now checks `__betterWhatsapp.ready` after each load and reloads if
  it's missing.
- Browser-level `Target.setAutoAttach` doesn't attach to a page that WebView2
  creates after we connect, so pages are attached explicitly through
  `setDiscoverTargets`.
- The module runtime snapshots `exports.default` when the factory returns and
  reads `factory.length`. Patches therefore run inside a wrapped factory that
  keeps `length`.
