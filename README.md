<p align="center">
  <img src="assets/logo-256.png" width="120" alt="BetterWhatsapp logo">
</p>

<h1 align="center">BetterWhatsapp</h1>

<p align="center">
  A local, open-source mod for WhatsApp Desktop on Windows.<br>
  Its first feature, <b>Anti-Delete</b>, keeps messages people delete for everyone.
</p>

<p align="center">
  <a href="https://github.com/oripetel/BetterWhatsapp/actions/workflows/ci.yml"><img src="https://github.com/oripetel/BetterWhatsapp/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/oripetel/BetterWhatsapp/releases"><img src="https://img.shields.io/github/v/release/oripetel/BetterWhatsapp?color=21c063" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/oripetel/BetterWhatsapp?color=21c063" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078d4" alt="Windows 10 | 11">
  <img src="https://img.shields.io/badge/dependencies-0-21c063" alt="Zero dependencies">
</p>

---

> [!WARNING]
> BetterWhatsapp is not affiliated with WhatsApp or Meta. Client mods break
> WhatsApp's Terms of Service, so using one puts your account at some risk.
> Read [Risks](#risks) before installing.

## Features

- **Anti-Delete.** When someone deletes a message for everyone, the bubble keeps
  its original content under a red **Deleted · 20:31** pill. The chat list shows
  a 🚫 preview instead of "This message was deleted".
- **Media too.** Photos, videos, voice notes, audio and documents are saved with
  the text, and they open and play inside the bubble.
- **Control card in Settings.** Click your profile picture (bottom-left) and the
  card sits under your photo, with these controls:
  - Turn saving on or off.
  - Hide or show deleted content in chats.
  - Turn media saving on or off.
  - Open the deleted-messages list.
- **Deleted-messages list.** Saved messages are grouped by day. You can:
  - Search them and filter by All, Text or Media.
  - Jump to the message in its chat.
  - Copy, remove, export to JSON or clear everything.
- **Private by design.** Everything stays on your PC, encrypted with AES-GCM
  under a key that can't be exported. No telemetry, no servers, and message
  content is never logged.
- **English and Hebrew.** The UI follows WhatsApp's language.

## Requirements

- Windows 10 or 11
- [WhatsApp Desktop](https://apps.microsoft.com/detail/9NKSQGP7F2NH) from the
  Microsoft Store
- [Node.js](https://nodejs.org) 22 or newer (it uses Node's built-in WebSocket)

## Install

```powershell
git clone https://github.com/oripetel/BetterWhatsapp.git
cd BetterWhatsapp
powershell -ExecutionPolicy Bypass -File scripts\install-shortcut.ps1
```

This adds a **BetterWhatsapp** shortcut to your Desktop and Start menu. Nothing
else is installed, and there's nothing to `npm install`.

## Usage

Open WhatsApp with the **BetterWhatsapp** shortcut. If WhatsApp is already open,
the mod restarts it once. If you open WhatsApp the normal way, the mod is off for
that session.

To uninstall, delete the two shortcuts and the folder. Saved messages stay in
WhatsApp's own browser storage until you clear them from the deleted-messages
list.

## Limits

- Only messages that reached this PC before the delete can be kept. If a message
  and its deletion both arrive while the mod is off, it's gone.
- Media is fetched right after the delete, up to 64 MB per file. If that fails,
  the bubble shows the small preview and a **Retry** link.
- Stickers can't be kept. WhatsApp doesn't hold their decryption key locally
  until they're on screen.

## Risks

- **Debug port.** While WhatsApp runs, a DevTools port is open on `127.0.0.1`.
  The port number is random and only local programs can reach it, but any
  program on your PC could use it to control your WhatsApp session. Only use
  BetterWhatsapp on a computer you trust.
- **Terms of Service.** The mod only changes what your own client shows and
  stores. Its only network traffic is the media download WhatsApp itself would
  make when you open that media. Still, mods are against WhatsApp's terms.
- **Respect people.** The sender chose to delete those messages. Keep what you
  see to yourself.

## How it works

The launcher opens WhatsApp's WebView2 with a local debug port and attaches over
the Chrome DevTools Protocol. It injects `src/inject.js` before WhatsApp's own
code runs. The payload then hooks WhatsApp's module loader and wraps the module
that applies deletions. It reads the original message just before it's wiped
and saves an encrypted copy.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) covers the injection, storage
format, debugging tools and the gotchas found while building it.

## Contributing

Bug reports and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md)
first, and report security issues privately as described in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 oripetel
