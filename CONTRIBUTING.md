# Contributing to BetterWhatsapp

Thanks for helping. This is a small, dependency-free project, so the bar is
simple: keep it working, keep it local and keep it readable.

## Ground rules

- **Nothing leaves the PC.** No analytics or remote servers, and no network
  calls beyond what WhatsApp itself would make. PRs that add any of these will
  be closed.
- **Never log message content.** Logs may say *that* something happened, never
  *what* a message said.
- **No new dependencies** unless there's no reasonable alternative.
- **Never commit real chats.** Screenshots in issues and PRs must use a test
  account or blur names, numbers and message text.

## Project layout

```
src/inject.js                 payload injected into WhatsApp's page and workers
src/launcher.mjs              CDP daemon that attaches to WhatsApp and injects the payload
scripts/start.ps1             opens WhatsApp with a temporary DevTools port, starts the launcher
scripts/start.vbs             runs start.ps1 without a console window (shortcut target)
scripts/install-shortcut.ps1  creates the Desktop and Start menu shortcuts
assets/                       logo and icon
docs/ARCHITECTURE.md          how it all works, plus known gotchas
```

## Development loop

1. Start WhatsApp with the mod: `npm start` (or the shortcut).
2. Find the debug port in `%LOCALAPPDATA%\BetterWhatsapp\launcher.log`
   ("connected on port N").
3. After editing `src/inject.js`, evaluate the file again in the WhatsApp page
   over CDP (`Runtime.evaluate`). The new copy disposes the old one and patches
   modules that are already loaded, so you don't need to restart WhatsApp.
   Changes to the launcher or anything that runs at document start do need a
   restart: close WhatsApp and run `npm start`.
4. `__betterWhatsapp.selfTest("<msg id>")` checks the capture pipeline on an
   existing message without storing anything.
5. Run `npm run check` before you push. CI runs it too, plus a PowerShell parse
   check.

WhatsApp ships a new web bundle often. When a hook stops installing, look for
the module name in `require("__debug").modulesMap` in the page and update the
`PATCHES` table in `src/inject.js`.

## Pull requests

- Keep one change per PR, and describe what you tested and on which WhatsApp
  Desktop version.
- Match the existing style: two-space indent, double quotes, and comments that
  explain *why* something is done.
- Add a line under "Unreleased" in `CHANGELOG.md` for anything users would
  notice.

## Commit messages

Use the imperative mood with a short summary line, for example
`Keep stickers when they are already cached`.
