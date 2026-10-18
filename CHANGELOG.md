# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-18

### Added
- BetterWhatsapp name, logo and shortcut icon.
- Control card under the profile photo in Settings (the "You" tab). It has a
  main switch, "show deleted content", "save photos & voice notes" and a link to
  the deleted-messages list.
- Deleted-messages list with day groups, search, All/Text/Media filters, Open
  chat (jumps to the message), Copy, Remove, Export (JSON) and Clear all.
- Media saving: photos, videos, voice notes, audio and documents are fetched
  through WhatsApp's own downloader right after a delete and stored encrypted.
- Redesigned deleted bubble with a "Deleted · time" pill, inline media players
  and a full-size photo viewer.
- English and Hebrew UI, following WhatsApp's language.

### Changed
- Records store chat, sender and timestamps and drop empty columns.
- Settings live in IndexedDB so the page and WhatsApp's worker share them.

### Fixed
- Messages saved by 0.1.0 with no visible text are recovered on load.
- The page payload could miss injection or crash at document start. The
  launcher now verifies it after every load and reloads if needed.

## [0.1.0] - 2026-10-18

### Added
- First version: keeps messages deleted for everyone and shows them in place of
  "This message was deleted".

[0.2.0]: https://github.com/oripetel/BetterWhatsapp/releases/tag/v0.2.0
[0.1.0]: https://github.com/oripetel/BetterWhatsapp/commits/v0.2.0
