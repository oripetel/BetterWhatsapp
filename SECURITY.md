# Security Policy

## Supported versions

Only the latest release gets fixes.

## Reporting a vulnerability

Please don't open a public issue for security problems. Report them privately
through [GitHub Security Advisories](https://github.com/oripetel/BetterWhatsapp/security/advisories/new).

Include what you found, how to reproduce it and what an attacker could do with
it. You should get a reply within a week.

## Known design trade-offs

- While WhatsApp runs with the mod, a Chrome DevTools port is open on
  `127.0.0.1` with a random port number. Any local program can connect to it
  and control the WhatsApp session. This is how the mod works, not a bug, but
  ideas for narrowing it are very welcome.
- Saved messages are encrypted with a non-extractable WebCrypto key stored in
  the same browser profile. This protects against casual reads of the profile
  folder. It doesn't protect against code running inside WhatsApp's page.
