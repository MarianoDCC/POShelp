# TuResto Print Agent

A small background application that lets a web page print receipts and kitchen
tickets straight to a printer installed on the computer — **without the browser's
print dialog**, and without the page ever touching the printer directly.

It is used by point-of-sale and restaurant software, where a waiter closing a
table has to produce a ticket in one tap: stopping to confirm a print dialog,
pick a printer and adjust margins on every order is not workable during service.

## What it does

- Runs in the background and listens on `127.0.0.1` only. It never opens a port
  to the local network or to the internet.
- Exposes a small local HTTP API so an authorised web page can list the
  printers installed on that machine and send it something to print.
- Prints **HTML**, rendered through the operating system's own printer driver.
  That means it works with anything the computer can already print to — USB,
  network, Wi-Fi, thermal receipt printers, ordinary laser printers.
- Keeps a persistent queue with retries, so a ticket is not lost if the printer
  is busy, out of paper or briefly disconnected.
- Keeps an audit log of what was printed and of pairing attempts.
- Best-effort detection of the paper roll width, so receipts are laid out for
  the right paper size.

There is no window, no tray icon and no settings panel: it is a background
service. To stop it, the local API exposes `POST /quit`.

## How a web page connects to it

A page cannot simply talk to a program on the user's computer, so the two are
paired explicitly, once per machine:

1. **Automatic** — the page opens a `turesto://pair` link. The agent registers
   that URL scheme at install time, so the operating system hands the request to
   it. The agent issues a token and the page collects it.
2. **Manual** — the agent generates a 6-digit code, the user types it into the
   page, and the page exchanges it for a token.

From then on, every request carries that token as a bearer token. Tokens expire
after 30 days and can be refreshed without pairing again.

> **Note for Chrome users.** Since Chrome 141 a public page reaching
> `127.0.0.1` requires the user to grant the *Local Network Access* permission.
> The browser shows this prompt the first time; it must be allowed, or the page
> will not find the agent. This is a browser permission and not something the
> agent can grant itself.

## Local API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | — | Status, version, whether it is paired |
| `POST` | `/pair/verify` | — | Exchange a 6-digit code for a token |
| `GET` | `/pair/claim` | — | Collect the token from an automatic pairing |
| `GET` | `/pair/code` | — | Current 6-digit pairing code |
| `GET` | `/printers` | token | Printers installed on the machine |
| `GET` | `/printer-config` | token | Detected paper width for one printer |
| `POST` | `/print` | token | Validate and queue an HTML document |
| `POST` | `/auth/refresh` | token | Extend the current token |
| `GET` | `/jobs`, `/jobs/:id` | token | Queue state |
| `DELETE` | `/jobs` | token | Clear finished jobs |
| `GET` | `/audit/prints`, `/audit/prints/stats`, `/audit/pairing` | token | History |
| `POST` | `/quit` | token | Shut the agent down |

It listens on `47823`, falling back to `47824`, `47825`, `51823` or `55823` if
that port is taken.

## Security

The agent accepts printing instructions from a web page, so it is written to
assume the page could be hostile: bearer token compared in constant time, CORS
allowlist, per-endpoint rate limiting, lockout after repeated failed pairing,
HTML validated before it is queued (no scripts, no iframes, no remote
resources), and remote requests blocked at print time.

Data at rest is encrypted with a key **generated per installation** and held by
the operating system's keychain — never in the source code. See
[SECURITY.md](SECURITY.md).

## Building from source

Requires Node.js 20 or newer.

```bash
npm ci
npm test          # unit tests, no Electron needed
npm run dist:win  # Windows installer (NSIS) into dist/
npm run dist:mac  # macOS disk image into dist/
```

`npm start` runs it without packaging.

Installers are also built from source by GitHub Actions on every push — see
[.github/workflows/build.yml](.github/workflows/build.yml).

## Browser extension

`extension/` holds an optional Chrome extension that can reach the agent
without the Local Network Access prompt. It is not required: the agent works
from an ordinary page, and that is how it is normally used.

## License

MIT — see [LICENSE](LICENSE).
