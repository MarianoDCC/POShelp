# Security

## Threat model

The agent runs on the same machine as the browser and is reachable **only**
from `127.0.0.1`. It never opens a port to the local network or the internet.

Protections in place:

| Concern | Mitigation |
|---|---|
| Any web page calling the agent | CORS allowlist + `Origin` check (`lib/config.js`) |
| Unauthenticated printing | 256-bit bearer token, compared in constant time (`lib/server.js`) |
| Token living forever | 30-day expiry with explicit refresh endpoint |
| Brute-forcing the pairing code | Per-endpoint rate limiting + lockout after 5 failures (`lib/rateLimiter.js`) |
| Malicious ticket content | HTML validated before queueing; no scripts, iframes or remote resources (`lib/htmlValidator.js`) |
| Remote resources at print time | Requests blocked except the app's own origin (`lib/queue.js`) |
| Data readable on disk | Stores encrypted with a per-installation key held by the OS keychain (`lib/clave.js`) |
| Stack traces leaking paths | Custom Express error handler (`lib/server.js`) |

## Encryption key

The key that encrypts the on-disk stores is **generated per installation** and
protected by the operating system (DPAPI on Windows, Keychain on macOS) through
Electron's `safeStorage`. It is never stored in the source code, so publishing
this repository does not weaken any installation, and copying the files to
another machine yields nothing.

Where no OS keychain is available, the key falls back to a file with `0600`
permissions. Still random per installation.

Covered by `npm test`.

## Reporting a vulnerability

Please open a GitHub issue. If you believe the issue is sensitive, say so in the
issue without details and we will follow up privately.
