# bchatpn — BChat push-notification server

One process. One command. Nothing else to run.

```
python3 -m bchatpn keygen /etc/bchatpn/x25519.key      # once; prints the public key for the app
python3 -m bchatpn serve                               # configured by BCHATPN_* env vars and/or a TOML file
```

There is **no** database server, message broker, Telegram bot, web-server front end, or separate notifier
process. State lives in an in-memory registry persisted to a local SQLite file. The core needs exactly one
third-party package (`cryptography`). nginx and systemd are optional conveniences, not requirements.

It is a drop-in replacement for the legacy v1 server (`bchat-legacy-Push-Notification-server`): same onion
endpoints, same request fields, same push payload. The Android app needs no change beyond the server URL and
public key in `Server.kt`.

## How it works

```
sender app ──onion──▶ /beldex/v2/lsrpc | /beldex/v4/lsrpc ──▶ decrypt ─▶ validate ─▶ enqueue ─▶ reply (ack)
                                                                                         │
                                       registry (in-memory, O(1)) ◀── workers ◀── bounded queue
                                                                          │
                                                          APNs (iOS) / FCM (Android) push, retried/pruned by verdict
```

Endpoints (inside the onion envelope): `register`, `unregister`, `register_legacy_groups_only`,
`subscribe_closed_group`, `unsubscribe_closed_group`, `notify`.

## Install

```
pip install cryptography            # the whole core
pip install 'httpx[http2]'          # only if you enable APNs (APNs requires HTTP/2); FCM needs nothing extra
pip install uvloop                  # optional, faster event loop
```
Python 3.11+.

## Configuration

Precedence: defaults < TOML file (`--config` or `$BCHATPN_CONFIG`) < `BCHATPN_<KEY>` environment variables.
Unknown keys and bad values are startup errors, never silently ignored. See `deploy/bchatpn.example.toml`.

| Key | Default | Meaning |
|---|---|---|
| `key_file` | `x25519.key` | Server X25519 key (32 raw bytes or 64 hex). **Refused unless mode 600.** |
| `db_path` | `bchatpn.db` | SQLite file (WAL). Back it up by copying it. |
| `listen_host` / `listen_port` | `0.0.0.0` / `5000` | Public onion listener. |
| `admin_enabled` / `admin_host` / `admin_port` | `true` / `127.0.0.1` / `5001` | `/healthz`, `/metrics` (GET only). |
| `admin_token` | *(empty)* | If set, `/metrics` needs `Authorization: Bearer <token>`. |
| `apns_cert_file`, `apns_key_file`, `apns_topic`, `apns_sandbox` | — / — / `com.beldex.bchat` / `false` | APNs client-certificate auth. |
| `fcm_credentials_file` | *(empty)* | Google service-account JSON for Android pushes (FCM HTTP v1). **Refused unless mode 600.** |
| `log_only` | `false` | Dry-run provider (accept and log, push nothing). Must be explicit. |
| `queue_size`, `workers` | `20000`, `32` | Dispatch queue bound and concurrency. |
| `max_attempts`, `backoff_base`, `backoff_max`, `send_timeout` | `4`, `0.5`, `30`, `15` | Retry policy (exponential with jitter). |
| `message_ttl` | `60` | Queued notifications older than this are dropped as stale. |
| `rate_per_sec`, `rate_burst` | `20`, `100` | Per-recipient token bucket. |
| `max_devices_per_account`, `max_group_members`, `data_max` | `10`, `500`, `10240` | Abuse caps. |
| `honor_legacy_groups_only` | `false` | See "Compatibility notes". Forced on by secure mode. |
| `log_events` | `true` | One INFO line per register / notify / push. Secure mode turns it off unless set. |
| `secure_mode` | `false` | See "Secure mode". Same as `serve --secure`. |
| `registration_ttl_days` | `30` | Secure mode: drop registrations not renewed within this many days (`0` = never). |
| `signature_window` | `3600` | Secure mode: how old (or far ahead) a subscribe signature's timestamp may be, seconds. |

The server refuses to start with no provider configured (set `apns_cert_file` and/or `fcm_credentials_file`, or
`log_only=true` on purpose). `log_only` only takes the device types no real provider serves.

## Secure mode

```
python3 -m bchatpn serve --secure          # or secure_mode = true / BCHATPN_SECURE_MODE=true
```

Same single process, same one dependency, same listener and endpoints. Without the flag nothing changes: the
`bchatpn.secure` package is not even imported. With it:

| | What it does | What it fixes |
|---|---|---|
| 1. Signed `/subscribe`, `/unsubscribe` | The app already sends these (signed with the account key). Accepted only if the Ed25519 key maps to the account id and the signature verifies; timestamp must be within `signature_window`. Only signed devices get 1:1 pushes (`honor_legacy_groups_only` is forced on). | Nobody can register their own phone against your id to receive your message pings, re-home your token, or push your device out with a flood of unsigned registrations. |
| 2. Encrypted pushes | Each signed device gets `enc_payload` (XChaCha20-Poly1305 under that device's own key, zero-padded to 256-byte steps) and `spns: 1`, the format the app already decrypts. A subscription with `data: false`, or a message over 2.5 kB, sends metadata only. | Google sees an opaque blob of uniform size, not the message envelope. |
| 3. Ids hashed, tokens sealed at rest | Account/group ids become keyed BLAKE2b hashes; device tokens and push keys are authenticated-encrypted. Keys are derived (HKDF) from the server key file, so nothing extra to deploy. | A copied database or backup shows no account-to-device mapping. |
| 4. Registrations expire | A device not renewed within `registration_ttl_days` is removed (hourly sweep, and at startup). The app re-subscribes every time its home screen opens. | Less data kept; abandoned devices disappear. |
| 5. Quiet logs | Per-message lines (register / notify / push) are off unless `log_events = true`. Problems still log; counters are always in `/metrics`. | No per-message metadata on disk. |

Replies to `/subscribe` use the JSON shape the app parses (`{"success":true,"added":true}` / `{"error":1,...}`).

### Limits: what secure mode does not do

- **The sender's app still tells this server the recipient of every message**, including people who never enabled
  push (the app calls `notify` for each visible message). The server drops those at once and logs them only at DEBUG, but
  an operator who modified the code could record them. Closing that needs the v2 design (the server watches the
  recipient's swarm), which costs OxenMQ, persistent connections to the network's service nodes and a different
  hosting footprint. It is deliberately not part of this server.
- **Legacy closed groups stay unauthenticated.** Joining one is still an unsigned `subscribe_closed_group`, so
  someone who knows a group id can still receive its pings.
- **The signature is not bound to the device token**, so a leaked request could be replayed until it ages out of
  `signature_window` (an hour by default, against v2's 14 days).
- **At-rest protection covers a copied database, not the host.** Anyone with both the database and the key file,
  or the running process, can read it. Losing or replacing the key file makes stored registrations unreadable;
  devices register again the next time their app opens.
- **Android only.** `/subscribe` accepts `service: "firebase"`; APNs is not offered in secure mode.
- **iOS and apps that cannot sign get no 1:1 pushes** in secure mode (legacy group pushes still work).

### Switching modes

Secure mode refuses to start on a database holding normal-mode registrations (it would leave them readable on
disk): point `db_path` at a new file. Devices re-register by themselves the next time the app opens, so there is
nothing to migrate. Going back to normal mode uses its own tables and starts empty the same way.

### Cost (`python3 tools/bench.py [--secure]`, one core, 20,000 notifies)

| Recipients with a registered device | Normal | Secure |
|---|---|---|
| none (the usual case) | 5,195 req/s | 5,179 req/s |
| 5% | 5,135 | 4,944 |
| all (every notify is a push) | ~4,780 | ~4,316 |

The extra cost is per delivered push (about 9 us to build the encrypted payload with libsodium, 37 us without),
against ~700,000 us for the round trip to Google.
Encryption uses libsodium if the system already has it and the `cryptography` package otherwise; both are
tested to produce identical bytes (`BCHATPN_NO_LIBSODIUM=1` forces the second).

## Operating it

- **Health:** `GET :5001/healthz` (200/503). **Metrics:** `GET :5001/metrics` (Prometheus text): requests by
  endpoint and result, `notify_accepted/untracked/duplicate/rejected{reason}`, `push{provider,result}`,
  `push_pruned`, `queue_depth`, `breaker_open_<provider>`, `store_pending`, `store_errors`, request latency.
- **Logs:** JSON lines on stderr (`log_json=false` for plain text). At INFO, every `register`, `unregister`, accepted or
  rejected `notify`, and each push attempt (provider, result, attempt number) is one line; account ids and device tokens
  are shortened to 8 characters and payloads are never logged. A `notify` for someone with no registered device is the
  common case, so it is logged at DEBUG only (`log_level=DEBUG` to see it). No third-party alerting is built in; point
  your own alerting at `/metrics` (suggested: `store_errors > 0`, `queue_depth` near `queue_size`,
  `breaker_open_apns == 1`, and `push{result="invalid_token"}` spikes).
- **Shutdown:** SIGTERM stops accepting, finishes in-flight requests, drains queued pushes (up to
  `shutdown_grace`), flushes the store. Registrations are durable ~50 ms after they are acknowledged.
- **Backup:** `cp bchatpn.db` (WAL checkpointed by SQLite) or `sqlite3 bchatpn.db ".backup file"`.

## What was verified, and what was not

Verified here (`python3 -m unittest discover -s tests` — 258 tests, offline):
- v2 and v4 onion wire compatibility, checked against an *independent* port of the Android client logic
  (`tests/clientcrypto.py`, which imports nothing from the server) and the RFC 7748 X25519 vector.
- Every endpoint's reply as the app parses it, and how the app reacts to each status (retry vs path penalty).
- Persistence including a hard process kill, write batching, retry of failed commits.
- Dispatcher retry/backoff, verdict-driven pruning, circuit breaker, backpressure, graceful drain.
- FCM: the service-account JWT's RS256 signature (verified with the matching public key), access-token caching,
  expiry margin, single shared refresh under concurrency, 401 refresh-and-retry, every status -> verdict mapping,
  and that the message is the one the legacy server sent (`data.ENCRYPTED_DATA`, priority high).
- Secure mode: Ed25519 signatures and id binding against an independent client (accounts derived the way the app
  derives them), pushes decrypted the way the app does (libsodium), hijack / eviction / replay / forgery attempts,
  expiry, restart persistence, and a scan of the database file for any plaintext id, token or key.
- HTTP hardening (limits, smuggling guards, slow clients) and a real single-process run from a stripped
  environment.

**Not verified (cannot be, offline):** real APNs over HTTP/2 with a client certificate (`httpx` was not
installable in the build sandbox, so the transport is exercised only through a fake — run one push against
Apple's sandbox, `apns_sandbox=true`, before production); real onion traffic through storage nodes; real FCM
(the exchange with Google's token endpoint and `fcm.googleapis.com` is exercised only through a fake — send one
push to a real device before relying on it).

## Compatibility notes — read before cutting over

- **FCM (Android)** is `bchatpn/providers/fcm.py`, authenticated with the same service-account JSON the legacy
  server uses (`bchat-android-ios-firebase.json`). It is a production credential: keep it outside the repo,
  mode 600, and point `fcm_credentials_file` at it. Huawei (HMS) is not implemented; those devices are stored
  and only served by the dry-run provider if `log_only` is on.
- **The app pins the server.** `Server.LEGACY` (URL + X25519 public key) is compiled into the app, so a new
  server key needs an app release. Do not reuse the legacy server's key: it is committed in that repo.
  Run old and new servers in parallel while app versions migrate; this server does not import the legacy
  database (apps re-register on their own).
- **No client authentication.** As with the legacy server, `register`/`notify` are unsigned (the app does not
  sign them), so anyone can register a token against any id. Bounded by per-account device caps and
  per-recipient rate limits; fixing it properly needs a client change.
- **`legacy_groups_only`** is stored but, by default, does not suppress 1:1 pushes, matching the legacy server's
  behaviour. Today that is what makes 1:1 push work (the v2 server's payload uses the key `pns`, which the app
  does not decode — it looks for `spns`). Enable `honor_legacy_groups_only` only after that is fixed.
- **Reply status codes are deliberate.** "Busy" and bad input are sent as status 400 inside the envelope:
  the app retries those, and 400 is the one rejection it does not count against its onion path (a 5xx or 429
  would make it discard a healthy path). Soft refusals (too large, rate limited) are status 200 / code 0, which
  the app logs and does not retry. Unregister and group-unsubscribe are idempotent.

## Performance (measured, one dev machine)

`python3 tools/bench.py`: real server process, dry-run provider, 64 in flight, 4 load-generator processes.

| | |
|---|---|
| Throughput | ~4,900–5,300 req/s, using 100% of **one** core |
| Latency at that load | p50 ≈ 13 ms, p99 ≈ 17 ms (queueing at saturation; unloaded it is far lower) |
| Memory | 37 MB with 2k devices, 87 MB with 100k devices |
| Registration | ~3,800 devices/s |

Where the time goes: about 85 µs/request is the handler (33 µs of that X25519, unavoidable); the rest is
per-connection asyncio/TCP work (one request per connection). The server is single-process by design (state is
in memory), so scale-up means a faster core, not more processes. These figures were **not** compared with the
legacy server, whose dependencies are not installed here; do not read them as a speedup claim. End-to-end push
latency is dominated by the Apple round trip, not this server.
