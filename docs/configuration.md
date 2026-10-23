# Configuration

For the standard Docker setup, edit `.env`. Apply changes with
`docker compose up -d --no-build`; restarting signaling ends active registrations.

## Server addresses

| Variable | Value | Meaning |
| --- | --- | --- |
| `SIGNAL_HOST` | Required hostname | Address people enter in Veil, such as `signal.example.com`. Caddy handles HTTPS automatically. |
| `TURN_HOST` | Required hostname | Relay address, such as `turn.example.com`. Can match `SIGNAL_HOST`. |
| `TURN_PUBLIC_IP` | Required public IPv4 | Externally reachable relay IP. Behind NAT, use `PUBLIC_IP/PRIVATE_IP`. |

The addresses in `.env.example` are placeholders. Hostnames must not include
`https://`, paths, or port numbers.

## Hosting limits

A session is one shared document. A relay grant gives one connection endpoint
temporary relay credentials; it is not a participant count.

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAX_SOCKETS` | `60` | Maximum live signaling connections across all users. |
| `MAX_RELAY_GRANTS` | `16` | Maximum active relay grants per issued host credential, across its documents. |
| `PUBLIC_HOSTING` | `off` | Set to `on` to allow hosting without an issued credential. |
| `PUBLIC_MAX_SESSIONS` | `12` | Maximum simultaneous public sessions. |
| `PUBLIC_SESSIONS_PER_IP` | `3` | Maximum public sessions per client network. |
| `PUBLIC_MAX_GUESTS` | `5` | Maximum guests per public session, excluding the host. |
| `PUBLIC_MAX_SOCKETS` | `40` | Maximum live signaling connections used by public sessions; cannot exceed `MAX_SOCKETS`. |
| `PUBLIC_RELAY_GRANTS` | `8` | Maximum public relay grants, within the server's total pool of 32. |
| `PUBLIC_RELAY_GRANTS_PER_IP` | `2` | Maximum public relay grants per client network. |

Per-IP limits group clients by IPv4 address or IPv6 /64. Public limits apply only
when public hosting is enabled. Issued credentials continue working in that mode.

Coturn also has separate limits in `deploy/turnserver.conf`: 32 relay allocations
total, four per TURN username, 256 KiB/s per allocation per direction, and 8 MiB/s
aggregate bandwidth. One connection can use multiple allocations. Raising the
environment limits alone does not raise coturn's limits.

## Container settings

Compose supplies these automatically. Leave them alone for the standard setup;
putting different values in `.env` will not override these entries in `compose.yaml`.

| Variable | Compose value | Meaning |
| --- | --- | --- |
| `LISTEN` | `0.0.0.0:8080` | Signaling listener inside the private Docker network. |
| `HOST_DB` | `/data/hosts.sqlite` | SQLite file holding issued host credential hashes and names. |
| `TURN_SECRET_FILE` | `/run/secrets/turn_secret` | Shared secret used by signaling to issue credentials coturn accepts. |
| `METRICS_SECRET_FILE` | `/run/secrets/metrics_secret` | Secret protecting signaling metrics. |
| `STUN_URLS` | `stun:${TURN_HOST}:3478` | Comma-separated connection discovery URLs sent to apps. |
| `TURN_URLS` | UDP and TCP URLs for `${TURN_HOST}:3478` | Comma-separated relay URLs sent to apps. The TLS override adds port 5349. |
| `CLIENT_IP_HEADER` | `X-Veil-Client-IP` | Header Caddy overwrites with the real client IP for public limits. Trusted only from private/loopback proxy connections. |

If running the binary without Compose, `LISTEN` defaults to `127.0.0.1:8080`,
`HOST_DB` to `hosts.sqlite`, and `CLIENT_IP_HEADER` is unset. Both secret-file paths
and both URL lists are required. Keep signaling behind a trusted HTTPS proxy;
never expose its plain HTTP listener directly.

## Optional TURN over TLS

For networks that need TLS relay, provide a valid certificate for `TURN_HOST` in
`secrets/turn.crt` and its key in `secrets/turn.key`, then open TCP 5349.
You must arrange certificate renewal; Caddy does not share its certificates with coturn.

```sh
docker compose -f compose.yaml -f compose.tls.yaml up -d --no-build
```

Use both `-f` options for subsequent Compose commands so TLS stays enabled.

## Metrics and image versions

Signaling metrics are at `/v2/metrics`, protected by Bearer authorization using
`secrets/metrics-secret`. Coturn metrics are at `http://127.0.0.1:9641/metrics`
on the server; keep that endpoint private. `docker stats --no-stream` shows
container CPU and memory use.

CI publishes `ghcr.io/ahmad-fatayerji/veil-server:latest` after checks pass on
`main`. It also publishes a full commit-SHA tag. To pin a version or roll back,
set the signaling image to that tag in a local Compose override and keep the
deployment configuration aligned with that revision. Publication does not update
your running server.

Developers can build from source with `docker compose up -d --build`.
