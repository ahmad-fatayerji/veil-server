# Environment variables

Edit `.env` for the bundled Compose deployment. Changes take effect when the
containers are recreated. A signaling restart loses active session registrations.
The example addresses are placeholders; replace them with your own.

## Server addresses

| Variable | How it works |
| --- | --- |
| `SIGNAL_HOST` | Public hostname for the sharing API, such as `signal.example.com`. Caddy uses it to obtain an HTTPS certificate and route requests to signaling. Users enter `https://signal.example.com` in Veil. |
| `TURN_HOST` | Public hostname for connection discovery and relay, such as `turn.example.com`. Signaling advertises this address to apps, and coturn uses it as its authentication realm. It can be the same hostname as `SIGNAL_HOST`. |
| `TURN_PUBLIC_IP` | Public IPv4 address coturn advertises for relay traffic. This must be reachable by the apps. Behind NAT, use `PUBLIC_IP/PRIVATE_IP`, for example `203.0.113.10/192.168.1.10`, so coturn maps its local address to the public one. |

Both hostnames need DNS records pointing to the server. Enter hostnames without
`https://`, paths, or port numbers. Only publish IPv6 DNS records if IPv6 routing
and firewall access work.

## Access and capacity

A **session** is one shared document. A **socket** is one app's live signaling
connection for a session. A **relay grant** gives one connection endpoint temporary
TURN credentials; it does not mean that connection actually uses the relay.

| Variable | Default | How it works |
| --- | --- | --- |
| `PUBLIC_HOSTING` | `off` | `off` requires an issued host credential to create a session. `on` also allows credential-free hosting, governed by the `PUBLIC_*` limits below. Issued credentials still work. Guests use invitations in either mode. |
| `MAX_SOCKETS` | `60` | Caps live signaling sockets across credentialed and public sessions together. New connections are rejected when full. Raising it allows more connections and increases potential memory and proxy load. |
| `MAX_RELAY_GRANTS` | `16` | Caps active relay grants per issued host credential, shared across all documents using that credential. Raising it lets that host request more simultaneous relay endpoints, subject to the server-wide pool and coturn limits. |

## Public hosting limits

These settings apply only to sessions created without an issued host credential.
All applicable limits must have room: raising one does not bypass the others.
Per-IP limits group clients by IPv4 address or IPv6 /64, so people behind the same
router may share an allowance.

| Variable | Default | How it works |
| --- | --- | --- |
| `PUBLIC_MAX_SESSIONS` | `12` | Caps simultaneous public sessions across the server. At 12, another public document cannot be shared until a session ends. Increase it to allow more public documents at once. |
| `PUBLIC_SESSIONS_PER_IP` | `3` | Caps simultaneous public sessions from one client network. Limits how much of the public session allowance one network can occupy. Raising it helps shared networks but lets one network use more capacity. |
| `PUBLIC_MAX_GUESTS` | `5` | Caps guest admissions per public document, excluding its host. The default allows a host and five guests. Raising it allows larger groups, subject to available sockets and relay capacity. |
| `PUBLIC_MAX_SOCKETS` | `40` | Caps signaling sockets belonging to public sessions. It cannot exceed `MAX_SOCKETS`. A lower public cap leaves room for credentialed users; with defaults, public sockets can occupy at most 40 of 60 slots. |
| `PUBLIC_RELAY_GRANTS` | `8` | Caps public relay grants across all public sessions. These use part of the server-wide 32-grant pool. Raising this allows more public fallback connections but leaves less reserved capacity for credentialed users. Cannot exceed 32. |
| `PUBLIC_RELAY_GRANTS_PER_IP` | `2` | Caps public relay grants across sessions created by hosts on one client network, including grants for their guests. Raising it allows those sessions more fallback endpoints, subject to the public and server-wide pools. |

These are concurrent limits, not bandwidth settings. Reaching a limit rejects
new work needing that capacity; it does not increase the server's resources.
Relay grants remain counted through credential expiry plus the allocation cleanup
window, so leaving a session does not immediately free its relay allowance.

Coturn has its own limits in `deploy/turnserver.conf`: 32 allocations total,
four per TURN username, 256 KiB/s per allocation per direction, and 8 MiB/s
aggregate bandwidth. A connection can use multiple allocations. Raising the
environment limits does not change these coturn limits.

## Settings supplied by Compose

These are environment variables inside the signaling container. The bundled
`compose.yaml` sets them directly, so adding them to `.env` does not override them.
Change the service environment in your deployment configuration only if you are
customizing the setup.

| Variable | Compose value | How it works |
| --- | --- | --- |
| `LISTEN` | `0.0.0.0:8080` | Address and port the signaling process binds inside Docker. Caddy forwards requests here. Changing it also requires changing the proxy destination. Keep this plain HTTP listener private. |
| `HOST_DB` | `/data/hosts.sqlite` | SQLite file containing issued credential hashes and names. Compose maps `/data` to the host's `data/` directory, which must be writable by UID 10001. Pointing at an empty database means previously issued credentials are no longer recognized. |
| `TURN_SECRET_FILE` | `/run/secrets/turn_secret` | File containing the secret signaling uses to generate temporary coturn credentials. Compose mounts `secrets/turn-secret` into both services; both must use the same secret. Signaling requires at least 32 characters. Changing it requires coordinating both services and affects existing relay credentials. |
| `METRICS_SECRET_FILE` | `/run/secrets/metrics_secret` | File containing the Bearer token required by `/v2/metrics`. Compose mounts the host's `secrets/metrics-secret` here. Changing it changes the token monitoring clients need; it does not change hosting credentials. |
| `STUN_URLS` | `stun:${TURN_HOST}:3478` | Comma-separated discovery addresses sent to apps for their first direct-connection attempt. Compose fills in `TURN_HOST`. If the address is wrong, apps cannot use that discovery service. |
| `TURN_URLS` | UDP and TCP TURN URLs on `${TURN_HOST}:3478` | Comma-separated relay addresses sent with temporary credentials when a link needs fallback. The bundled values offer UDP and TCP. Advertise only listeners the relay actually serves; incorrect addresses break fallback. |
| `CLIENT_IP_HEADER` | `X-Veil-Client-IP` | Header used to identify client networks for public limits. Caddy overwrites it with the connecting client's address; signaling trusts it only from private or loopback proxy connections. A custom proxy must overwrite it too, or limits may group users incorrectly. |

The two secret files must be readable by the signaling process (UID 10001).
Without Compose, the binary defaults to `LISTEN=127.0.0.1:8080` and
`HOST_DB=hosts.sqlite`, with no client-IP header. Both secret-file paths and both
URL lists must be supplied.

## Optional TURN over TLS

`compose.tls.yaml` adds a `turns:` URL on TCP 5349 to `TURN_URLS` and configures
coturn to use `secrets/turn.crt` and `secrets/turn.key`. The certificate must cover
`TURN_HOST`. Enable this override when you need TLS relay, allow TCP 5349, and
arrange certificate renewal. Caddy's HTTPS certificate is separate.
