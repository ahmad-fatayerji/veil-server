# Veil server

MIT-licensed, self-hosted signaling and selective WebRTC relay for Veil desktop.
Friends install only Veil. Operators maintain this Linux stack; hosts save their
operator-issued credential once, or host without one when the operator enables
the bounded public tier. There is no account registration, document storage or
host migration.

The desktop forms a star: five host–guest connections in a six-person session.
Each connection tries STUN/direct ICE for six seconds without TURN credentials.
Only failed links request short-lived TURN credentials and retry for twenty
seconds. Three friends may remain direct while two relay. Relayed links carry
the host's forwarded document/presence changes from all participants.

## Deploy on Linux

Install Docker Engine and Compose v2. Obtain a public hostname you control (a
free DNS hostname can work; buying a domain is not required). Set its DNS A record
to your public IPv4 address. Add AAAA only when IPv6 routing/firewalls work.
The host needs internet ingress; CGNAT without an inbound mapping is insufficient.

```sh
git clone https://github.com/ahmad-fatayerji/veil-server.git
cd veil-server
cp .env.example .env
# Edit SIGNAL_HOST, TURN_HOST and TURN_PUBLIC_IP. Do not include https://.
mkdir -p data secrets
chmod 700 secrets
openssl rand -hex 32 > secrets/turn-secret
openssl rand -hex 32 > secrets/metrics-secret
chmod 600 secrets/*
# The signaling container runs as uid 10001.
sudo chown 10001:10001 data
# Compose file secrets must be readable by the container uid.
sudo chown 10001:10001 secrets/turn-secret secrets/metrics-secret
docker compose up -d --build
docker compose exec signaling veil-server issue alice
```

The last command prints Alice's host credential. Send it privately, never commit
it or paste it into an issue. Alice enters `https://SIGNAL_HOST` and that credential
in Veil Settings. Create document works offline; Share uses the saved configuration
and creates one reusable app link for friends. Friends need Veil installed and
press Join after opening or pasting the link. Stop sharing or Reset link blocks
new admission without disconnecting existing collaborators. Legacy ten-minute,
single-use invitations remain supported. Use `docker compose exec signaling veil-server
revoke alice` to revoke every credential issued under that name.

Open/forward TCP 80 (certificate issuance), TCP/UDP 443 (signaling HTTPS), TCP/UDP
3478 (STUN/TURN), and UDP 49160–49200 (relay sockets). NAT port mappings must
preserve relay port numbers. `TURN_PUBLIC_IP` is the externally reachable IP;
for a host behind NAT use coturn's `PUBLIC_IP/PRIVATE_IP` mapping. Host networking
for coturn intentionally requires Linux. Caddy terminates signaling HTTPS;
TURN is not HTTP and does not pass through Caddy.

The bundled containers run at low CPU priority with hard memory, CPU and process
ceilings (signaling 96 MiB/0.25 CPU, TURN 160 MiB/0.5 CPU), so a busy Veil server
slows down instead of starving other services on the same machine. Lower coturn's
`bps-capacity` if relay bandwidth must stay below the default 8 MiB/s.

Restrict access to the Docker socket and secret files. Back up `data/hosts.sqlite`
and configuration securely; there are no document snapshots to back up. Restarting
signaling terminates registrations. Healthy existing peer transports may continue
until clients learn their registration is gone; local content stays visible for
copying. New joins/recovery require a new host session.

## Optional public hosting

Set `PUBLIC_HOSTING=on` in `.env` to let anyone host without a credential. Issued
credentials keep working as a trusted tier whose capacity public load cannot use.
Each limit is an environment variable:

| Variable                     | Default | Meaning                                              |
| ---------------------------- | ------: | ---------------------------------------------------- |
| `MAX_SOCKETS`                |      60 | Live WebSockets server-wide, both tiers              |
| `PUBLIC_MAX_SESSIONS`        |      12 | Concurrent public sessions                           |
| `PUBLIC_SESSIONS_PER_IP`     |       3 | Concurrent public sessions per IPv4 address/IPv6 /64 |
| `PUBLIC_MAX_GUESTS`          |       5 | Guests per public session                            |
| `PUBLIC_MAX_SOCKETS`         |      40 | Live WebSockets used by public sessions              |
| `PUBLIC_RELAY_GRANTS`        |       8 | Public relay grants (of the 32 total)                |
| `PUBLIC_RELAY_GRANTS_PER_IP` |       2 | Public relay grants per client network               |
| `MAX_RELAY_GRANTS`           |      16 | Relay grants per issued credential                   |

When a limit is reached the desktop tells users and suggests self-hosting or
another server. Public limits need the real client address: the bundled Caddy
sets `X-Veil-Client-IP` and the server trusts it only from the private backend
network (`CLIENT_IP_HEADER`). With another reverse proxy, overwrite that header
with the validated client address; behind a CDN, resolve it only from the CDN's
trusted ranges, so clients that bypass the CDN keep their own address. Each WebSocket holds a
proxy connection, so keep `MAX_SOCKETS` well below your proxy's worker limit if
it serves other sites. Set `PUBLIC_HOSTING=off` and restart signaling to end all
public sessions; credentialed hosts are unaffected.

## Optional TURN TLS

Supply your own valid certificate/key for TURN_HOST in `secrets/turn.crt` and
`secrets/turn.key`. Open TCP 5349. Certificates require external renewal; Caddy's
signaling certificates are not automatically shared with coturn.

```sh
docker compose -f compose.yaml -f compose.tls.yaml up -d --build
```

## Limits, metrics and maintenance

The initial profile permits 32 allocations total, four per credential,
256 KiB/s per allocation per direction and an 8 MiB/s aggregate bandwidth budget.
These are coturn resource ceilings, not a participant cap. The signaling service
allows sixteen active endpoint grants per host credential by default (shared by
all documents that host has open), with cached identities,
bounded renewal and issuance. Increase MAX_RELAY_GRANTS and coturn quotas only
after measuring the server and reviewing its budget. One connection can allocate
more than one TURN socket during ICE; credentials do not imply a selected relay.

Operator-only signaling counters are available at `/v2/metrics` with the separate
metrics secret as Bearer authorization. Coturn's Prometheus endpoint binds to
127.0.0.1:9641 on the Linux host; never expose it publicly. It measures actual
allocation and byte counters. Use `docker stats --no-stream` for CPU/memory.
Client path telemetry reports selected ICE paths; it is client-reported and is
not billing evidence. Compare it with coturn counters.

```sh
curl -H "Authorization: Bearer $(cat secrets/metrics-secret)" https://YOUR_SIGNAL_HOST/v2/metrics
curl http://127.0.0.1:9641/metrics
docker stats --no-stream
docker compose logs --tail=100 signaling turn
docker compose build --pull
docker compose up -d
```

Credential expiry/revocation does not instantly kill existing TURN allocations.
Clients close obsolete transports after synchronization or leaving; coturn expires
abandoned allocations according to its allocation lifetime. Grant accounting retains
expired usernames for that additional lifetime to prevent identity churn. Rotation
may overlap old/new allocations; total-quota remains the hard ceiling. Test cleanup
on your coturn version before relying on an exact deadline.

Private, loopback, link-local and multicast relay destinations are blocked. No
content, decrypted signaling or invitation secrets are logged. Operators can
observe addresses, timing, ciphertext sizes and relay traffic, or deny service;
they cannot authenticate a substituted peer without the invitation secret.

## Published server image

`develop` is the integration branch; `main` is the production source branch.
Promote changes with a PR from `develop` into `main`. Both branches require
Server CI gate and resolved review conversations before merging, and reject force
pushes and deletion. Merged feature branches are automatically deleted; `develop`
and `main` remain protected.

Every push to `main` runs Rust checks, protocol fixtures, Docker build and real
STUN/TURN integration before publishing `ghcr.io/ahmad-fatayerji/veil-server`.
Images have a full commit SHA tag and `latest`. Publication is serialized; rerunning
an older commit publishes its SHA tag without moving `latest` backwards. Manual
publication is available through **Publish server container** on `main` only.
Publication never connects to or restarts an operator's server.

Operators choose when to update. To use the published image with the bundled
Compose configuration instead of building locally:

```sh
docker compose pull signaling
docker compose up -d --no-build signaling
```

For a pinned release or rollback, override the signaling image with
`ghcr.io/ahmad-fatayerji/veil-server:<full-commit-sha>` in a local Compose override.
Keep the deployment configuration aligned with that source revision and preserve
the data and secrets directories. Updating/restarting ends active registrations.

## Development and validation

Upgrading an existing deployment keeps `data/hosts.sqlite` and every issued
credential; current sessions end and hosts share again:

```sh
git pull
docker compose up -d --build
curl -s https://YOUR_SIGNAL_HOST/v2/capabilities
```

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
docker compose --env-file .env.example config --quiet
docker build -t veil-server:development .
```

CI validates Rust, protocol/authentication, container builds and actual STUN/TURN
allocation/cleanup. Desktop connection tests live in the private desktop repository;
no private editor source belongs here. See [protocol.md](protocol.md) and
[SECURITY.md](SECURITY.md). Local automation does not establish connectivity from
unrelated Windows PCs. Test direct, TURN UDP, TURN TCP and optional TURN TLS on
real networks before deploying to friends; universal connectivity is not promised.

Reusable sharing requires the coordinated desktop update and this server revision.
Old servers omit `groupSharing: 1`; the new desktop explains that an update is
required instead of silently replacing group sharing with one-use invitations.
Upgrade through your normal deployment process; source PRs do not deploy servers.

## Client compatibility

Capabilities advertise the server software version and release-maintained API
support. New clients can preview a session using its admission credential without
consuming an invitation. Session creation/admission reject unsupported protocols;
older clients retain API 2 / peer 1 support until it is explicitly retired.
Different supported desktop versions may join after a feature-compatibility warning.
See [protocol.md](protocol.md). Deploy coordinated server support before distributing
the desktop feature; changing supported generations requires compatibility review.

## Short links and optional approval

Capabilities now advertise `shortInvitations: 1`. Updated hosts copy links with
the server authority and a 22-character random code. Invitations are encrypted
locally; the service never receives the code or invitation root secret. Hosts
choose Auto join (default) or Require approval. Pending guests expire after two
minutes and cannot obtain relay credentials. Existing long-link registrations
remain supported. Upgrade the server before distributing the coordinated app;
opening a source PR does not deploy or publish a container.
