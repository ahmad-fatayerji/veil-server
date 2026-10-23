# Veil server

Self-hosted sharing for Veil. The server helps apps connect and relays encrypted
traffic when a direct connection fails. It does not store documents. The host's
Veil app must stay open while people collaborate.

| Service | Role |
| --- | --- |
| `signaling` | Our Rust server: sharing sessions, guest admission, connection setup, and temporary relay credentials. |
| `caddy` | HTTPS and automatic signaling certificates. |
| `turn` | coturn: network address discovery and fallback traffic relay. |

## Hosting requirements

The bundled stack uses Linux and Docker Compose. Both hostnames must resolve to
an externally reachable server. It needs TCP 80, TCP/UDP 443, TCP/UDP 3478, and
UDP 49160-49200. Behind a router, forward these ports without changing the relay
port numbers. CGNAT needs an inbound mapping.

Published image: `ghcr.io/ahmad-fatayerji/veil-server:latest`.
Deployment configuration: [compose.yaml](compose.yaml).

## Configuration

Use [.env.example](.env.example) as your `.env`. Set `SIGNAL_HOST`, `TURN_HOST`,
and `TURN_PUBLIC_IP` to your server's addresses. Leave the limits at their defaults
unless you need different capacity.

**[Every environment variable explained](docs/configuration.md)**

By default, hosting requires a credential. The server's `veil-server issue alice`
command issues one; `veil-server revoke alice` revokes all credentials under that
name. Run these commands inside the signaling container. In Veil, use
`https://<SIGNAL_HOST>` and the issued credential.

Set `PUBLIC_HOSTING=on` to let anyone host without a credential, within the public
limits. Guests join using the host's invitation link.

Restarting signaling loses active session registrations; hosts need to share
again. Host credentials persist in `data/hosts.sqlite`.

[Security](SECURITY.md) | [Protocol](protocol.md) | [MIT license](LICENSE)
