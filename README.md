# Veil server

Host your own server for sharing documents in Veil. It helps apps connect and
relays encrypted traffic when a direct connection fails. Documents stay on the
participants' computers.

Docker runs three services: **signaling** (our server), **Caddy** (HTTPS), and
**coturn** (connection discovery and relay).

## 1. Prepare your server

You need a Linux machine with Docker Engine, Docker Compose v2, Git, and OpenSSL.
Use a public IPv4 address that accepts incoming connections. Home hosting needs
port forwarding; CGNAT without an inbound mapping will not work.

Point your signaling and TURN hostnames at that IP using DNS A records. You can
use the same hostname for both. Only add an AAAA record if IPv6 works too.

Open these ports in your firewall and router:

| Ports | Purpose |
| --- | --- |
| TCP 80 | HTTPS certificate setup and renewal |
| TCP/UDP 443 | Secure app connections |
| TCP/UDP 3478 | Connection discovery and relay |
| UDP 49160–49200 | Relay traffic; preserve port numbers when forwarding |

## 2. Configure

```sh
git clone --branch main https://github.com/ahmad-fatayerji/veil-server.git
cd veil-server
cp .env.example .env
```

Edit these three values in `.env` (hostnames have no `https://` prefix):

```dotenv
SIGNAL_HOST=signal.example.com
TURN_HOST=turn.example.com
TURN_PUBLIC_IP=203.0.113.10
```

Leave the other settings at their defaults. See the
[environment variable reference](docs/configuration.md) if you want to change them.

Create the secrets once, on a new installation:

```sh
mkdir -p data secrets
chmod 700 secrets
openssl rand -hex 32 > secrets/turn-secret
openssl rand -hex 32 > secrets/metrics-secret
chmod 600 secrets/turn-secret secrets/metrics-secret
sudo chown 10001:10001 data secrets/turn-secret secrets/metrics-secret
```

## 3. Start and connect

```sh
docker compose pull
docker compose up -d --no-build
docker compose exec signaling veil-server issue alice
```

The last command prints a private hosting credential. In Veil Settings, choose
your own server and enter `https://signal.example.com` and that credential.
Share a document and send the invite link to friends who have Veil installed.
The host's app must stay open.

By default, only people with an issued credential can host. To let anyone host,
set `PUBLIC_HOSTING=on` in `.env` and run `docker compose up -d --no-build` again.
Public hosting has [configurable limits](docs/configuration.md).

To revoke all credentials issued under a name:

```sh
docker compose exec signaling veil-server revoke alice
```

## Updates and maintenance

To update the configuration and download the latest published containers:

```sh
git pull --ff-only
docker compose pull
docker compose up -d --no-build
```

Updates that restart signaling end session registrations; hosts need to share
again. Back up `data/hosts.sqlite`, `.env`, and `secrets/` securely. Keep secret
files private and do not regenerate them during updates.

To check status or troubleshoot:

```sh
docker compose ps
docker compose logs --tail=100 signaling turn caddy
curl -f https://signal.example.com/health
```

The health check confirms signaling responds. Test sharing between computers on
different networks to check real connectivity.

[Configuration and optional TURN TLS](docs/configuration.md) ·
[Security](SECURITY.md) · [Protocol](protocol.md) · [MIT license](LICENSE)
