# Security boundaries

Report vulnerabilities privately to the repository owner before disclosing them.
The service requires TLS via Caddy in production, individually issued host access
credentials and admitted per-invitation guest tickets. Only SHA-256 host/admission
credential hashes persist. Tickets, invitations, registrations and signaling remain
in memory. No endpoint accepts document snapshots.

Invitation root secrets never reach signaling. The server forwards authenticated
ciphertext; its admission credential is a separate HKDF output. Client verification
must bind session, invitation, role, generation, sequence, participant identity and
DTLS fingerprint. HTTPS alone does not protect against a malicious operator.

Protect secret files, backups and Docker administration. Metrics use a separate
operator credential. Public health/capabilities reveal configuration only. API
payloads and WebSocket frames are limited to 128 KiB; queues to 128 messages;
signaling to 120 frames per second per ticket; idle registrations to ten minutes.
Slow destinations are disconnected independently. Operator-approved hosts can still
abuse their permissions: deploy firewall egress restrictions as an additional layer.
Keep coturn and base images patched and review resource ceilings periodically.

Do not enable allow-loopback-peers or remove destination exclusions in production.
CI binds its listeners locally but retains production peer destination exclusions.
Never add `denied-peer-ip=::`: coturn treats that unspecified address as a wildcard
range and denies public peers too. Its default unspecified-peer guard remains on.
Coturn applies the IPv4 exclusions to mapped IPv4 addresses as well. Do not block
the entire `::ffff:0:0/96` range: that also denies legitimate public IPv4 peers.
Container CI checks public permissions succeed while private, loopback and
link-local destinations are rejected, without sending traffic to those peers.
