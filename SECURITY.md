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

Reusable sharing uses a revocable admission capability and a separate ticket for
each guest. Clients pin the host signing public key from the app link and derive
per-link encryption keys using authenticated ECDH. Shared invitation holders do
not know other guests' established keys. Only the bootstrap contains public
exchange keys; the server does not receive root secrets, private keys or document
content. See protocol.md for transcript and domain separation details. Do not log
invitation URLs. Reset/Stop sharing blocks new joins, not existing editing access.

Short links carry a 128-bit code that never reaches the server. The service holds
only domain-separated lookup credentials/hashes and the authenticated encrypted
invitation record. Resolution is credential-authenticated, bounded and rate
limited; it never refreshes a session lifetime. Pending short-link guest tickets
expire after 120 seconds, cannot obtain TURN grants and can send only bootstrap
signaling. Hosts gate signed key exchange and document transport locally. A
server-side approval is not proof of the host's user decision. Names are unverified.
Reset/Stop discard pending tickets and lookup state, preserving approved guests.
