# Veil signaling protocol v2

JSON names are camelCase. IDs are 32 lowercase hex characters; credentials are
64 lowercase hex characters. HTTPS origins have no user information, path, query
or fragment. Production clients refuse plaintext. HTTP loopback is test-only.

`veil-invite:v2:` precedes base64 UTF-8 JSON with version=2, server, sessionId,
inviteId, secret (32 random bytes as hex), hostClientId (Yjs uint32), expiresAt
(Unix milliseconds). Send invitations privately. Single redemption, ten minutes.

HKDF-SHA-256 input is the decoded 32-byte root secret; salt is UTF-8
`sessionId:inviteId`. Info is `veil.signaling.v2:admission`, `:host`, or `:guest`.
Admission output is 32 bytes encoded as hex. Register SHA-256 of that hex string's
UTF-8 bytes, redeem with the hex admission output. Host/guest outputs are separate
AES-GCM-256 keys. Neither root nor encryption key is sent to the server.

An envelope contains inviteId, role (host|guest), generation (0..1000000), sequence
(monotonically increasing safe integer), nonce (base64: four random prefix bytes fixed per sender, followed by the eight-byte big-endian sequence), ciphertext
(base64 AES-GCM ciphertext with 128-bit tag). Additional authenticated data is UTF-8
JSON array `[2,sessionId,inviteId,role,generation,sequence]`. Clients reject replay,
wrong roles, nonces, metadata or cross-session substitution. Sequence does not reset
on socket reconnect. Negotiation generation increases for each replacement; late
messages cannot affect another generation.

Encrypted payload kinds: request `{clientId,migrate?,restart?}`, offer
`{connectionId,clientId,sdp,phase:'direct'|'relay',migrate}`, answer
`{connectionId,clientId,sdp}`, candidate `{connectionId,candidate}` and cancel
`{connectionId}`. Authenticate descriptions before accepting their SHA-256 DTLS
fingerprints or candidates. Data channel hello binds the invitation and expected
Yjs client ID; synchronize state vectors before closing a replacement's predecessor.

| Endpoint                          | Authorization and purpose                                                    |
| --------------------------------- | ---------------------------------------------------------------------------- |
| GET /health                       | Public liveness/protocol version                                             |
| GET /v2/capabilities              | Public STUN URLs and negotiation deadlines                                   |
| POST /v2/sessions                 | Host Bearer credential; `{clientId}` → sessionId, ticket, stunUrls           |
| POST /v2/sessions/:id/invitations | Host session ticket; inviteId, admissionHash, expiresAt                      |
| POST /v2/join                     | sessionId, inviteId, admission, clientId → ticket, hostClientId, stunUrls    |
| GET /v2/socket/:id                | Bearer session ticket; WSS opaque signaling                                  |
| POST /v2/relay                    | Admitted ticket; sessionId, inviteId → urls, username, credential, expiresAt |
| DELETE /v2/sessions/:id           | Host session ticket; end/notify peers                                        |
| GET /v2/metrics                   | Separate operator metrics Bearer secret                                      |

POST `/v2/path` accepts host-ticket-authenticated sessionId, inviteId and selected
path telemetry (`direct`, `relay`, `checking`). POST `/v2/leave` accepts the guest
ticket plus sessionId/inviteId, revokes that admission and notifies the host.

Socket events: ready, admitted `{inviteId,clientId}`, signal `{envelope}`, left `{inviteId}`, ended.
Session tickets are server capabilities, not proof of peer identity. Clients never
trust plaintext admitted metadata as document authentication.

TURN uses coturn REST time-limited HMAC-SHA1 credentials, expiry 600 seconds.
Issue only after direct failure. Refresh by authenticated replacement at 480 seconds
for active selected relay paths. Never restart healthy unrelated host–guest links.
