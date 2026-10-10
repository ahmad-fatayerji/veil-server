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


## Reusable sharing extension (groupSharing=1)

The v2 capabilities response advertises `groupSharing: 1`. Existing v2 invitations,
WebSocket routing, relay grants and single-use semantics remain compatible.

A host session ticket authorizes POST `/v3/sessions/:session/sharing` with
`groupId` (32 lowercase hex) and `admissionHash` (SHA-256 of the hex admission
credential). Registration atomically replaces the previous group capability.
DELETE on the same endpoint disables new admission. Both leave all existing
participant tickets and relay grants intact. Links have no independent expiry;
they exist only in the host's in-memory session. Session teardown/restart ends them.

POST `/v3/join` accepts sessionId, groupId, admission, inviteId (a fresh random
32-hex link identifier), clientId (Yjs uint32), and guestPublic (base64 65-byte
uncompressed P-256 ECDH public key). Only the current group capability admits.
Each successful redemption gets its own random session ticket and immutable
link/client/exchange-key binding. Duplicate link or client IDs are rejected.
Guests cannot administer sharing, send on another participant's link, or obtain
another participant's relay grant. Admission is rate limited without imposing
an application-level participant count. The host receives `admitted` with
inviteId, clientId, groupId and guestPublic; replayed socket-ready admissions
retain that same binding.

The app link is `veil://join/` followed by unpadded base64url UTF-8 JSON with
version=4, server, sessionId, groupId, secret (32 random bytes as lowercase hex),
hostClientId and hostPublic (base64 uncompressed P-256 ECDSA public key). The
root secret and host private signing key are never sent to the server. Host
private signing keys are generated per sharing capability and remain in memory.

Group admission uses the existing invitationKeys HKDF with inviteId=groupId.
For each admitted link, bootstrap keys use inviteId=that unique link ID and
secret=the group's root. Bootstrap envelopes use v2 envelope encoding plus
`bootstrap: true`; generation is zero. No SDP or private keys enter bootstrap.
The host sends a signed canonical transcript in this exact property order:
`{version:1,sessionId,groupId,inviteId,hostClientId,guestClientId,guestPublic,hostExchange}`.
Signature is base64 ECDSA P-256/SHA-256 in WebCrypto's raw 64-byte encoding.
The guest reconstructs its locally expected transcript and verifies against the
hostPublic pinned in its invitation. Guests retry bootstrap by sending encrypted
`{kind:"handshake",clientId}`. The host reuses the same transcript/exchange pair.

Peers derive 256 ECDH bits, then HKDF-SHA-256 with salt=UTF-8 JSON transcript,
info=UTF-8 JSON array `["veil.sharing.v1",groupRootSecret]`, producing a fresh
32-byte per-link secret. Feed this into the existing invitationKeys derivation
with the unique link ID to obtain independent host/guest AES-GCM keys. Final
signaling uses the existing v2 authenticated envelope with bootstrap omitted;
its cipher, nonce prefixes, sequence and replay counters are independent of
bootstrap and every other guest. The final signaling and data-channel hello
bind participant IDs and DTLS fingerprints as before. Knowing a shared invite
cannot decrypt another established link or impersonate its pinned host.

Revoking admission does not revoke previously admitted guests' editing access.
Ending the host session disconnects them. Sharing remains a private capability:
anyone given the link can edit. No permission roles or document storage are added.
