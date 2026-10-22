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
| POST /v2/sessions                 | Host Bearer credential (optional with publicHosting); `{clientId}` → sessionId, ticket, stunUrls |
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

## Compatibility before joining

Release-maintained app metadata declares `appVersion`, `serverProtocols` and
`peerProtocols`; current implementations support API generation 2 and peer
generation 1. Server capabilities advertise `compatibility: 1`, `serverVersion`
and `serverProtocols`. Package versions are descriptive; mutually implemented
protocol generations determine whether admission is supported.

After capability discovery, new clients send optional `compatibility` metadata
on session creation and either join endpoint. Older servers receive the existing
request shapes. An admission-credential-protected POST `/v3/compatibility` accepts
`sessionId`, `admission`, `compatibility` and exactly one of `groupId`/`inviteId`.
It previews `hostClientId`, nullable `hostCompatibility`, `serverVersion`,
`serverProtocol` and `peerProtocol` without issuing a ticket or consuming an invite.
Admission rechecks support and link validity under the same server lock.
Unsupported client/server, host/server and peer combinations return HTTP 409 with
`CLIENT_PROTOCOL_UNSUPPORTED`, `HOST_PROTOCOL_UNSUPPORTED` or
`PEER_PROTOCOL_UNSUPPORTED`; these failures cannot be bypassed.

Matching verified host/guest app versions proceed normally. Different supported
versions require **Join anyway** or **Cancel**, warning that some features may not
work properly. Missing server/host metadata requires confirmation that compatibility
could not be verified. Compatibility warnings remain separate from connection
notices. Cancelling before admission creates no ticket; cancelling after host
authentication revokes the provisional guest admission before closing transports.

Reusable-link bootstrap additionally carries `hostCompatibility` and
`compatibilitySignature`. The signature is ECDSA P-256/SHA-256 over UTF-8 JSON
`["veil.compatibility.v1", canonicalHandshake, canonicalHostCompatibility]`.
The metadata property order is `appVersion`, `serverProtocols`, `peerProtocols`;
array order is preserved. The original v1 handshake signature and ECDH transcript
remain unchanged. Guests verify against the host identity pinned in the link before
sending final signaling. Changed signed metadata requires renewed confirmation;
invalid signatures or omitted previously advertised metadata stop admission.
Legacy manual invitations retain their existing authentication limits and cannot
provide a pinned host compatibility signature.

Every networking change must assess server impact and update compatibility support,
protocol documentation and coordinated app/server regression coverage as needed.
Never declare unsupported generations or infer compatibility from equal versions.

## Short invitation extension (shortInvitations=1)

This additive capability retains API generation 2 and peer generation 1. Existing
sharing registrations without a shortInvitation record, legacy admission, and
established signaling keep their prior behavior. Deploy this support before the
coordinated desktop update. Software versions do not establish compatibility.

New app links use `veil://join/<authority>/<code>`: HTTPS authority is a canonical
host plus optional port, percent-encoded as one path segment. IPv6 brackets are
encoded. The code is the canonical unpadded Base64url encoding of 16 random bytes
(22 characters). Test-only HTTP loopback encodes the entire origin in that segment
and is refused by production clients. Extra segments, query, fragment, user info,
unsafe origins and noncanonical codes are rejected. Legacy long links still decode.

HKDF-SHA-256 input is the decoded code; salt is UTF-8 canonical server origin.
Info is `veil.short-invitation.v1:reference`, `:lookup`, or `:encryption`.
Each output has 256 bits. Reference and lookup are lowercase hex; encryption is
an AES-GCM-256 key. The code's entropy remains 128 bits. The code and encryption
key never reach the server. Root invitation secrets remain unchanged.

POST `/v3/sessions/:session/sharing` optionally adds `shortInvitation` containing
reference, lookupHash (SHA-256 of the lookup credential's hex UTF-8), nonce
(unpadded Base64url, 12 bytes), and ciphertext (unpadded Base64url, at most 8192
characters and at least a 16-byte tag). The plaintext is the existing version-4
long app link. AES-GCM uses a fresh nonce and a 128-bit tag; additional data is
UTF-8 JSON array `["veil.short-invitation.v1",serverOrigin,reference]`.
Registration is host-ticket-authenticated and atomically replaces admission and
lookup state; invalid requests do not replace either. References must not collide
with another live session. One encrypted record is retained per active sharing
capability in memory, not in SQLite.

POST `/v3/invitations/resolve` accepts reference and lookup. Verification returns
only nonce and ciphertext. Missing, wrong and revoked credentials receive the
same denial response. Resolution uses a shared 600-attempt/minute limiter rather
than allocating limiter state for attacker-selected references. It does not
refresh session lifetime or admit a guest. Stop, reset, expiry, host revocation,
end and server restart invalidate lookup. Successful resolution is not admission.
Clients decrypt locally and validate the embedded invitation and matching origin.

For a short-record group, POST `/v3/join` requires `approvalProtocol: 1`. The guest
gets a pending ticket with a 120-second deadline. Only generation-zero bootstrap
envelopes are forwarded while pending; relay and established signaling are denied.
There are at most 128 pending requests per session, not a connected-participant cap.
POST `/v3/admission/decision` takes sessionId, inviteId and approve, authenticated
by the host session ticket. Approval clears the deadline; rejection deletes the
ticket/socket. Rejection may include a host-role generation-zero bootstrap envelope
in `rejection`; the server queues it before the terminal `admission-ended` event
and closes only that guest. Late host messages for removed admissions are ignored.
Approval is idempotent for an existing admitted guest. Reset/Stop
remove pending tickets but preserve approved tickets, transports and relay grants.
Client Auto join sends approval after the guest's encrypted handshake request;
Require approval waits for a local host decision. Server state alone never causes
the client to sign a host handshake or start document transport.

Guests send their requested name inside the encrypted bootstrap handshake request.
Names are limited to 80 characters by clients and are not verified identities.
The host snapshots its local join mode per admission. Changing mode retains the
link and does not automatically approve existing waiting requests.

A waiting/rejected bootstrap payload contains status and signature. Status is
canonical JSON in this property order:
`{version:1,sessionId,groupId,inviteId,hostClientId,guestClientId,guestPublic,state,deadline}`.
State is waiting or rejected; deadline is Unix milliseconds. Signature is raw
64-byte ECDSA P-256/SHA-256, standard Base64, over UTF-8 JSON array
`["veil.admission-status.v1",status]`. Guests reconstruct expected identity and
exchange fields locally and verify the signature against the invitation's pinned
host key. Status does not release document access. Approval uses the existing
signed handshake and per-link key derivation; no peer generation is removed.

## Public hosting extension (publicHosting=1)

Operators may enable a credential-less hosting tier (`PUBLIC_HOSTING=on`). The
capabilities response then also contains `publicHosting: 1` and
`publicLimits: {maxGuests, sessionsPerClient}`. Without it, hosting requires an
issued credential exactly as before.

POST `/v2/sessions` without an `Authorization` header creates a public session.
A present but invalid credential is still rejected with 401; it is never
downgraded to the public tier. Public sessions otherwise use the same tickets,
invitations, sharing, admission and socket protocol as credentialed sessions.

Public limits are keyed by the client network: the IPv4 address or the IPv6 /64.
Behind a reverse proxy the server reads the address from `CLIENT_IP_HEADER`, only
when the TCP peer is loopback or a private address; otherwise it uses the peer.

| Error (status)               | Meaning                                                              |
| ---------------------------- | -------------------------------------------------------------------- |
| `PUBLIC_LIMIT_REACHED` (429) | This client reached its public session, creation or relay allowance |
| `PUBLIC_CAPACITY_FULL` (503) | The public tier has no free sessions, sockets or relay grants        |
| `PUBLIC_GUEST_LIMIT` (429)   | The public session already has `maxGuests` admitted/pending guests   |
| `CAPACITY_FULL` (503)        | The server-wide socket ceiling (`MAX_SOCKETS`) is reached            |

Session creation reports `PUBLIC_CAPACITY_FULL` or `CAPACITY_FULL` before a
session is shared, so clients can suggest another server. WebSocket upgrades past
the ceiling receive 503 `CAPACITY_FULL`; reconnecting an already connected ticket
replaces its socket and never needs headroom. Joins are refused once the guest's
socket cannot fit. Public relay grants come from a separate pool inside the
32-grant total, so credentialed hosts always keep relay headroom.

Metrics add `publicSessions`, `sockets`, `publicSockets` and `publicRelayGrants`.
