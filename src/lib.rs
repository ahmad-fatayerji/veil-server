mod compatibility;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, State,
    },
    http::{request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use compatibility::{check_client, check_pair, ClientCompatibility};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn random() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
pub fn hash(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}
pub fn credential_db(path: &str) -> rusqlite::Result<Connection> {
    let db = Connection::open(path)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS hosts (hash TEXT PRIMARY KEY, name TEXT NOT NULL);",
    )?;
    Ok(db)
}
pub fn issue(db: &Connection, name: &str) -> rusqlite::Result<String> {
    let token = random();
    db.execute(
        "INSERT INTO hosts VALUES (?1, ?2)",
        params![hash(&token), name],
    )?;
    Ok(token)
}

#[derive(Clone)]
pub struct Config {
    pub stun_urls: Vec<String>,
    pub turn_urls: Vec<String>,
    pub turn_secret: String,
    pub metrics_secret: String,
    pub max_sessions: usize,
    pub max_relay_grants: usize,
    /// Server-wide live WebSocket ceiling; protects the reverse proxy's workers.
    pub max_sockets: usize,
    /// Request header carrying the client IP; honoured only from loopback/private proxies.
    pub client_ip_header: Option<String>,
    /// Credential-less hosting tier. `None` keeps hosting operator-issued only.
    pub public: Option<PublicLimits>,
}
#[derive(Clone)]
pub struct PublicLimits {
    pub max_sessions: usize,
    pub sessions_per_ip: usize,
    pub max_guests: usize,
    pub max_sockets: usize,
    pub relay_grants: usize,
    pub relay_grants_per_ip: usize,
}
impl Default for PublicLimits {
    fn default() -> Self {
        Self {
            max_sessions: 12,
            sessions_per_ip: 3,
            max_guests: 5,
            max_sockets: 40,
            relay_grants: 8,
            relay_grants_per_ip: 2,
        }
    }
}
// Both tiers share coturn's total-quota; public grants are a bounded subset of it.
const MAX_GRANTS: usize = 32;
fn number(key: &str, default: usize) -> std::result::Result<usize, String> {
    match std::env::var(key) {
        Ok(value) => value.trim().parse().map_err(|_| format!("Invalid {key}")),
        Err(_) => Ok(default),
    }
}
impl Config {
    pub fn from_env() -> std::result::Result<Self, String> {
        let turn_secret = std::fs::read_to_string(
            std::env::var("TURN_SECRET_FILE").map_err(|_| "TURN_SECRET_FILE is required")?,
        )
        .map_err(|_| "Cannot read TURN secret")?
        .trim()
        .to_string();
        if turn_secret.len() < 32 {
            return Err("TURN secret must contain at least 32 characters".into());
        }
        let urls = |key: &str| -> std::result::Result<Vec<String>, String> {
            let list: Vec<String> = std::env::var(key)
                .map_err(|_| format!("{key} is required"))?
                .split(',')
                .map(str::trim)
                .map(str::to_string)
                .filter(|s| !s.is_empty())
                .collect();
            if list.is_empty() {
                return Err(format!("{key} is empty"));
            }
            Ok(list)
        };
        let public = match std::env::var("PUBLIC_HOSTING")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "off" | "false" | "0" => None,
            "on" | "true" | "1" => {
                let d = PublicLimits::default();
                Some(PublicLimits {
                    max_sessions: number("PUBLIC_MAX_SESSIONS", d.max_sessions)?,
                    sessions_per_ip: number("PUBLIC_SESSIONS_PER_IP", d.sessions_per_ip)?,
                    max_guests: number("PUBLIC_MAX_GUESTS", d.max_guests)?,
                    max_sockets: number("PUBLIC_MAX_SOCKETS", d.max_sockets)?,
                    relay_grants: number("PUBLIC_RELAY_GRANTS", d.relay_grants)?,
                    relay_grants_per_ip: number(
                        "PUBLIC_RELAY_GRANTS_PER_IP",
                        d.relay_grants_per_ip,
                    )?,
                })
            }
            _ => return Err("PUBLIC_HOSTING must be on or off".into()),
        };
        let max_sockets = number("MAX_SOCKETS", 60)?;
        if let Some(p) = &public {
            if p.max_sockets > max_sockets || p.relay_grants > MAX_GRANTS {
                return Err(
                    "PUBLIC_MAX_SOCKETS and PUBLIC_RELAY_GRANTS must fit the server-wide caps"
                        .into(),
                );
            }
        }
        let client_ip_header = std::env::var("CLIENT_IP_HEADER")
            .ok()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty());
        if client_ip_header
            .as_deref()
            .is_some_and(|h| axum::http::HeaderName::from_bytes(h.as_bytes()).is_err())
        {
            return Err("Invalid CLIENT_IP_HEADER".into());
        }
        Ok(Self {
            stun_urls: urls("STUN_URLS")?,
            turn_urls: urls("TURN_URLS")?,
            turn_secret,
            metrics_secret: std::fs::read_to_string(
                std::env::var("METRICS_SECRET_FILE")
                    .map_err(|_| "METRICS_SECRET_FILE is required")?,
            )
            .map_err(|_| "Cannot read metrics secret")?
            .trim()
            .to_string(),
            max_sessions: 1024,
            max_relay_grants: number("MAX_RELAY_GRANTS", 16)?,
            max_sockets,
            client_ip_header,
            public,
        })
    }
}

struct Invite {
    admission_hash: String,
    expires: u64,
    client_id: Option<u32>,
    guest_ticket: Option<String>,
    group: Option<GroupGuest>,
    pending_until: Option<u64>,
}
struct Sharing {
    group_id: String,
    admission_hash: String,
    short_invitation: Option<ShortInvitation>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ShortInvitation {
    reference: String,
    lookup_hash: String,
    nonce: String,
    ciphertext: String,
}
fn url_bytes(value: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    (URL_SAFE_NO_PAD.encode(&bytes) == value).then_some(bytes)
}
fn valid_short(record: &ShortInvitation) -> bool {
    secret(&record.reference)
        && secret(&record.lookup_hash)
        && record.nonce.len() == 16
        && url_bytes(&record.nonce).is_some_and(|b| b.len() == 12)
        && record.ciphertext.len() <= 8192
        && url_bytes(&record.ciphertext).is_some_and(|b| b.len() >= 16)
}
fn remove_guest(room: &mut Room, invite_id: &str) {
    if let Some(invite) = room.invites.remove(invite_id) {
        if let Some(ticket) = invite.guest_ticket {
            if let Some(socket) = room.sockets.get(&ticket) {
                // Keep the stop sender alive until the FIFO terminal event is delivered.
                let _ = socket.try_send(json!({"kind":"admission-ended"}));
            }
        }
    }
    room.paths.remove(invite_id);
    if let Some(host) = room.sockets.get(&room.host_ticket) {
        let _ = host.try_send(json!({"kind":"left","inviteId":invite_id}));
    }
}
fn cancel_pending(room: &mut Room) {
    let pending: Vec<_> = room
        .invites
        .iter()
        .filter(|(_, i)| i.pending_until.is_some())
        .map(|(id, _)| id.clone())
        .collect();
    for id in pending {
        remove_guest(room, &id);
    }
}
struct GroupGuest {
    group_id: String,
    guest_public: String,
}
struct Room {
    owner: String,
    /// Client network key of a credential-less host; `None` for issued credentials.
    public: Option<String>,
    host_ticket: String,
    host_client_id: u32,
    host_compatibility: Option<ClientCompatibility>,
    touched: u64,
    invites: HashMap<String, Invite>,
    sharing: Option<Sharing>,
    sockets: HashMap<String, SocketSender>,
    paths: HashMap<String, String>,
}
struct SocketSender {
    tx: mpsc::Sender<Value>,
    stop: watch::Sender<bool>,
}
impl SocketSender {
    fn try_send(&self, value: Value) -> std::result::Result<(), mpsc::error::TrySendError<Value>> {
        let result = self.tx.try_send(value);
        if result.is_err() {
            let _ = self.stop.send(true);
        }
        result
    }
    fn same_channel(&self, other: &mpsc::Sender<Value>) -> bool {
        self.tx.same_channel(other)
    }
}
struct Grant {
    owner: String,
    until: u64,
    credentials_until: u64,
    username: String,
    credential: String,
}
#[derive(Default)]
struct Data {
    rooms: HashMap<String, Room>,
    limits: HashMap<String, VecDeque<u64>>,
    grants: HashMap<String, Grant>,
    issued: u64,
    rejected: u64,
    forwarded: u64,
}
#[derive(Clone)]
pub struct App {
    db: Arc<Mutex<Connection>>,
    data: Arc<Mutex<Data>>,
    config: Config,
}
type Result<T> = std::result::Result<T, ApiError>;
#[derive(Debug)]
pub struct ApiError(StatusCode, &'static str);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
fn bad() -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, "INVALID_REQUEST")
}
fn denied() -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, "UNAUTHORIZED")
}
fn full() -> ApiError {
    ApiError(StatusCode::TOO_MANY_REQUESTS, "CAPACITY_UNAVAILABLE")
}
// One public client used its own share; clients can retry later or self-host.
fn public_limit() -> ApiError {
    ApiError(StatusCode::TOO_MANY_REQUESTS, "PUBLIC_LIMIT_REACHED")
}
fn public_full() -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, "PUBLIC_CAPACITY_FULL")
}
fn sockets_full() -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, "CAPACITY_FULL")
}
fn guest_limit() -> ApiError {
    ApiError(StatusCode::TOO_MANY_REQUESTS, "PUBLIC_GUEST_LIMIT")
}
/// TCP peer of the request, when the server runs with connect info.
pub struct Peer(Option<SocketAddr>);
impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        Ok(Peer(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0),
        ))
    }
}
// Only a same-host or private-network reverse proxy may name the client; internet
// peers that reach the listener directly cannot choose their own limit key.
fn proxy_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_private())
        }
    }
}
// IPv6 clients usually control a whole /64, so it counts as one client.
fn network_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}
fn room_sockets(d: &Data, public: bool) -> usize {
    d.rooms
        .values()
        .filter(|r| !public || r.public.is_some())
        .map(|r| r.sockets.len())
        .sum()
}
fn id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn secret(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn bearer(h: &HeaderMap) -> Result<String> {
    h.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| secret(s))
        .map(str::to_string)
        .ok_or_else(denied)
}
fn rate(data: &mut Data, key: String, count: usize, seconds: u64) -> Result<()> {
    if data.limits.len() > 16384 && !data.limits.contains_key(&key) {
        return Err(full());
    }
    let list = data.limits.entry(key).or_default();
    let t = now();
    while list.front().is_some_and(|v| *v + seconds <= t) {
        list.pop_front();
    }
    if list.len() >= count {
        data.rejected += 1;
        return Err(full());
    }
    list.push_back(t);
    Ok(())
}
impl App {
    pub fn new(db: Connection, config: Config) -> Self {
        Self {
            db: Arc::new(Mutex::new(db)),
            data: Arc::new(Mutex::new(Data::default())),
            config,
        }
    }
    fn owner_valid(&self, owner: &str) -> bool {
        self.db
            .lock()
            .unwrap()
            .query_row("SELECT 1 FROM hosts WHERE hash=?1", [owner], |_| Ok(()))
            .is_ok()
    }
    // Public rooms have no credential to revoke; operators stop them by disabling the tier.
    fn room_valid(&self, room: &Room) -> bool {
        room.public.is_some() || self.owner_valid(&room.owner)
    }
    fn client_key(&self, h: &HeaderMap, peer: Option<SocketAddr>) -> String {
        let peer = peer.map(|p| p.ip());
        let forwarded = self
            .config
            .client_ip_header
            .as_deref()
            .filter(|_| peer.is_some_and(proxy_peer))
            .and_then(|name| h.get(name))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<IpAddr>().ok());
        forwarded
            .or(peer)
            .map(network_key)
            .unwrap_or_else(|| "unknown".into())
    }
    fn host_owner(&self, h: &HeaderMap) -> Result<String> {
        let owner = hash(&bearer(h)?);
        if self.owner_valid(&owner) {
            Ok(owner)
        } else {
            Err(denied())
        }
    }
    fn authorize(&self, room: &Room, ticket: &str) -> Result<Option<String>> {
        if !self.room_valid(room) {
            return Err(denied());
        }
        if room.host_ticket == ticket {
            return Ok(None);
        }
        room.invites
            .iter()
            .find(|(_, i)| {
                i.guest_ticket.as_deref() == Some(ticket)
                    && i.pending_until.is_none_or(|until| until > now())
            })
            .map(|(id, _)| Some(id.clone()))
            .ok_or_else(denied)
    }
    pub fn sweep(&self) {
        let mut d = self.data.lock().unwrap();
        let t = now();
        d.rooms.retain(|_, r| {
            let keep = r.touched + 600 > t && self.room_valid(r);
            if !keep {
                for tx in r.sockets.values() {
                    let _ = tx.try_send(json!({"kind":"ended"}));
                }
            }
            let expired: Vec<_> = r
                .invites
                .iter()
                .filter(|(_, i)| i.pending_until.is_some_and(|until| until <= t))
                .map(|(id, _)| id.clone())
                .collect();
            for id in expired {
                remove_guest(r, &id);
            }
            r.invites
                .retain(|_, i| i.guest_ticket.is_some() || i.expires > t);
            keep
        });
        d.grants.retain(|_, g| g.until > t);
        d.limits
            .retain(|_, times| times.back().is_some_and(|v| *v + 600 > t));
    }
}
pub fn router(app: App) -> Router {
    Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"status":"ok","protocol":2})) }),
        )
        .route("/v2/capabilities", get(capabilities))
        .route("/v2/sessions", post(create))
        .route("/v2/sessions/{session}", delete(end))
        .route("/v2/sessions/{session}/invitations", post(invite))
        .route("/v2/join", post(join))
        .route(
            "/v3/sessions/{session}/sharing",
            post(share).delete(stop_sharing),
        )
        .route("/v3/join", post(group_join))
        .route("/v3/invitations/resolve", post(resolve_invitation))
        .route("/v3/admission/decision", post(admission_decision))
        .route("/v3/compatibility", post(preflight))
        .route("/v2/relay", post(relay))
        .route("/v2/path", post(path_report))
        .route("/v2/leave", post(leave))
        .route("/v2/socket/{session}", get(socket))
        .route("/v2/metrics", get(metrics))
        .layer(DefaultBodyLimit::max(128 * 1024))
        .with_state(app)
}
async fn capabilities(State(a): State<App>) -> Json<Value> {
    let mut value = json!({"protocol":2,"groupSharing":1,"shortInvitations":1,"compatibility":1,"serverVersion":env!("CARGO_PKG_VERSION"),"serverProtocols":compatibility::SERVER_PROTOCOLS,"stunUrls":a.config.stun_urls,"directTimeoutMs":6000,"relayTimeoutMs":20000});
    if let Some(p) = &a.config.public {
        value["publicHosting"] = json!(1);
        value["publicLimits"] =
            json!({"maxGuests":p.max_guests,"sessionsPerClient":p.sessions_per_ip});
    }
    Json(value)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Create {
    client_id: u32,
    compatibility: Option<ClientCompatibility>,
}
async fn create(
    State(a): State<App>,
    Peer(peer): Peer,
    h: HeaderMap,
    Json(b): Json<Create>,
) -> Result<Json<Value>> {
    // A present but wrong credential is rejected, never silently downgraded to public.
    let public = match &a.config.public {
        Some(p) if !h.contains_key("authorization") => Some((p, a.client_key(&h, peer))),
        _ => None,
    };
    let owner = match &public {
        Some((_, client)) => format!("public:{client}"),
        None => a.host_owner(&h)?,
    };
    check_client(b.compatibility.as_ref())?;
    a.sweep();
    let mut d = a.data.lock().unwrap();
    if d.rooms.len() >= a.config.max_sessions {
        return Err(full());
    }
    if let Some((p, client)) = &public {
        rate(&mut d, format!("create:{owner}"), 6, 60).map_err(|_| public_limit())?;
        let mine = d
            .rooms
            .values()
            .filter(|r| r.public.as_ref() == Some(client))
            .count();
        if mine >= p.sessions_per_ip {
            return Err(public_limit());
        }
        // Each host needs at least its own socket; refuse before the user shares.
        if d.rooms.values().filter(|r| r.public.is_some()).count() >= p.max_sessions
            || room_sockets(&d, true) >= p.max_sockets
            || room_sockets(&d, false) >= a.config.max_sockets
        {
            return Err(public_full());
        }
    } else {
        rate(&mut d, format!("create:{owner}"), 10, 60)?;
        if room_sockets(&d, false) >= a.config.max_sockets {
            return Err(sockets_full());
        }
    }
    let session = Uuid::new_v4().simple().to_string();
    let ticket = random();
    d.rooms.insert(
        session.clone(),
        Room {
            owner,
            public: public.map(|(_, client)| client),
            host_ticket: ticket.clone(),
            host_client_id: b.client_id,
            host_compatibility: b.compatibility,
            touched: now(),
            invites: HashMap::new(),
            sharing: None,
            sockets: HashMap::new(),
            paths: HashMap::new(),
        },
    );
    Ok(Json(
        json!({"sessionId":session,"ticket":ticket,"stunUrls":a.config.stun_urls}),
    ))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Invitation {
    invite_id: String,
    admission_hash: String,
    expires_at: u64,
}
async fn invite(
    State(a): State<App>,
    Path(session): Path<String>,
    h: HeaderMap,
    Json(b): Json<Invitation>,
) -> Result<Json<Value>> {
    if !id(&b.invite_id)
        || !secret(&b.admission_hash)
        || b.expires_at <= now() * 1000
        || b.expires_at > (now() + 600) * 1000 + 1000
    {
        return Err(bad());
    }
    let ticket = bearer(&h)?;
    let mut d = a.data.lock().unwrap();
    rate(&mut d, format!("invite:{session}"), 60, 60)?;
    let r = d.rooms.get_mut(&session).ok_or_else(denied)?;
    if a.authorize(r, &ticket)?.is_some() {
        return Err(denied());
    }
    if r.invites.contains_key(&b.invite_id) {
        return Err(ApiError(StatusCode::CONFLICT, "INVITATION_EXISTS"));
    }
    if r.invites
        .values()
        .filter(|i| i.guest_ticket.is_none() && i.expires > now())
        .count()
        >= 64
    {
        return Err(full());
    }
    r.invites.insert(
        b.invite_id,
        Invite {
            admission_hash: b.admission_hash,
            expires: b.expires_at / 1000,
            client_id: None,
            guest_ticket: None,
            group: None,
            pending_until: None,
        },
    );
    r.touched = now();
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Join {
    session_id: String,
    invite_id: String,
    admission: String,
    client_id: u32,
    compatibility: Option<ClientCompatibility>,
}
// Every admitted guest opens a socket, so admission is refused once that socket cannot fit.
fn guest_headroom(c: &Config, d: &Data, session: &str) -> Result<()> {
    let Some(r) = d.rooms.get(session) else {
        return Ok(());
    };
    if room_sockets(d, false) >= c.max_sockets {
        return Err(sockets_full());
    }
    if let (Some(_), Some(p)) = (&r.public, &c.public) {
        if room_sockets(d, true) >= p.max_sockets {
            return Err(sockets_full());
        }
        if r.invites
            .values()
            .filter(|i| i.guest_ticket.is_some())
            .count()
            >= p.max_guests
        {
            return Err(guest_limit());
        }
    }
    Ok(())
}
async fn join(State(a): State<App>, Json(b): Json<Join>) -> Result<Json<Value>> {
    if !id(&b.session_id) || !id(&b.invite_id) || !secret(&b.admission) {
        return Err(bad());
    }
    let mut d = a.data.lock().unwrap();
    rate(&mut d, format!("join:{}", b.session_id), 30, 60)?;
    let headroom = guest_headroom(&a.config, &d, &b.session_id);
    let r = d.rooms.get_mut(&b.session_id).ok_or_else(denied)?;
    if !a.room_valid(r) {
        return Err(denied());
    }
    let i = r.invites.get(&b.invite_id).ok_or_else(denied)?;
    if i.expires <= now() || i.admission_hash != hash(&b.admission) || i.guest_ticket.is_some() {
        return Err(denied());
    }
    check_pair(r.host_compatibility.as_ref(), b.compatibility.as_ref())?;
    headroom?;
    if b.client_id == r.host_client_id
        || r.invites.values().any(|i| i.client_id == Some(b.client_id))
    {
        return Err(bad());
    }
    let i = r.invites.get_mut(&b.invite_id).ok_or_else(denied)?;
    let ticket = random();
    i.guest_ticket = Some(ticket.clone());
    i.client_id = Some(b.client_id);
    r.touched = now();
    if let Some(tx) = r.sockets.get(&r.host_ticket) {
        let _ =
            tx.try_send(json!({"kind":"admitted","inviteId":b.invite_id,"clientId":b.client_id}));
    }
    Ok(Json(
        json!({"ticket":ticket,"hostClientId":r.host_client_id,"stunUrls":a.config.stun_urls,"hostCompatibility":r.host_compatibility}),
    ))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Preflight {
    session_id: String,
    invite_id: Option<String>,
    group_id: Option<String>,
    admission: String,
    compatibility: Option<ClientCompatibility>,
}
async fn preflight(State(a): State<App>, Json(b): Json<Preflight>) -> Result<Json<Value>> {
    if !id(&b.session_id) || !secret(&b.admission) {
        return Err(bad());
    }
    let mut d = a.data.lock().unwrap();
    rate(&mut d, format!("compatibility:{}", b.session_id), 120, 60)?;
    let r = d.rooms.get(&b.session_id).ok_or_else(denied)?;
    if !a.room_valid(r) {
        return Err(denied());
    }
    match (&b.group_id, &b.invite_id) {
        (Some(group), None) if id(group) => {
            let sharing = r.sharing.as_ref().ok_or_else(denied)?;
            if sharing.group_id != *group || sharing.admission_hash != hash(&b.admission) {
                return Err(denied());
            }
        }
        (None, Some(invite)) if id(invite) => {
            let i = r.invites.get(invite).ok_or_else(denied)?;
            if i.expires <= now()
                || i.guest_ticket.is_some()
                || i.admission_hash != hash(&b.admission)
            {
                return Err(denied());
            }
        }
        _ => return Err(bad()),
    }
    let (server_protocol, peer_protocol) =
        check_pair(r.host_compatibility.as_ref(), b.compatibility.as_ref())?;
    Ok(Json(
        json!({"hostClientId":r.host_client_id,"hostCompatibility":r.host_compatibility,
        "serverVersion":env!("CARGO_PKG_VERSION"),"serverProtocol":server_protocol,"peerProtocol":peer_protocol}),
    ))
}
// The reusable capability is separate from each admitted participant. Revoking
// it never removes participant tickets, relay grants, or healthy transports.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Share {
    group_id: String,
    admission_hash: String,
    short_invitation: Option<ShortInvitation>,
}
async fn share(
    State(a): State<App>,
    Path(session): Path<String>,
    h: HeaderMap,
    Json(b): Json<Share>,
) -> Result<Json<Value>> {
    if !id(&b.group_id)
        || !secret(&b.admission_hash)
        || b.short_invitation
            .as_ref()
            .is_some_and(|record| !valid_short(record))
    {
        return Err(bad());
    }
    let ticket = bearer(&h)?;
    let mut d = a.data.lock().unwrap();
    rate(&mut d, format!("sharing:{ticket}"), 60, 60)?;
    if let Some(record) = &b.short_invitation {
        if d.rooms.iter().any(|(id, r)| {
            id != &session
                && r.sharing
                    .as_ref()
                    .and_then(|s| s.short_invitation.as_ref())
                    .is_some_and(|other| other.reference == record.reference)
        }) {
            return Err(bad());
        }
    }
    let r = d.rooms.get_mut(&session).ok_or_else(denied)?;
    if a.authorize(r, &ticket)?.is_some() {
        return Err(denied());
    }
    cancel_pending(r);
    r.sharing = Some(Sharing {
        group_id: b.group_id,
        admission_hash: b.admission_hash,
        short_invitation: b.short_invitation,
    });
    r.touched = now();
    Ok(Json(json!({"ok":true})))
}
async fn stop_sharing(
    State(a): State<App>,
    Path(session): Path<String>,
    h: HeaderMap,
) -> Result<Json<Value>> {
    let ticket = bearer(&h)?;
    let mut d = a.data.lock().unwrap();
    let r = d.rooms.get_mut(&session).ok_or_else(denied)?;
    if a.authorize(r, &ticket)?.is_some() {
        return Err(denied());
    }
    cancel_pending(r);
    r.sharing = None;
    r.touched = now();
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResolveInvitation {
    reference: String,
    lookup: String,
}
async fn resolve_invitation(
    State(a): State<App>,
    Json(b): Json<ResolveInvitation>,
) -> Result<Json<Value>> {
    if !secret(&b.reference) || !secret(&b.lookup) {
        return Err(denied());
    }
    a.sweep();
    let mut d = a.data.lock().unwrap();
    rate(&mut d, "short-resolve".into(), 600, 60)?;
    let record = d
        .rooms
        .values()
        .filter_map(|r| r.sharing.as_ref())
        .filter_map(|s| s.short_invitation.as_ref())
        .find(|record| record.reference == b.reference && record.lookup_hash == hash(&b.lookup))
        .ok_or_else(denied)?;
    Ok(Json(
        json!({"nonce":record.nonce,"ciphertext":record.ciphertext}),
    ))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionDecision {
    session_id: String,
    invite_id: String,
    approve: bool,
    rejection: Option<Envelope>,
}
async fn admission_decision(
    State(a): State<App>,
    h: HeaderMap,
    Json(b): Json<AdmissionDecision>,
) -> Result<Json<Value>> {
    if !id(&b.session_id) || !id(&b.invite_id) {
        return Err(bad());
    }
    let ticket = bearer(&h)?;
    let mut d = a.data.lock().unwrap();
    let r = d.rooms.get_mut(&b.session_id).ok_or_else(denied)?;
    if a.authorize(r, &ticket)?.is_some() {
        return Err(denied());
    }
    let invite = r.invites.get_mut(&b.invite_id).ok_or_else(denied)?;
    if b.approve {
        if invite
            .pending_until
            .is_some_and(|deadline| deadline <= now())
        {
            remove_guest(r, &b.invite_id);
            return Err(denied());
        }
        invite.pending_until = None;
    } else {
        if let Some(envelope) = b.rejection {
            if envelope.invite_id != b.invite_id
                || envelope.role != "host"
                || !envelope.bootstrap
                || envelope.generation != 0
                || envelope.nonce.len() != 16
                || envelope.ciphertext.len() > 96 * 1024
                || envelope.sequence > 9007199254740991
            {
                return Err(bad());
            }
            if let Some(socket) = invite
                .guest_ticket
                .as_ref()
                .and_then(|ticket| r.sockets.get(ticket))
            {
                let _ = socket.try_send(json!({"kind":"signal","envelope":envelope}));
            }
        }
        remove_guest(r, &b.invite_id);
    }
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GroupJoin {
    session_id: String,
    group_id: String,
    admission: String,
    invite_id: String,
    client_id: u32,
    guest_public: String,
    approval_protocol: Option<u32>,
    compatibility: Option<ClientCompatibility>,
}
fn public_key(s: &str) -> bool {
    STANDARD
        .decode(s)
        .is_ok_and(|bytes| bytes.len() == 65 && bytes[0] == 4)
}
fn admitted(id: &str, client: u32, invite: &Invite) -> Value {
    let mut event = json!({"kind":"admitted","inviteId":id,"clientId":client});
    if let Some(group) = &invite.group {
        event["groupId"] = json!(group.group_id);
        event["guestPublic"] = json!(group.guest_public);
    }
    event
}
async fn group_join(State(a): State<App>, Json(b): Json<GroupJoin>) -> Result<Json<Value>> {
    a.sweep();
    if !id(&b.session_id)
        || !id(&b.group_id)
        || !id(&b.invite_id)
        || !secret(&b.admission)
        || !public_key(&b.guest_public)
    {
        return Err(bad());
    }
    let mut d = a.data.lock().unwrap();
    rate(&mut d, format!("group-join:{}", b.session_id), 120, 60)?;
    let headroom = guest_headroom(&a.config, &d, &b.session_id);
    let r = d.rooms.get_mut(&b.session_id).ok_or_else(denied)?;
    if !a.room_valid(r) {
        return Err(denied());
    }
    let sharing = r.sharing.as_ref().ok_or_else(denied)?;
    if sharing.group_id != b.group_id
        || sharing.admission_hash != hash(&b.admission)
        || (sharing.short_invitation.is_some() && b.approval_protocol != Some(1))
    {
        return Err(denied());
    }
    check_pair(r.host_compatibility.as_ref(), b.compatibility.as_ref())?;
    headroom?;
    if b.client_id == r.host_client_id
        || r.invites.contains_key(&b.invite_id)
        || r.invites.values().any(|i| i.client_id == Some(b.client_id))
    {
        return Err(bad());
    }
    let pending = sharing.short_invitation.is_some();
    if pending
        && r.invites
            .values()
            .filter(|i| i.pending_until.is_some())
            .count()
            >= 128
    {
        return Err(full());
    }
    let ticket = random();
    let invite = Invite {
        pending_until: pending.then(|| now() + 120),
        admission_hash: String::new(),
        expires: 0,
        client_id: Some(b.client_id),
        guest_ticket: Some(ticket.clone()),
        group: Some(GroupGuest {
            group_id: b.group_id,
            guest_public: b.guest_public,
        }),
    };
    if let Some(tx) = r.sockets.get(&r.host_ticket) {
        let _ = tx.try_send(admitted(&b.invite_id, b.client_id, &invite));
    }
    r.invites.insert(b.invite_id, invite);
    r.touched = now();
    Ok(Json(
        json!({"ticket":ticket,"hostClientId":r.host_client_id,"stunUrls":a.config.stun_urls,"hostCompatibility":r.host_compatibility}),
    ))
}
async fn end(
    State(a): State<App>,
    Path(session): Path<String>,
    h: HeaderMap,
) -> Result<Json<Value>> {
    let ticket = bearer(&h)?;
    let mut d = a.data.lock().unwrap();
    let r = d.rooms.get(&session).ok_or_else(denied)?;
    if a.authorize(r, &ticket)?.is_some() {
        return Err(denied());
    }
    let r = d.rooms.remove(&session).unwrap();
    for tx in r.sockets.values() {
        let _ = tx.try_send(json!({"kind":"ended"}));
    }
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Relay {
    session_id: String,
    invite_id: String,
}
async fn leave(State(a): State<App>, h: HeaderMap, Json(b): Json<Relay>) -> Result<Json<Value>> {
    let ticket = bearer(&h)?;
    let mut d = a.data.lock().unwrap();
    let r = d.rooms.get_mut(&b.session_id).ok_or_else(denied)?;
    if a.authorize(r, &ticket)?.as_deref() != Some(b.invite_id.as_str()) {
        return Err(denied());
    }
    r.invites.remove(&b.invite_id);
    r.paths.remove(&b.invite_id);
    if let Some(socket) = r.sockets.remove(&ticket) {
        let _ = socket.stop.send(true);
    }
    if let Some(host) = r.sockets.get(&r.host_ticket) {
        let _ = host.try_send(json!({"kind":"left","inviteId":b.invite_id}));
    }
    Ok(Json(json!({"ok":true})))
}
async fn relay(State(a): State<App>, h: HeaderMap, Json(b): Json<Relay>) -> Result<Json<Value>> {
    let ticket = bearer(&h)?;
    let mut d = a.data.lock().unwrap();
    let r = d.rooms.get(&b.session_id).ok_or_else(denied)?;
    let guest = a.authorize(r, &ticket)?;
    if guest.as_ref().is_some_and(|g| g != &b.invite_id)
        || !r
            .invites
            .get(&b.invite_id)
            .is_some_and(|i| i.guest_ticket.is_some() && i.pending_until.is_none())
    {
        return Err(denied());
    }
    let owner = r.owner.clone();
    let public = r.public.is_some();
    let key = format!(
        "{}:{}:{}",
        b.session_id,
        b.invite_id,
        if guest.is_some() { "guest" } else { "host" }
    );
    // A grant has one stable logical identity. Returning cached credentials prevents
    // repeated requests from creating more coturn usernames/allocations.
    if let Some(g) = d.grants.get(&key) {
        if g.credentials_until > now() + 120 {
            return Ok(Json(relay_value(&a.config, g)));
        }
    }
    rate(&mut d, format!("relay:{key}"), 1, 120)?;
    rate(&mut d, format!("relay-owner:{owner}"), 32, 600)?;
    d.grants.retain(|_, g| g.until > now());
    if !d.grants.contains_key(&key) {
        let owned = d.grants.values().filter(|g| g.owner == owner).count();
        match (&a.config.public, public) {
            (Some(p), true) => {
                if owned >= p.relay_grants_per_ip {
                    return Err(public_limit());
                }
                // The public pool is capped below MAX_GRANTS, so trusted hosts keep headroom.
                let pooled = d
                    .grants
                    .values()
                    .filter(|g| g.owner.starts_with("public:"))
                    .count();
                if pooled >= p.relay_grants || d.grants.len() >= MAX_GRANTS {
                    return Err(public_full());
                }
            }
            (None, true) => return Err(denied()),
            (_, false) => {
                if d.grants.len() >= MAX_GRANTS || owned >= a.config.max_relay_grants {
                    return Err(full());
                }
            }
        }
    }
    let expiry = now() + 600;
    let username = format!("{expiry}:{}", hash(&key));
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(a.config.turn_secret.as_bytes()).unwrap();
    mac.update(username.as_bytes());
    let g = Grant {
        owner,
        until: expiry + 600,
        credentials_until: expiry,
        username,
        credential: STANDARD.encode(mac.finalize().into_bytes()),
    };
    let value = relay_value(&a.config, &g);
    d.grants.insert(key, g);
    d.issued += 1;
    Ok(Json(value))
}
fn relay_value(c: &Config, g: &Grant) -> Value {
    json!({"urls":c.turn_urls,"username":g.username,"credential":g.credential,"expiresAt":g.credentials_until*1000})
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PathReport {
    session_id: String,
    invite_id: String,
    path: String,
}
async fn path_report(
    State(a): State<App>,
    h: HeaderMap,
    Json(b): Json<PathReport>,
) -> Result<Json<Value>> {
    if !["direct", "relay", "checking"].contains(&b.path.as_str()) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "Invalid selected path"));
    }
    let ticket = bearer(&h)?;
    let mut d = a.data.lock().unwrap();
    rate(&mut d, format!("path:{ticket}"), 60, 60)?;
    let r = d.rooms.get_mut(&b.session_id).ok_or_else(denied)?;
    if a.authorize(r, &ticket)?.is_some()
        || !r
            .invites
            .get(&b.invite_id)
            .is_some_and(|i| i.guest_ticket.is_some() && i.pending_until.is_none())
    {
        return Err(denied());
    }
    r.paths.insert(b.invite_id, b.path);
    Ok(Json(json!({"ok":true})))
}
async fn metrics(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    if hash(&bearer(&h)?) != hash(&a.config.metrics_secret) {
        return Err(denied());
    }
    let d = a.data.lock().unwrap();
    let mut paths = HashMap::<&str, usize>::new();
    for room in d.rooms.values() {
        for path in room.paths.values() {
            *paths.entry(path).or_default() += 1;
        }
    }
    let public_sessions = d.rooms.values().filter(|r| r.public.is_some()).count();
    let public_grants = d
        .grants
        .values()
        .filter(|g| g.owner.starts_with("public:"))
        .count();
    Ok(Json(
        json!({"sessions":d.rooms.len(),"publicSessions":public_sessions,"sockets":room_sockets(&d,false),"publicSockets":room_sockets(&d,true),"relayGrants":d.grants.len(),"publicRelayGrants":public_grants,"relayCredentialsIssued":d.issued,"rateRejected":d.rejected,"signalingForwarded":d.forwarded,"reportedSelectedPaths":paths}),
    ))
}
async fn socket(
    State(a): State<App>,
    Path(session): Path<String>,
    h: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    let ticket = bearer(&h)?;
    {
        let mut d = a.data.lock().unwrap();
        rate(&mut d, format!("socket:{ticket}"), 30, 60)?;
        let r = d.rooms.get(&session).ok_or_else(denied)?;
        a.authorize(r, &ticket)?;
        if !socket_fits(&a.config, &d, &session, &ticket) {
            return Err(sockets_full());
        }
    }
    Ok(ws
        .max_message_size(128 * 1024)
        .max_frame_size(128 * 1024)
        .on_upgrade(move |ws| socket_loop(a, session, ticket, ws)))
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    invite_id: String,
    role: String,
    generation: u32,
    sequence: u64,
    nonce: String,
    ciphertext: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    bootstrap: bool,
}
// A reconnect replaces its own socket, so it never needs extra headroom.
fn socket_fits(c: &Config, d: &Data, session: &str, ticket: &str) -> bool {
    let Some(r) = d.rooms.get(session) else {
        return false;
    };
    if r.sockets.contains_key(ticket) {
        return true;
    }
    room_sockets(d, false) < c.max_sockets
        && (r.public.is_none()
            || c.public
                .as_ref()
                .is_some_and(|p| room_sockets(d, true) < p.max_sockets))
}
async fn socket_loop(a: App, session: String, ticket: String, ws: WebSocket) {
    let (tx, mut rx) = mpsc::channel(128);
    let (stop, mut stopped) = watch::channel(false);
    {
        let mut d = a.data.lock().unwrap();
        // Re-check under the lock: concurrent upgrades may have filled the cap meanwhile.
        if !socket_fits(&a.config, &d, &session, &ticket) {
            return;
        }
        let Some(r) = d.rooms.get_mut(&session) else {
            return;
        };
        let Ok(guest) = a.authorize(r, &ticket) else {
            return;
        };
        if let Some(old) = r.sockets.insert(
            ticket.clone(),
            SocketSender {
                tx: tx.clone(),
                stop,
            },
        ) {
            let _ = old.stop.send(true);
        }
        let _ = tx.try_send(json!({"kind":"ready"}));
        if guest.is_none() {
            for (id, i) in &r.invites {
                if let Some(client) = i.client_id {
                    let _ = tx.try_send(admitted(id, client, i));
                }
            }
        }
    }
    let (mut sink, mut source) = ws.split();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            _=stopped.changed()=> {break;}
            msg=rx.recv()=> { let Some(msg)=msg else{break}; let terminal=msg["kind"]=="ended" || msg["kind"]=="replaced" || msg["kind"]=="admission-ended";
                if !matches!(tokio::time::timeout(std::time::Duration::from_secs(5),sink.send(Message::Text(msg.to_string().into()))).await, Ok(Ok(()))) {break;}
                if terminal {break;}
            }
            _=tick.tick()=> {
                if let Some(r)=a.data.lock().unwrap().rooms.get_mut(&session) { r.touched=now(); }
                if !matches!(tokio::time::timeout(std::time::Duration::from_secs(5),sink.send(Message::Ping(Vec::new().into()))).await, Ok(Ok(()))){break;} }
            msg=source.next()=> {
                let Some(Ok(msg))=msg else{break};
                let mut d=a.data.lock().unwrap();
                if rate(&mut d,format!("signal:{ticket}"),120,1).is_err(){break;}
                let Message::Text(text)=msg else { if matches!(msg,Message::Close(_)){break;} continue; };
                let Some(r)=d.rooms.get_mut(&session) else{break}; let Ok(guest)=a.authorize(r,&ticket) else{break}; r.touched=now();
                let Ok(e)=serde_json::from_str::<Envelope>(&text) else{break};
                if !id(&e.invite_id) || e.nonce.len()!=16 || e.ciphertext.len()>96*1024 || e.sequence>9007199254740991 || e.generation>1_000_000 {break;}
                if r.invites.get(&e.invite_id).is_some_and(|i| i.pending_until.is_some()) && (!e.bootstrap || e.generation != 0) {break;}
                let is_host=guest.is_none();
                let destination=if let Some(g)=guest { if g!=e.invite_id || e.role!="guest" {break;} Some(r.host_ticket.clone()) }
                    else { if e.role!="host" {break;} r.invites.get(&e.invite_id).and_then(|i|i.guest_ticket.clone()) };
                let Some(dest)=destination else{if is_host {continue;} break;};
                // Offline receivers renegotiate when they reconnect; no unbounded mailbox.
                if let Some(target)=r.sockets.get(&dest) { let _=target.try_send(json!({"kind":"signal","envelope":e})); }
                d.forwarded+=1;
            }
        }
    }
    // Do not remove a newer connection that replaced this socket.
    if let Some(r) = a.data.lock().unwrap().rooms.get_mut(&session) {
        if r.sockets
            .get(&ticket)
            .is_some_and(|current| current.same_channel(&tx))
        {
            r.sockets.remove(&ticket);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use std::future::IntoFuture;
    use tower::ServiceExt;
    fn app() -> (App, String) {
        app_with(None, 60)
    }
    fn app_with(public: Option<PublicLimits>, max_sockets: usize) -> (App, String) {
        let db = credential_db(":memory:").unwrap();
        let token = issue(&db, "test").unwrap();
        (
            App::new(
                db,
                Config {
                    stun_urls: vec!["stun:localhost:3478".into()],
                    turn_urls: vec!["turn:localhost:3478".into()],
                    turn_secret: "x".repeat(32),
                    metrics_secret: "d".repeat(64),
                    max_sessions: 10,
                    max_relay_grants: 1,
                    max_sockets,
                    client_ip_header: Some("x-veil-client-ip".into()),
                    public,
                },
            ),
            token,
        )
    }
    async fn request(a: &App, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
        let response = router(a.clone())
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 200000)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    async fn delete_request(a: &App, path: &str, ticket: &str) -> StatusCode {
        router(a.clone())
            .oneshot(
                Request::delete(path)
                    .header("authorization", format!("Bearer {ticket}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }
    #[tokio::test]
    async fn short_lookup_is_authenticated_bounded_and_revocable() {
        let (a, host) = app();
        let (_, room) = request(&a, "/v2/sessions", &host, json!({"clientId":1})).await;
        let session = room["sessionId"].as_str().unwrap();
        let ticket = room["ticket"].as_str().unwrap();
        let path = format!("/v3/sessions/{session}/sharing");
        let lookup = random();
        let reference = "a".repeat(64);
        let record = json!({"reference":reference,"lookupHash":hash(&lookup),"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"});
        let register = json!({"groupId":"b".repeat(32),"admissionHash":hash(&random()),"shortInvitation":record});
        assert_eq!(
            request(&a, &path, &random(), register.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(&a, &path, ticket, register.clone()).await.0,
            StatusCode::OK
        );
        let resolve = json!({"reference":reference,"lookup":lookup});
        let (status, value) = request(&a, "/v3/invitations/resolve", "", resolve.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            value,
            json!({"nonce":record["nonce"],"ciphertext":record["ciphertext"]})
        );
        let wrong = request(
            &a,
            "/v3/invitations/resolve",
            "",
            json!({"reference":reference,"lookup":random()}),
        )
        .await;
        let absent = request(
            &a,
            "/v3/invitations/resolve",
            "",
            json!({"reference":"f".repeat(64),"lookup":lookup}),
        )
        .await;
        assert_eq!(wrong, absent);
        assert_eq!(wrong.0, StatusCode::UNAUTHORIZED);
        let mut invalid = register.clone();
        invalid["shortInvitation"]["ciphertext"] = json!("A".repeat(8193));
        assert_eq!(
            request(&a, &path, ticket, invalid).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            request(&a, "/v3/invitations/resolve", "", resolve.clone())
                .await
                .0,
            StatusCode::OK
        );
        let mut replacement = register.clone();
        replacement["shortInvitation"]["reference"] = json!("c".repeat(64));
        assert_eq!(
            request(&a, &path, ticket, replacement).await.0,
            StatusCode::OK
        );
        assert_eq!(
            request(&a, "/v3/invitations/resolve", "", resolve.clone())
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(delete_request(&a, &path, ticket).await, StatusCode::OK);
        assert_eq!(
            request(&a, "/v3/invitations/resolve", "", resolve.clone())
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        request(&a, &path, ticket, register.clone()).await;
        a.data
            .lock()
            .unwrap()
            .rooms
            .get_mut(session)
            .unwrap()
            .touched = now() - 601;
        assert_eq!(
            request(&a, "/v3/invitations/resolve", "", resolve.clone())
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let (_, room) = request(&a, "/v2/sessions", &host, json!({"clientId":1})).await;
        request(
            &a,
            &format!(
                "/v3/sessions/{}/sharing",
                room["sessionId"].as_str().unwrap()
            ),
            room["ticket"].as_str().unwrap(),
            register,
        )
        .await;
        let (_, ended_room) = request(&a, "/v2/sessions", &host, json!({"clientId":7})).await;
        let ended_session = ended_room["sessionId"].as_str().unwrap();
        let ended_ticket = ended_room["ticket"].as_str().unwrap();
        let ended_reference = "e".repeat(64);
        request(&a, &format!("/v3/sessions/{ended_session}/sharing"), ended_ticket,
            json!({"groupId":"d".repeat(32),"admissionHash":hash(&random()),"shortInvitation":{"reference":ended_reference,"lookupHash":hash(&lookup),"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}})).await;
        assert_eq!(
            delete_request(&a, &format!("/v2/sessions/{ended_session}"), ended_ticket).await,
            StatusCode::OK
        );
        assert_eq!(
            request(
                &a,
                "/v3/invitations/resolve",
                "",
                json!({"reference":ended_reference,"lookup":lookup})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        a.db.lock()
            .unwrap()
            .execute("DELETE FROM hosts WHERE name=?1", ["test"])
            .unwrap();
        assert_eq!(
            request(&a, "/v3/invitations/resolve", "", resolve).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    #[tokio::test]
    async fn short_resolution_rate_limit_does_not_allocate_per_guessed_reference() {
        let (a, _) = app();
        for _ in 0..600 {
            assert_eq!(
                request(
                    &a,
                    "/v3/invitations/resolve",
                    "",
                    json!({"reference":random(),"lookup":random()})
                )
                .await
                .0,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            request(
                &a,
                "/v3/invitations/resolve",
                "",
                json!({"reference":random(),"lookup":random()})
            )
            .await
            .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(a.data.lock().unwrap().limits.len(), 1);
    }
    #[tokio::test]
    async fn pending_guests_need_host_decision_and_expire_without_affecting_approved_guests() {
        let (a, host) = app();
        let (_, room) = request(&a, "/v2/sessions", &host, json!({"clientId":1})).await;
        let session = room["sessionId"].as_str().unwrap();
        let ticket = room["ticket"].as_str().unwrap();
        let path = format!("/v3/sessions/{session}/sharing");
        let admission = random();
        let group = "a".repeat(32);
        let register = json!({"groupId":group,"admissionHash":hash(&admission),"shortInvitation":{"reference":random(),"lookupHash":hash(&random()),"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}});
        assert_eq!(
            request(&a, &path, ticket, register.clone()).await.0,
            StatusCode::OK
        );
        let key = STANDARD.encode([vec![4], vec![0; 64]].concat());
        let body = |id: &str, client: u32| json!({"sessionId":session,"groupId":group,"admission":admission,"inviteId":id,"clientId":client,"guestPublic":key,"approvalProtocol":1});
        let first_id = "b".repeat(32);
        let second_id = "c".repeat(32);
        let mut unsupported = body(&first_id, 2);
        unsupported
            .as_object_mut()
            .unwrap()
            .remove("approvalProtocol");
        assert_eq!(
            request(&a, "/v3/join", "", unsupported).await.0,
            StatusCode::UNAUTHORIZED
        );
        let (_, first) = request(&a, "/v3/join", "", body(&first_id, 2)).await;
        let guest = first["ticket"].as_str().unwrap();
        let relay_body = json!({"sessionId":session,"inviteId":first_id});
        assert_eq!(
            request(&a, "/v2/relay", guest, relay_body.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        let decision = json!({"sessionId":session,"inviteId":first_id,"approve":true});
        assert_eq!(
            request(&a, "/v3/admission/decision", guest, decision.clone())
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(&a, "/v3/admission/decision", ticket, decision)
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            request(&a, "/v2/relay", guest, relay_body).await.0,
            StatusCode::OK
        );
        request(&a, "/v3/join", "", body(&second_id, 3)).await;
        a.data
            .lock()
            .unwrap()
            .rooms
            .get_mut(session)
            .unwrap()
            .invites
            .get_mut(&second_id)
            .unwrap()
            .pending_until = Some(now() - 1);
        a.sweep();
        assert!(!a.data.lock().unwrap().rooms[session]
            .invites
            .contains_key(&second_id));
        assert!(a.data.lock().unwrap().rooms[session]
            .invites
            .contains_key(&first_id));
        request(&a, "/v3/join", "", body(&second_id, 3)).await;
        request(&a, &path, ticket, register).await;
        assert!(!a.data.lock().unwrap().rooms[session]
            .invites
            .contains_key(&second_id));
        assert!(a.data.lock().unwrap().rooms[session]
            .invites
            .contains_key(&first_id));
        request(&a, "/v3/join", "", body(&second_id, 3)).await;
        assert_eq!(
            request(
                &a,
                "/v3/admission/decision",
                ticket,
                json!({"sessionId":session,"inviteId":second_id,"approve":false})
            )
            .await
            .0,
            StatusCode::OK
        );
        assert!(!a.data.lock().unwrap().rooms[session]
            .invites
            .contains_key(&second_id));
    }
    #[tokio::test]
    async fn authenticated_single_use_invites_and_lazy_bounded_relay() {
        let (a, host) = app();
        assert_eq!(
            request(&a, "/v2/sessions", &random(), json!({"clientId":1}))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let (_, room) = request(&a, "/v2/sessions", &host, json!({"clientId":1})).await;
        let s = room["sessionId"].as_str().unwrap();
        let ticket = room["ticket"].as_str().unwrap();
        let i = Uuid::new_v4().simple().to_string();
        let admission = random();
        assert_eq!(
            request(
                &a,
                &format!("/v2/sessions/{s}/invitations"),
                ticket,
                json!({"inviteId":i,"admissionHash":hash(&admission),"expiresAt":(now()+600)*1000})
            )
            .await
            .0,
            StatusCode::OK
        );
        let join_body = json!({"sessionId":s,"inviteId":i,"admission":admission,"clientId":2});
        let (_, guest) = request(&a, "/v2/join", "", join_body.clone()).await;
        assert_eq!(
            request(&a, "/v2/join", "", join_body).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(a.data.lock().unwrap().issued, 0);
        let body = json!({"sessionId":s,"inviteId":i});
        let guest = guest["ticket"].as_str().unwrap();
        let (_, first) = request(&a, "/v2/relay", guest, body.clone()).await;
        let (_, second) = request(&a, "/v2/relay", guest, body.clone()).await;
        assert_eq!(first, second);
        assert_eq!(a.data.lock().unwrap().issued, 1);
        assert_eq!(
            request(&a, "/v2/relay", ticket, body).await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
        // Simulate reaching the renewal window without a ten-minute wall-clock test.
        {
            let mut d = a.data.lock().unwrap();
            for grant in d.grants.values_mut() {
                grant.credentials_until = now() + 10;
            }
            d.limits.retain(|key, _| !key.starts_with("relay:"));
        }
        let (_, renewed) =
            request(&a, "/v2/relay", guest, json!({"sessionId":s,"inviteId":i})).await;
        assert!(renewed["expiresAt"].as_u64().unwrap() > (now() + 500) * 1000);
        assert_eq!(a.data.lock().unwrap().grants.len(), 1);
        let other = issue(&a.db.lock().unwrap(), "other-host").unwrap();
        a.db.lock()
            .unwrap()
            .execute("DELETE FROM hosts WHERE name='test'", [])
            .unwrap();
        assert_eq!(
            request(&a, "/v2/relay", guest, json!({"sessionId":s,"inviteId":i}))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(&a, "/v2/sessions", &other, json!({"clientId":99}))
                .await
                .0,
            StatusCode::OK
        );
    }
    #[tokio::test]
    async fn reusable_sharing_revokes_admission_not_participant_tickets() {
        let (a, host) = app();
        let (_, room) = request(&a, "/v2/sessions", &host, json!({"clientId":1})).await;
        let s = room["sessionId"].as_str().unwrap();
        let t = room["ticket"].as_str().unwrap();
        let path = format!("/v3/sessions/{s}/sharing");
        let group = "a".repeat(32);
        let admission = random();
        let mut key = vec![0; 65];
        key[0] = 4;
        let key = STANDARD.encode(key);
        assert_eq!(
            request(
                &a,
                &path,
                &random(),
                json!({"groupId":group,"admissionHash":hash(&admission)})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                &a,
                &path,
                t,
                json!({"groupId":group,"admissionHash":hash(&admission)})
            )
            .await
            .0,
            StatusCode::OK
        );
        let body = |id: &str, client: u32| json!({"sessionId":s,"groupId":group,"admission":admission,"inviteId":id,"clientId":client,"guestPublic":key});
        let first_id = "b".repeat(32);
        let second_id = "c".repeat(32);
        let (status, first) = request(&a, "/v3/join", "", body(&first_id, 2)).await;
        assert_eq!(status, StatusCode::OK);
        let (status, second) = request(&a, "/v3/join", "", body(&second_id, 3)).await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(first["ticket"], second["ticket"]);
        assert_eq!(
            request(&a, "/v3/join", "", body(&first_id, 4)).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            request(&a, "/v3/join", "", body(&"d".repeat(32), 2))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let first_ticket = first["ticket"].as_str().unwrap();
        assert_eq!(
            request(
                &a,
                &path,
                first_ticket,
                json!({"groupId":"d".repeat(32),"admissionHash":hash(&admission)})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                &a,
                "/v2/relay",
                first_ticket,
                json!({"sessionId":s,"inviteId":second_id})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        // Atomic replacement prevents every new admission under the previous link.
        assert_eq!(
            request(
                &a,
                &path,
                t,
                json!({"groupId":"d".repeat(32),"admissionHash":hash(&random())})
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            request(&a, "/v3/join", "", body(&"e".repeat(32), 4))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let response = router(a.clone())
            .oneshot(
                Request::delete(&path)
                    .header("authorization", format!("Bearer {t}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            request(&a, "/v3/join", "", body(&"f".repeat(32), 5))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let data = a.data.lock().unwrap();
        let room = &data.rooms[s];
        assert_eq!(a.authorize(room, first_ticket).unwrap(), Some(first_id));
        assert_eq!(
            a.authorize(room, second["ticket"].as_str().unwrap())
                .unwrap(),
            Some(second_id)
        );
        assert_eq!(data.issued, 0);
    }
    #[tokio::test]
    async fn opaque_socket_forwarding_rejects_role_substitution() {
        use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message as ClientMessage};
        let (a, host) = app();
        let (_, room) = request(&a, "/v2/sessions", &host, json!({"clientId":1})).await;
        let s = room["sessionId"].as_str().unwrap();
        let ticket = room["ticket"].as_str().unwrap();
        let i = "b".repeat(32);
        let admission = random();
        request(
            &a,
            &format!("/v2/sessions/{s}/invitations"),
            ticket,
            json!({"inviteId":i,"admissionHash":hash(&admission),"expiresAt":(now()+600)*1000}),
        )
        .await;
        let (_, guest) = request(
            &a,
            "/v2/join",
            "",
            json!({"sessionId":s,"inviteId":i,"admission":admission,"clientId":2}),
        )
        .await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = tokio::spawn(axum::serve(listener, router(a.clone())).into_future());
        let url = format!("ws://{address}/v2/socket/{s}");
        assert!(tokio_tungstenite::connect_async(&url).await.is_err());
        let connection = |ticket: &str| {
            let mut request = url.clone().into_client_request().unwrap();
            request
                .headers_mut()
                .insert("authorization", format!("Bearer {ticket}").parse().unwrap());
            request
        };
        let (mut host_socket, _) = tokio_tungstenite::connect_async(connection(ticket))
            .await
            .unwrap();
        let (mut guest_socket, _) =
            tokio_tungstenite::connect_async(connection(guest["ticket"].as_str().unwrap()))
                .await
                .unwrap();
        let signal = json!({"inviteId":i,"role":"guest","generation":1,"sequence":0,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"opaque"});
        guest_socket
            .send(ClientMessage::Text(signal.to_string().into()))
            .await
            .unwrap();
        let forwarded = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(Ok(ClientMessage::Text(text))) = host_socket.next().await {
                    let message: Value = serde_json::from_str(&text).unwrap();
                    if message["kind"] == "signal" {
                        break message;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(forwarded["envelope"], signal);
        let mut forged = signal;
        forged["role"] = json!("host");
        guest_socket
            .send(ClientMessage::Text(forged.to_string().into()))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while let Some(message) = guest_socket.next().await {
                if message.is_err() || matches!(message, Ok(ClientMessage::Close(_))) {
                    break;
                }
            }
        })
        .await
        .unwrap();
        // The healthy host socket remains registered after rejecting only the guest.
        assert!(a.data.lock().unwrap().rooms[s].sockets.contains_key(ticket));
        service.abort();
    }
    #[tokio::test]
    async fn pending_socket_allows_only_bootstrap_and_keeps_host_healthy() {
        use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message as ClientMessage};
        let (a, host) = app();
        let (_, room) = request(&a, "/v2/sessions", &host, json!({"clientId":1})).await;
        let session = room["sessionId"].as_str().unwrap();
        let ticket = room["ticket"].as_str().unwrap();
        let invite = "a".repeat(32);
        let admission = random();
        request(&a, &format!("/v3/sessions/{session}/sharing"), ticket,
            json!({"groupId":"b".repeat(32),"admissionHash":hash(&admission),"shortInvitation":{"reference":random(),"lookupHash":hash(&random()),"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}})).await;
        let (_, guest) = request(&a, "/v3/join", "", json!({"sessionId":session,"groupId":"b".repeat(32),"admission":admission,"inviteId":invite,"clientId":2,"guestPublic":STANDARD.encode([vec![4],vec![0;64]].concat()),"approvalProtocol":1})).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = tokio::spawn(axum::serve(listener, router(a.clone())).into_future());
        let connection = |ticket: &str| {
            let mut request = format!("ws://{address}/v2/socket/{session}")
                .into_client_request()
                .unwrap();
            request
                .headers_mut()
                .insert("authorization", format!("Bearer {ticket}").parse().unwrap());
            request
        };
        let (mut host_socket, _) = tokio_tungstenite::connect_async(connection(ticket))
            .await
            .unwrap();
        let (mut guest_socket, _) =
            tokio_tungstenite::connect_async(connection(guest["ticket"].as_str().unwrap()))
                .await
                .unwrap();
        let signal = json!({"inviteId":invite,"role":"guest","generation":0,"sequence":0,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"opaque","bootstrap":true});
        guest_socket
            .send(ClientMessage::Text(signal.to_string().into()))
            .await
            .unwrap();
        let forwarded = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(Ok(ClientMessage::Text(text))) = host_socket.next().await {
                    let value: Value = serde_json::from_str(&text).unwrap();
                    if value["kind"] == "signal" {
                        break value;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(forwarded["envelope"], signal);
        let mut established = signal;
        established["bootstrap"] = json!(false);
        established["sequence"] = json!(1);
        guest_socket
            .send(ClientMessage::Text(established.to_string().into()))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while let Some(message) = guest_socket.next().await {
                if message.is_err() || matches!(message, Ok(ClientMessage::Close(_))) {
                    break;
                }
            }
        })
        .await
        .unwrap();
        let (mut retry_socket, _) =
            tokio_tungstenite::connect_async(connection(guest["ticket"].as_str().unwrap()))
                .await
                .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(Ok(ClientMessage::Text(text))) = retry_socket.next().await {
                    let value: Value = serde_json::from_str(&text).unwrap();
                    if value["kind"] == "ready" {
                        break;
                    }
                }
            }
        })
        .await
        .unwrap();
        let rejection = json!({"inviteId":invite,"role":"host","generation":0,"sequence":1,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"signed-rejection","bootstrap":true});
        assert_eq!(
            request(
                &a,
                "/v3/admission/decision",
                ticket,
                json!({"sessionId":session,"inviteId":invite,"approve":false,"rejection":rejection})
            )
            .await
            .0,
            StatusCode::OK
        );
        let delivered = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut messages = Vec::new();
            while let Some(Ok(message)) = retry_socket.next().await {
                let ClientMessage::Text(text) = message else {
                    continue;
                };
                let value: Value = serde_json::from_str(&text).unwrap();
                if value["kind"] == "signal" {
                    messages.push(value);
                } else if value["kind"] == "admission-ended" {
                    messages.push(value);
                    break;
                }
            }
            messages
        })
        .await
        .unwrap();
        assert_eq!(delivered[0]["envelope"], rejection);
        assert_eq!(delivered[1]["kind"], "admission-ended");
        assert!(a.data.lock().unwrap().rooms[session]
            .sockets
            .contains_key(ticket));
        service.abort();
    }
    #[tokio::test]
    async fn expired_invites_and_cross_connection_credentials_fail() {
        let (a, host) = app();
        let (_, r) = request(&a, "/v2/sessions", &host, json!({"clientId":1})).await;
        let s = r["sessionId"].as_str().unwrap();
        let t = r["ticket"].as_str().unwrap();
        assert_eq!(request(&a,&format!("/v2/sessions/{s}/invitations"),t,json!({"inviteId":"a".repeat(32),"admissionHash":"b".repeat(64),"expiresAt":now()*1000-1000})).await.0,StatusCode::BAD_REQUEST);
        assert_eq!(
            request(
                &a,
                "/v2/relay",
                &random(),
                json!({"sessionId":s,"inviteId":"a".repeat(32)})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    #[tokio::test]
    async fn compatibility_preflight_and_atomic_admission() {
        let (a, host) = app();
        let metadata = json!({"appVersion":"0.5.0","serverProtocols":[2],"peerProtocols":[1]});
        let (_, room) = request(
            &a,
            "/v2/sessions",
            &host,
            json!({"clientId":1,"compatibility":metadata}),
        )
        .await;
        let s = room["sessionId"].as_str().unwrap();
        let ticket = room["ticket"].as_str().unwrap();
        let group = "a".repeat(32);
        let admission = random();
        let path = format!("/v3/sessions/{s}/sharing");
        request(
            &a,
            &path,
            ticket,
            json!({"groupId":group,"admissionHash":hash(&admission)}),
        )
        .await;
        let mut preview =
            json!({"sessionId":s,"groupId":group,"admission":admission,"compatibility":metadata});
        let (status, data) = request(&a, "/v3/compatibility", "", preview.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(data["hostCompatibility"], metadata);
        assert_eq!(data["peerProtocol"], 1);
        assert!(data.get("ticket").is_none());
        assert!(a.data.lock().unwrap().rooms[s].invites.is_empty());
        preview["admission"] = json!(random());
        assert_eq!(
            request(&a, "/v3/compatibility", "", preview.clone())
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        preview["admission"] = json!(admission);
        preview["compatibility"]["peerProtocols"] = json!([2]);
        assert_eq!(
            request(&a, "/v3/compatibility", "", preview.clone())
                .await
                .1["error"],
            "PEER_PROTOCOL_UNSUPPORTED"
        );
        let mut key = vec![0; 65];
        key[0] = 4;
        let mut join = json!({"sessionId":s,"groupId":group,"admission":admission,"inviteId":"b".repeat(32),"clientId":2,"guestPublic":STANDARD.encode(key),"compatibility":metadata});
        join["compatibility"]["serverProtocols"] = json!([3]);
        assert_eq!(
            request(&a, "/v3/join", "", join.clone()).await.1["error"],
            "CLIENT_PROTOCOL_UNSUPPORTED"
        );
        assert!(a.data.lock().unwrap().rooms[s].invites.is_empty());
        join["compatibility"] = metadata.clone();
        join["compatibility"]["appVersion"] = json!("0.4.0");
        assert_eq!(
            request(&a, "/v3/join", "", join.clone()).await.0,
            StatusCode::OK
        );
        // Revoking after preflight must reject new admission, retaining admitted guests.
        a.data.lock().unwrap().rooms.get_mut(s).unwrap().sharing = None;
        join["inviteId"] = json!("c".repeat(32));
        join["clientId"] = json!(3);
        assert_eq!(
            request(&a, "/v3/join", "", join).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(a.data.lock().unwrap().rooms[s].invites.len(), 1);
        assert_eq!(
            request(&a, "/v3/compatibility", "", preview).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    #[tokio::test]
    async fn compatibility_legacy_invites_are_not_consumed_by_preview() {
        let (a, host) = app();
        let (_, room) = request(&a, "/v2/sessions", &host, json!({"clientId":1})).await;
        let s = room["sessionId"].as_str().unwrap();
        let ticket = room["ticket"].as_str().unwrap();
        let invite = "a".repeat(32);
        let admission = random();
        request(&a, &format!("/v2/sessions/{s}/invitations"), ticket,
            json!({"inviteId":invite,"admissionHash":hash(&admission),"expiresAt":(now()+600)*1000})).await;
        let metadata = json!({"appVersion":"0.5.0","serverProtocols":[2],"peerProtocols":[1]});
        let body =
            json!({"sessionId":s,"inviteId":invite,"admission":admission,"compatibility":metadata});
        let (status, preview) = request(&a, "/v3/compatibility", "", body.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(preview["hostCompatibility"].is_null());
        let mut join = body;
        join["clientId"] = json!(2);
        join["compatibility"]["peerProtocols"] = json!([2]);
        assert_eq!(
            request(&a, "/v2/join", "", join.clone()).await.1["error"],
            "PEER_PROTOCOL_UNSUPPORTED"
        );
        assert!(a.data.lock().unwrap().rooms[s].invites[&invite]
            .guest_ticket
            .is_none());
        join["compatibility"] = metadata;
        assert_eq!(request(&a, "/v2/join", "", join).await.0, StatusCode::OK);
    }
    async fn from_peer(
        a: &App,
        path: &str,
        peer: &str,
        client_ip: Option<&str>,
        token: Option<&str>,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut builder = Request::post(path).header("content-type", "application/json");
        if let Some(ip) = client_ip {
            builder = builder.header("x-veil-client-ip", ip);
        }
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let mut req = builder.body(Body::from(body.to_string())).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        let response = router(a.clone()).oneshot(req).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 200000)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    async fn get_json(a: &App, path: &str, token: Option<&str>) -> Value {
        let mut builder = Request::get(path);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let response = router(a.clone())
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 200000)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
    async fn relay_for(a: &App, s: &str, t: &str) -> (StatusCode, Value) {
        request(
            a,
            "/v2/relay",
            t,
            json!({"sessionId":s,"inviteId":"b".repeat(32)}),
        )
        .await
    }
    fn limits() -> PublicLimits {
        PublicLimits {
            max_sessions: 3,
            sessions_per_ip: 2,
            max_guests: 1,
            max_sockets: 40,
            relay_grants: 1,
            relay_grants_per_ip: 1,
        }
    }
    const PROXY: &str = "127.0.0.1:40000";
    #[tokio::test]
    async fn public_hosting_is_off_by_default() {
        let (a, _) = app();
        let create = json!({"clientId":1});
        let (status, _) = from_peer(
            &a,
            "/v2/sessions",
            PROXY,
            Some("198.51.100.1"),
            None,
            create,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(get_json(&a, "/v2/capabilities", None)
            .await
            .get("publicHosting")
            .is_none());
    }
    #[tokio::test]
    async fn public_sessions_are_bounded_per_client_and_globally() {
        let (a, host) = app_with(Some(limits()), 60);
        let caps = get_json(&a, "/v2/capabilities", None).await;
        assert_eq!(caps["publicHosting"], 1);
        assert_eq!(caps["publicLimits"]["maxGuests"], 1);
        let create = json!({"clientId":1});
        let at =
            |ip: &'static str| from_peer(&a, "/v2/sessions", PROXY, Some(ip), None, create.clone());
        assert_eq!(at("198.51.100.1").await.0, StatusCode::OK);
        assert_eq!(at("198.51.100.1").await.0, StatusCode::OK);
        let (status, body) = at("198.51.100.1").await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::TOO_MANY_REQUESTS, Some("PUBLIC_LIMIT_REACHED"))
        );
        assert_eq!(at("198.51.100.2").await.0, StatusCode::OK);
        let (status, body) = at("198.51.100.3").await;
        assert_eq!(
            (status, body["error"].as_str()),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("PUBLIC_CAPACITY_FULL")
            )
        );
        // A full public tier leaves trusted hosts alone, and a wrong credential is never downgraded.
        let trusted = from_peer(&a, "/v2/sessions", PROXY, None, Some(&host), create.clone()).await;
        assert_eq!(trusted.0, StatusCode::OK);
        let wrong = from_peer(
            &a,
            "/v2/sessions",
            PROXY,
            None,
            Some(&random()),
            create.clone(),
        )
        .await;
        assert_eq!(wrong.0, StatusCode::UNAUTHORIZED);
        let (session, ticket) = a
            .data
            .lock()
            .unwrap()
            .rooms
            .iter()
            .find(|(_, r)| r.public.is_some())
            .map(|(s, r)| (s.clone(), r.host_ticket.clone()))
            .unwrap();
        assert_eq!(
            delete_request(&a, &format!("/v2/sessions/{session}"), &ticket).await,
            StatusCode::OK
        );
        assert_eq!(at("198.51.100.3").await.0, StatusCode::OK);
    }
    #[tokio::test]
    async fn client_ip_header_is_trusted_only_from_proxies() {
        let (a, _) = app_with(Some(limits()), 60);
        let create = json!({"clientId":1});
        let direct = "203.0.113.5:5000";
        for (spoof, expected) in [
            ("198.51.100.7", StatusCode::OK),
            ("198.51.100.8", StatusCode::OK),
            ("198.51.100.9", StatusCode::TOO_MANY_REQUESTS),
        ] {
            let (status, _) = from_peer(
                &a,
                "/v2/sessions",
                direct,
                Some(spoof),
                None,
                create.clone(),
            )
            .await;
            assert_eq!(status, expected);
        }
        // One IPv6 /64 counts as one client.
        let (a, _) = app_with(Some(limits()), 60);
        for (ip, expected) in [
            ("2001:db8::1", StatusCode::OK),
            ("2001:db8::2", StatusCode::OK),
            ("2001:db8::3", StatusCode::TOO_MANY_REQUESTS),
        ] {
            let (status, _) =
                from_peer(&a, "/v2/sessions", PROXY, Some(ip), None, create.clone()).await;
            assert_eq!(status, expected);
        }
    }
    #[tokio::test]
    async fn public_guest_cap_and_relay_pool_preserve_trusted_headroom() {
        let (a, host) = app_with(Some(limits()), 60);
        let mut rooms = Vec::new();
        for (ip, token) in [
            (Some("198.51.100.1"), None),
            (Some("198.51.100.2"), None),
            (None, Some(host.as_str())),
        ] {
            let (_, room) =
                from_peer(&a, "/v2/sessions", PROXY, ip, token, json!({"clientId":1})).await;
            let s = room["sessionId"].as_str().unwrap().to_string();
            let t = room["ticket"].as_str().unwrap().to_string();
            let mut joined = Vec::new();
            for (n, client) in [("b", 2), ("c", 3)] {
                let i = n.repeat(32);
                let admission = random();
                request(
                    &a,
                    &format!("/v2/sessions/{s}/invitations"),
                    &t,
                    json!({"inviteId":i,"admissionHash":hash(&admission),"expiresAt":(now()+600)*1000}),
                )
                .await;
                joined.push(
                    request(
                        &a,
                        "/v2/join",
                        "",
                        json!({"sessionId":s,"inviteId":i,"admission":admission,"clientId":client}),
                    )
                    .await,
                );
            }
            rooms.push((s, t, joined));
        }
        for (_, _, joined) in &rooms[..2] {
            assert_eq!(joined[0].0, StatusCode::OK);
            assert_eq!(
                (joined[1].0, joined[1].1["error"].as_str()),
                (StatusCode::TOO_MANY_REQUESTS, Some("PUBLIC_GUEST_LIMIT"))
            );
        }
        assert!(rooms[2]
            .2
            .iter()
            .all(|(status, _)| *status == StatusCode::OK));
        assert_eq!(
            relay_for(&a, &rooms[0].0, &rooms[0].1).await.0,
            StatusCode::OK
        );
        let (status, body) = relay_for(&a, &rooms[1].0, &rooms[1].1).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("PUBLIC_CAPACITY_FULL")
            )
        );
        assert_eq!(
            relay_for(&a, &rooms[2].0, &rooms[2].1).await.0,
            StatusCode::OK
        );
        let metrics = get_json(&a, "/v2/metrics", Some(&"d".repeat(64))).await;
        assert_eq!(metrics["publicSessions"], 2);
        assert_eq!(metrics["publicRelayGrants"], 1);
        assert_eq!(metrics["relayGrants"], 2);
    }
    #[tokio::test]
    async fn socket_cap_refuses_new_sockets_sessions_and_guests() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let (a, host) = app_with(None, 1);
        let mut rooms = Vec::new();
        for _ in 0..2 {
            let (_, room) = request(&a, "/v2/sessions", &host, json!({"clientId":1})).await;
            rooms.push((
                room["sessionId"].as_str().unwrap().to_string(),
                room["ticket"].as_str().unwrap().to_string(),
            ));
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = tokio::spawn(axum::serve(listener, router(a.clone())).into_future());
        let connect = |(s, t): &(String, String)| {
            let mut req = format!("ws://{address}/v2/socket/{s}")
                .into_client_request()
                .unwrap();
            req.headers_mut()
                .insert("authorization", format!("Bearer {t}").parse().unwrap());
            tokio_tungstenite::connect_async(req)
        };
        let _first = connect(&rooms[0]).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while room_sockets(&a.data.lock().unwrap(), false) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(connect(&rooms[1]).await.is_err());
        // Reconnecting an existing ticket replaces its own socket and needs no headroom.
        assert!(connect(&rooms[0]).await.is_ok());
        let (status, body) = request(&a, "/v2/sessions", &host, json!({"clientId":1})).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::SERVICE_UNAVAILABLE, Some("CAPACITY_FULL"))
        );
        let (s, t) = &rooms[0];
        let admission = random();
        request(
            &a,
            &format!("/v2/sessions/{s}/invitations"),
            t,
            json!({"inviteId":"b".repeat(32),"admissionHash":hash(&admission),"expiresAt":(now()+600)*1000}),
        )
        .await;
        let (status, _) = request(
            &a,
            "/v2/join",
            "",
            json!({"sessionId":s,"inviteId":"b".repeat(32),"admission":admission,"clientId":2}),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        service.abort();
    }
}
