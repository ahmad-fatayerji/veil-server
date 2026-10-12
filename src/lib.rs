mod compatibility;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Path, State,
    },
    http::{HeaderMap, StatusCode},
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
            max_relay_grants: std::env::var("MAX_RELAY_GRANTS")
                .unwrap_or("8".into())
                .parse()
                .map_err(|_| "Invalid MAX_RELAY_GRANTS")?,
        })
    }
}

struct Invite {
    admission_hash: String,
    expires: u64,
    client_id: Option<u32>,
    guest_ticket: Option<String>,
    group: Option<GroupGuest>,
}
struct Sharing {
    group_id: String,
    admission_hash: String,
}
struct GroupGuest {
    group_id: String,
    guest_public: String,
}
struct Room {
    owner: String,
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
    fn host_owner(&self, h: &HeaderMap) -> Result<String> {
        let owner = hash(&bearer(h)?);
        if self.owner_valid(&owner) {
            Ok(owner)
        } else {
            Err(denied())
        }
    }
    fn authorize(&self, room: &Room, ticket: &str) -> Result<Option<String>> {
        if !self.owner_valid(&room.owner) {
            return Err(denied());
        }
        if room.host_ticket == ticket {
            return Ok(None);
        }
        room.invites
            .iter()
            .find(|(_, i)| i.guest_ticket.as_deref() == Some(ticket))
            .map(|(id, _)| Some(id.clone()))
            .ok_or_else(denied)
    }
    pub fn sweep(&self) {
        let mut d = self.data.lock().unwrap();
        let t = now();
        d.rooms.retain(|_, r| {
            let keep = r.touched + 600 > t && self.owner_valid(&r.owner);
            if !keep {
                for tx in r.sockets.values() {
                    let _ = tx.try_send(json!({"kind":"ended"}));
                }
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
    Json(
        json!({"protocol":2,"groupSharing":1,"compatibility":1,"serverVersion":env!("CARGO_PKG_VERSION"),"serverProtocols":compatibility::SERVER_PROTOCOLS,"stunUrls":a.config.stun_urls,"directTimeoutMs":6000,"relayTimeoutMs":20000}),
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Create {
    client_id: u32,
    compatibility: Option<ClientCompatibility>,
}
async fn create(State(a): State<App>, h: HeaderMap, Json(b): Json<Create>) -> Result<Json<Value>> {
    let owner = a.host_owner(&h)?;
    check_client(b.compatibility.as_ref())?;
    a.sweep();
    let mut d = a.data.lock().unwrap();
    rate(&mut d, format!("create:{owner}"), 10, 60)?;
    if d.rooms.len() >= a.config.max_sessions {
        return Err(full());
    }
    let session = Uuid::new_v4().simple().to_string();
    let ticket = random();
    d.rooms.insert(
        session.clone(),
        Room {
            owner,
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
async fn join(State(a): State<App>, Json(b): Json<Join>) -> Result<Json<Value>> {
    if !id(&b.session_id) || !id(&b.invite_id) || !secret(&b.admission) {
        return Err(bad());
    }
    let mut d = a.data.lock().unwrap();
    rate(&mut d, format!("join:{}", b.session_id), 30, 60)?;
    let r = d.rooms.get_mut(&b.session_id).ok_or_else(denied)?;
    if !a.owner_valid(&r.owner) {
        return Err(denied());
    }
    let i = r.invites.get(&b.invite_id).ok_or_else(denied)?;
    if i.expires <= now() || i.admission_hash != hash(&b.admission) || i.guest_ticket.is_some() {
        return Err(denied());
    }
    check_pair(r.host_compatibility.as_ref(), b.compatibility.as_ref())?;
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
    if !a.owner_valid(&r.owner) {
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
}
async fn share(
    State(a): State<App>,
    Path(session): Path<String>,
    h: HeaderMap,
    Json(b): Json<Share>,
) -> Result<Json<Value>> {
    if !id(&b.group_id) || !secret(&b.admission_hash) {
        return Err(bad());
    }
    let ticket = bearer(&h)?;
    let mut d = a.data.lock().unwrap();
    rate(&mut d, format!("sharing:{ticket}"), 60, 60)?;
    let r = d.rooms.get_mut(&session).ok_or_else(denied)?;
    if a.authorize(r, &ticket)?.is_some() {
        return Err(denied());
    }
    r.sharing = Some(Sharing {
        group_id: b.group_id,
        admission_hash: b.admission_hash,
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
    r.sharing = None;
    r.touched = now();
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
    let r = d.rooms.get_mut(&b.session_id).ok_or_else(denied)?;
    if !a.owner_valid(&r.owner) {
        return Err(denied());
    }
    let sharing = r.sharing.as_ref().ok_or_else(denied)?;
    if sharing.group_id != b.group_id || sharing.admission_hash != hash(&b.admission) {
        return Err(denied());
    }
    check_pair(r.host_compatibility.as_ref(), b.compatibility.as_ref())?;
    if b.client_id == r.host_client_id
        || r.invites.contains_key(&b.invite_id)
        || r.invites.values().any(|i| i.client_id == Some(b.client_id))
    {
        return Err(bad());
    }
    let ticket = random();
    let invite = Invite {
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
            .is_some_and(|i| i.guest_ticket.is_some())
    {
        return Err(denied());
    }
    let owner = r.owner.clone();
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
    if !d.grants.contains_key(&key)
        && (d.grants.len() >= 32
            || d.grants.values().filter(|g| g.owner == owner).count() >= a.config.max_relay_grants)
    {
        return Err(full());
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
            .is_some_and(|i| i.guest_ticket.is_some())
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
    Ok(Json(
        json!({"sessions":d.rooms.len(),"relayGrants":d.grants.len(),"relayCredentialsIssued":d.issued,"rateRejected":d.rejected,"signalingForwarded":d.forwarded,"reportedSelectedPaths":paths}),
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
async fn socket_loop(a: App, session: String, ticket: String, ws: WebSocket) {
    let (tx, mut rx) = mpsc::channel(128);
    let (stop, mut stopped) = watch::channel(false);
    {
        let mut d = a.data.lock().unwrap();
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
            msg=rx.recv()=> { let Some(msg)=msg else{break}; let terminal=msg["kind"]=="ended" || msg["kind"]=="replaced";
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
                let Some(r)=d.rooms.get_mut(&session) else{break}; let Ok(guest)=a.authorize(r,&ticket) else{break}; r.touched=now();
                let Message::Text(text)=msg else { if matches!(msg,Message::Close(_)){break;} continue; };
                let Ok(e)=serde_json::from_str::<Envelope>(&text) else{break};
                if !id(&e.invite_id) || e.nonce.len()!=16 || e.ciphertext.len()>96*1024 || e.sequence>9007199254740991 || e.generation>1_000_000 {break;}
                let destination=if let Some(g)=guest { if g!=e.invite_id || e.role!="guest" {break;} Some(r.host_ticket.clone()) }
                    else { if e.role!="host" {break;} r.invites.get(&e.invite_id).and_then(|i|i.guest_ticket.clone()) };
                let Some(dest)=destination else{break};
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
}
