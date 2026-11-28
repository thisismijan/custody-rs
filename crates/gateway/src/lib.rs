use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{OriginalUri, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use sfv::{Dictionary, FieldType, InnerList, ListEntry, Parser};
use sha2::{Digest, Sha256};

const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_CREATED_AGE_SECS: i64 = 60;
const MAX_CREATED_SKEW_SECS: i64 = 5;
const NONCE_RETENTION_SECS: u64 = 65;
const COVERED_COMPONENTS: [&str; 5] =
    ["@method", "@authority", "@path", "@query", "content-digest"];

#[derive(Clone, Debug)]
pub struct RegisteredKey {
    pub key_id: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub public_key: VerifyingKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Caller {
    pub client_id: String,
    pub key_id: String,
    pub scopes: Vec<String>,
}

pub struct GatewayConfig {
    pub authority: String,
}

pub trait KeyStore: Send + Sync + 'static {
    fn get(&self, key_id: &str) -> impl Future<Output = Option<RegisteredKey>> + Send;
}

pub trait NonceStore: Send + Sync + 'static {
    fn record_if_new(
        &self,
        key_id: &str,
        nonce: &str,
        created: u64,
        now: u64,
    ) -> impl Future<Output = bool> + Send;
}

pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> u64;
}

pub struct GatewayState<K: KeyStore, N: NonceStore, C: Clock> {
    pub config: Arc<GatewayConfig>,
    pub keys: Arc<K>,
    pub nonces: Arc<N>,
    pub clock: Arc<C>,
}

impl<K: KeyStore, N: NonceStore, C: Clock> Clone for GatewayState<K, N, C> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            keys: self.keys.clone(),
            nonces: self.nonces.clone(),
            clock: self.clock.clone(),
        }
    }
}

pub struct InMemoryKeyStore {
    keys: HashMap<String, RegisteredKey>,
}

impl InMemoryKeyStore {
    pub fn new(keys: Vec<RegisteredKey>) -> Self {
        Self {
            keys: keys.into_iter().map(|k| (k.key_id.clone(), k)).collect(),
        }
    }
}

impl KeyStore for InMemoryKeyStore {
    async fn get(&self, key_id: &str) -> Option<RegisteredKey> {
        self.keys.get(key_id).cloned()
    }
}

#[derive(Default)]
struct NonceState {
    created_by_pair: HashMap<(String, String), u64>,
    insertion_order: VecDeque<(String, String)>,
}

impl NonceState {
    fn prune(&mut self, now: u64) {
        while let Some(pair) = self.insertion_order.front() {
            let expired = self
                .created_by_pair
                .get(pair)
                .is_none_or(|created| created.saturating_add(NONCE_RETENTION_SECS) <= now);
            if !expired {
                break;
            }
            if let Some(pair) = self.insertion_order.pop_front() {
                self.created_by_pair.remove(&pair);
            }
        }
    }
}

#[derive(Default)]
pub struct InMemoryNonceStore {
    state: Mutex<NonceState>,
}

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prune(&self, now: u64) {
        self.lock().prune(now);
    }

    pub fn contains(&self, key_id: &str, nonce: &str) -> bool {
        self.lock()
            .created_by_pair
            .contains_key(&(key_id.to_owned(), nonce.to_owned()))
    }

    fn lock(&self) -> MutexGuard<'_, NonceState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl NonceStore for InMemoryNonceStore {
    async fn record_if_new(&self, key_id: &str, nonce: &str, created: u64, now: u64) -> bool {
        let mut state = self.lock();
        state.prune(now);
        let pair = (key_id.to_owned(), nonce.to_owned());
        if state.created_by_pair.contains_key(&pair) {
            return false;
        }
        state.created_by_pair.insert(pair.clone(), created);
        state.insertion_order.push_back(pair);
        true
    }
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

pub fn app<K: KeyStore, N: NonceStore, C: Clock>(state: GatewayState<K, N, C>) -> Router {
    authenticated(Router::new().route("/v1/whoami", get(whoami)), state)
}

pub fn authenticated<K: KeyStore, N: NonceStore, C: Clock>(
    router: Router,
    state: GatewayState<K, N, C>,
) -> Router {
    router.layer(middleware::from_fn_with_state(
        state,
        authenticate::<K, N, C>,
    ))
}

async fn whoami(Extension(caller): Extension<Caller>) -> Json<Caller> {
    Json(caller)
}

async fn authenticate<K: KeyStore, N: NonceStore, C: Clock>(
    State(state): State<GatewayState<K, N, C>>,
    req: Request,
    next: Next,
) -> Response {
    match verify(&state, req).await {
        Ok(req) => next.run(req).await,
        Err(StatusCode::UNAUTHORIZED) => unauthorized(),
        Err(status) => status.into_response(),
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"error":"unauthorized"}"#,
    )
        .into_response()
}

struct SignatureInput {
    inner: InnerList,
    created: i64,
    nonce: String,
    keyid: String,
    expires: Option<i64>,
}

const DENY: StatusCode = StatusCode::UNAUTHORIZED;

async fn verify<K: KeyStore, N: NonceStore, C: Clock>(
    state: &GatewayState<K, N, C>,
    req: Request,
) -> Result<Request, StatusCode> {
    let (mut parts, body) = req.into_parts();

    let (label, input) = single_member(one_header(&parts.headers, "signature-input"))
        .and_then(|(label, entry)| Some((label, parse_signature_input(entry)?)))
        .ok_or(DENY)?;
    let signature = single_member(one_header(&parts.headers, "signature"))
        .filter(|(sig_label, _)| *sig_label == label)
        .and_then(|(_, entry)| parse_signature(entry))
        .ok_or(DENY)?;

    let authority = match parts.headers.get(header::HOST) {
        Some(host) => host.to_str().ok(),
        None => parts.uri.authority().map(|a| a.as_str()),
    }
    .ok_or(DENY)?
    .to_ascii_lowercase();
    if authority != state.config.authority.to_ascii_lowercase() {
        return Err(DENY);
    }
    let key = state.keys.get(&input.keyid).await.ok_or(DENY)?;

    let now = state.clock.now();
    let now_signed = i64::try_from(now).map_err(|_| DENY)?;
    if input.created < now_signed - MAX_CREATED_AGE_SECS
        || input.created > now_signed + MAX_CREATED_SKEW_SECS
        || input.expires.is_some_and(|expires| expires <= now_signed)
    {
        return Err(DENY);
    }
    let created = u64::try_from(input.created).map_err(|_| DENY)?;

    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    let digest_header = one_header(&parts.headers, "content-digest").ok_or(DENY)?;
    let digest: Dictionary = Parser::new(digest_header).parse().map_err(|_| DENY)?;
    let claimed = match digest.get("sha-256") {
        Some(ListEntry::Item(item)) => item.bare_item.as_byte_sequence(),
        _ => None,
    };
    if claimed != Some(Sha256::digest(&bytes).as_slice()) {
        return Err(DENY);
    }

    let path = parts
        .extensions
        .get::<OriginalUri>()
        .map_or_else(|| parts.uri.path(), |original| original.0.path());
    let params = vec![ListEntry::InnerList(input.inner.clone())]
        .serialize()
        .ok_or(DENY)?;
    let base = format!(
        "\"@method\": {}\n\"@authority\": {}\n\"@path\": {}\n\"@query\": ?{}\n\"content-digest\": {}\n\"@signature-params\": {}",
        parts.method.as_str(),
        authority,
        path,
        parts.uri.query().unwrap_or(""),
        digest_header,
        params,
    );
    key.public_key
        .verify_strict(base.as_bytes(), &signature)
        .map_err(|_| DENY)?;

    if !state
        .nonces
        .record_if_new(&input.keyid, &input.nonce, created, now)
        .await
    {
        return Err(DENY);
    }

    parts.extensions.insert(Caller {
        client_id: key.client_id,
        key_id: key.key_id,
        scopes: key.scopes,
    });
    Ok(Request::from_parts(parts, Body::from(bytes)))
}

fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first.to_str().ok()
}

fn single_member(value: Option<&str>) -> Option<(String, ListEntry)> {
    let dict: Dictionary = Parser::new(value?).parse().ok()?;
    if dict.len() != 1 {
        return None;
    }
    let (label, entry) = dict.into_iter().next()?;
    Some((label.as_str().to_owned(), entry))
}

fn parse_signature_input(entry: ListEntry) -> Option<SignatureInput> {
    let ListEntry::InnerList(inner) = entry else {
        return None;
    };
    let covers_exactly = inner.items.len() == COVERED_COMPONENTS.len()
        && inner
            .items
            .iter()
            .zip(COVERED_COMPONENTS)
            .all(|(item, name)| {
                item.params.is_empty()
                    && item
                        .bare_item
                        .as_string()
                        .is_some_and(|s| s.as_str() == name)
            });
    if !covers_exactly {
        return None;
    }
    let (mut created, mut nonce, mut keyid, mut expires) = (None, None, None, None);
    for (name, value) in &inner.params {
        match name.as_str() {
            "created" => created = Some(i64::from(value.as_integer()?)),
            "nonce" => nonce = Some(value.as_string()?.as_str().to_owned()),
            "keyid" => keyid = Some(value.as_string()?.as_str().to_owned()),
            "expires" => expires = Some(i64::from(value.as_integer()?)),
            "alg" => {
                value.as_string()?;
            }
            _ => return None,
        }
    }
    Some(SignatureInput {
        created: created?,
        nonce: nonce?,
        keyid: keyid?,
        expires,
        inner,
    })
}

fn parse_signature(entry: ListEntry) -> Option<Signature> {
    let ListEntry::Item(item) = entry else {
        return None;
    };
    Signature::from_slice(item.bare_item.as_byte_sequence()?).ok()
}
