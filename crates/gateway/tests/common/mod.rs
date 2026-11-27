#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderValue, Request, StatusCode};
use axum::routing::any;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey};
use gateway::{
    Clock, GatewayConfig, GatewayState, InMemoryKeyStore, InMemoryNonceStore, RegisteredKey,
};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

pub const AUTHORITY: &str = "gateway.test";
pub const NOW: u64 = 1_700_000_000;

pub struct TestClock(AtomicU64);

impl TestClock {
    pub fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }

    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

pub type TestState = GatewayState<InMemoryKeyStore, InMemoryNonceStore, TestClock>;

pub fn registered_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

pub fn unregistered_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

pub fn bootstrap_key() -> RegisteredKey {
    RegisteredKey {
        key_id: "bootstrap".to_string(),
        client_id: "bootstrap".to_string(),
        scopes: vec!["bootstrap".to_string()],
        public_key: registered_signing_key().verifying_key(),
    }
}

pub struct Fixture {
    pub config: Arc<GatewayConfig>,
    pub keys: Arc<InMemoryKeyStore>,
    pub nonces: Arc<InMemoryNonceStore>,
    pub clock: Arc<TestClock>,
}

impl Fixture {
    pub fn new() -> Self {
        Self {
            config: Arc::new(GatewayConfig {
                authority: AUTHORITY.to_string(),
            }),
            keys: Arc::new(InMemoryKeyStore::new(vec![bootstrap_key()])),
            nonces: Arc::new(InMemoryNonceStore::new()),
            clock: Arc::new(TestClock::new(NOW)),
        }
    }

    pub fn state(&self) -> TestState {
        GatewayState {
            config: self.config.clone(),
            keys: self.keys.clone(),
            nonces: self.nonces.clone(),
            clock: self.clock.clone(),
        }
    }

    pub fn app(&self) -> Router {
        gateway::app(self.state())
    }

    pub fn probe(&self) -> Probe {
        let calls = Arc::new(AtomicUsize::new(0));
        let top = Router::new()
            .merge(probe_routes(calls.clone()))
            .nest("/api", probe_routes(calls.clone()))
            .nest("/elsewhere", probe_routes(calls.clone()));
        Probe {
            router: gateway::authenticated(top, self.state()),
            calls,
        }
    }

    /// Probe routes whose authentication layer sits inside each `nest`, so the
    /// layer sees the prefix-stripped URI and must verify the original path.
    pub fn nested_probe(&self) -> Probe {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .nest(
                "/api",
                gateway::authenticated(probe_routes(calls.clone()), self.state()),
            )
            .nest(
                "/elsewhere",
                gateway::authenticated(probe_routes(calls.clone()), self.state()),
            );
        Probe { router, calls }
    }
}

pub struct Probe {
    pub router: Router,
    pub calls: Arc<AtomicUsize>,
}

impl Probe {
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn probe_routes(calls: Arc<AtomicUsize>) -> Router {
    Router::new()
        .route("/probe", any(echo))
        .route("/probe2", any(echo))
        .with_state(calls)
}

async fn echo(State(calls): State<Arc<AtomicUsize>>, body: Bytes) -> Bytes {
    calls.fetch_add(1, Ordering::SeqCst);
    body
}

pub struct Req {
    pub method: &'static str,
    pub path: String,
    pub query: Option<String>,
    pub host: String,
    pub body: Vec<u8>,
    pub created: u64,
    pub nonce: String,
    pub keyid: String,
    pub expires: Option<u64>,
    pub key: SigningKey,
}

impl Req {
    pub fn new(method: &'static str, path: &str) -> Self {
        Self {
            method,
            path: path.to_string(),
            query: None,
            host: AUTHORITY.to_string(),
            body: Vec::new(),
            created: NOW,
            nonce: "nonce-1".to_string(),
            keyid: "bootstrap".to_string(),
            expires: None,
            key: registered_signing_key(),
        }
    }

    pub fn whoami() -> Self {
        Self::new("GET", "/v1/whoami")
    }

    pub fn body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }

    pub fn query(mut self, query: &str) -> Self {
        self.query = Some(query.to_string());
        self
    }

    pub fn host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    pub fn created(mut self, created: u64) -> Self {
        self.created = created;
        self
    }

    pub fn nonce(mut self, nonce: &str) -> Self {
        self.nonce = nonce.to_string();
        self
    }

    pub fn keyid(mut self, keyid: &str) -> Self {
        self.keyid = keyid.to_string();
        self
    }

    pub fn expires(mut self, expires: u64) -> Self {
        self.expires = Some(expires);
        self
    }

    pub fn key(mut self, key: SigningKey) -> Self {
        self.key = key;
        self
    }

    pub fn content_digest(&self) -> String {
        content_digest(&self.body)
    }

    pub fn signature_params(&self) -> String {
        let mut params = format!(
            "(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\");created={};nonce=\"{}\";keyid=\"{}\"",
            self.created, self.nonce, self.keyid
        );
        if let Some(expires) = self.expires {
            params.push_str(&format!(";expires={expires}"));
        }
        params
    }

    pub fn signature_base(&self) -> String {
        format!(
            "\"@method\": {}\n\"@authority\": {}\n\"@path\": {}\n\"@query\": ?{}\n\"content-digest\": {}\n\"@signature-params\": {}",
            self.method,
            self.host.to_ascii_lowercase(),
            self.path,
            self.query.as_deref().unwrap_or(""),
            self.content_digest(),
            self.signature_params()
        )
    }

    pub fn build(&self) -> Request<Body> {
        let signature = self.key.sign(self.signature_base().as_bytes());
        let uri = match &self.query {
            Some(query) => format!("{}?{}", self.path, query),
            None => self.path.clone(),
        };
        Request::builder()
            .method(self.method)
            .uri(uri)
            .header("host", &self.host)
            .header("content-digest", self.content_digest())
            .header(
                "signature-input",
                format!("sig1={}", self.signature_params()),
            )
            .header(
                "signature",
                format!("sig1=:{}:", B64.encode(signature.to_bytes())),
            )
            .body(Body::from(self.body.clone()))
            .unwrap()
    }
}

pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", B64.encode(Sha256::digest(body)))
}

pub fn flip_signature_byte(req: &mut Request<Body>) {
    let value = req
        .headers()
        .get("signature")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let encoded = value
        .strip_prefix("sig1=:")
        .and_then(|rest| rest.strip_suffix(':'))
        .unwrap();
    let mut bytes = B64.decode(encoded).unwrap();
    bytes[0] ^= 0x01;
    let flipped = format!("sig1=:{}:", B64.encode(bytes));
    req.headers_mut()
        .insert("signature", HeaderValue::from_str(&flipped).unwrap());
}

pub async fn send(router: &Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec())
}

pub fn public_key_pem(key: &SigningKey) -> String {
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(key.verifying_key().as_bytes());
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        B64.encode(der)
    )
}
