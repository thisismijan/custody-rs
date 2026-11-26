use std::future::Future;
use std::sync::Arc;

use axum::Router;
use ed25519_dalek::VerifyingKey;

#[derive(Clone, Debug)]
pub struct RegisteredKey {
    pub key_id: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub public_key: VerifyingKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

pub struct InMemoryKeyStore;

impl InMemoryKeyStore {
    pub fn new(_keys: Vec<RegisteredKey>) -> Self {
        Self
    }
}

impl KeyStore for InMemoryKeyStore {
    async fn get(&self, _key_id: &str) -> Option<RegisteredKey> {
        None
    }
}

pub struct InMemoryNonceStore;

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self
    }

    pub fn prune(&self, _now: u64) {}

    pub fn contains(&self, _key_id: &str, _nonce: &str) -> bool {
        false
    }
}

impl Default for InMemoryNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceStore for InMemoryNonceStore {
    async fn record_if_new(&self, _key_id: &str, _nonce: &str, _created: u64, _now: u64) -> bool {
        false
    }
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        0
    }
}

pub fn app<K: KeyStore, N: NonceStore, C: Clock>(_state: GatewayState<K, N, C>) -> Router {
    Router::new()
}

pub fn authenticated<K: KeyStore, N: NonceStore, C: Clock>(
    _router: Router,
    _state: GatewayState<K, N, C>,
) -> Router {
    Router::new()
}
