use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use ed25519_dalek::pkcs8::DecodePublicKey;
use gateway::{
    GatewayConfig, GatewayState, InMemoryKeyStore, InMemoryNonceStore, RegisteredKey, SystemClock,
};

const DEFAULT_KEY_FILE: &str = "/run/secrets/bootstrap_operator_public_key";
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_AUTHORITY: &str = "localhost:8080";

#[tokio::main]
async fn main() {
    if let Err(message) = run().await {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn load_bootstrap_key(path: &str) -> Result<VerifyingKey, String> {
    let fail = |reason: String| format!("gateway: cannot load bootstrap key from {path}: {reason}");
    let pem = std::fs::read_to_string(path).map_err(|e| fail(e.kind().to_string()))?;
    VerifyingKey::from_public_key_pem(&pem)
        .map_err(|_| fail("not a valid Ed25519 PEM public key".to_string()))
}

async fn run() -> Result<(), String> {
    let key_file = env_or("GATEWAY_BOOTSTRAP_KEY_FILE", DEFAULT_KEY_FILE);
    let public_key = load_bootstrap_key(&key_file)?;
    let listen_addr: SocketAddr = env_or("GATEWAY_LISTEN_ADDR", DEFAULT_LISTEN_ADDR)
        .parse()
        .map_err(|_| "gateway: GATEWAY_LISTEN_ADDR is not a socket address".to_string())?;

    let state = GatewayState {
        config: Arc::new(GatewayConfig {
            authority: env_or("GATEWAY_AUTHORITY", DEFAULT_AUTHORITY),
        }),
        keys: Arc::new(InMemoryKeyStore::new(vec![RegisteredKey {
            key_id: "bootstrap".to_string(),
            client_id: "bootstrap".to_string(),
            scopes: vec!["bootstrap".to_string()],
            public_key,
        }])),
        nonces: Arc::new(InMemoryNonceStore::new()),
        clock: Arc::new(SystemClock),
    };

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .map_err(|e| format!("gateway: cannot listen on {listen_addr}: {}", e.kind()))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("gateway: cannot read bound address: {}", e.kind()))?;
    println!("gateway listening on {bound}");

    axum::serve(listener, gateway::app(state))
        .await
        .map_err(|e| format!("gateway: server error: {}", e.kind()))
}
