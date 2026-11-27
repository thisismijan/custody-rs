mod common;

use axum::http::StatusCode;
use common::{Fixture, Req, send};

#[tokio::test]
async fn signed_whoami_from_the_bootstrap_key_returns_its_identity() {
    let f = Fixture::new();
    let (status, body) = send(&f.app(), Req::whoami().build()).await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["client_id"], "bootstrap");
    assert_eq!(json["key_id"], "bootstrap");
    assert_eq!(json["scopes"], serde_json::json!(["bootstrap"]));
}

#[tokio::test]
async fn signed_request_with_a_body_reaches_its_handler() {
    let f = Fixture::new();
    let probe = f.probe();
    let req = Req::new("POST", "/probe").body(b"hello custody").build();

    let (status, body) = send(&probe.router, req).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"hello custody");
    assert_eq!(probe.calls(), 1);
}

#[tokio::test]
async fn signed_request_under_a_path_prefix_is_verified_over_the_full_path() {
    let f = Fixture::new();
    let probe = f.probe();

    let (status, _) = send(&probe.router, Req::new("GET", "/api/probe").build()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(probe.calls(), 1);

    let mut moved = Req::new("GET", "/api/probe").nonce("nonce-2").build();
    *moved.uri_mut() = "/elsewhere/probe".parse().unwrap();
    let (status, _) = send(&probe.router, moved).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(probe.calls(), 1);
}

#[tokio::test]
async fn layer_inside_a_nested_router_verifies_the_full_received_path() {
    let f = Fixture::new();
    let probe = f.nested_probe();

    let (status, _) = send(&probe.router, Req::new("GET", "/api/probe").build()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(probe.calls(), 1);

    let mut moved = Req::new("GET", "/api/probe").nonce("nonce-2").build();
    *moved.uri_mut() = "/elsewhere/probe".parse().unwrap();
    let (status, _) = send(&probe.router, moved).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let mut stripped = Req::new("GET", "/probe").nonce("nonce-3").build();
    *stripped.uri_mut() = "/api/probe".parse().unwrap();
    let (status, _) = send(&probe.router, stripped).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(probe.calls(), 1);
}
