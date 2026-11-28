mod common;

use axum::http::StatusCode;
use common::{Fixture, NOW, Req, flip_signature_byte, send};

#[tokio::test]
async fn same_request_sent_twice_is_accepted_only_once() {
    let f = Fixture::new();
    let probe = f.probe();
    let req = Req::new("POST", "/probe").body(b"once");

    let (first, _) = send(&probe.router, req.build()).await;
    let (second, _) = send(&probe.router, req.build()).await;

    assert_eq!(first, StatusCode::OK);
    assert_eq!(second, StatusCode::UNAUTHORIZED);
    assert_eq!(probe.calls(), 1);
}

#[tokio::test]
async fn created_time_61_seconds_old_is_rejected() {
    let f = Fixture::new();
    let probe = f.probe();
    let req = Req::new("GET", "/probe").created(NOW - 61).build();

    let (status, _) = send(&probe.router, req).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(probe.calls(), 0);
}

#[tokio::test]
async fn created_time_6_seconds_in_the_future_is_rejected() {
    let f = Fixture::new();
    let probe = f.probe();
    let req = Req::new("GET", "/probe").created(NOW + 6).build();

    let (status, _) = send(&probe.router, req).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(probe.calls(), 0);
}

#[tokio::test]
async fn created_time_4_seconds_in_the_future_is_accepted() {
    let f = Fixture::new();
    let probe = f.probe();
    let req = Req::new("GET", "/probe").created(NOW + 4).build();

    let (status, _) = send(&probe.router, req).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(probe.calls(), 1);
}

#[tokio::test]
async fn expired_signature_is_rejected() {
    let f = Fixture::new();
    let probe = f.probe();
    let req = Req::new("GET", "/probe").expires(NOW - 1).build();

    let (status, _) = send(&probe.router, req).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(probe.calls(), 0);
}

#[tokio::test]
async fn rejected_request_does_not_use_up_its_nonce() {
    let f = Fixture::new();
    let probe = f.probe();

    let mut forged = Req::new("GET", "/probe").nonce("shared-nonce").build();
    flip_signature_byte(&mut forged);
    let (rejected, _) = send(&probe.router, forged).await;
    assert_eq!(rejected, StatusCode::UNAUTHORIZED);

    let valid = Req::new("GET", "/probe").nonce("shared-nonce").build();
    let (accepted, _) = send(&probe.router, valid).await;

    assert_eq!(accepted, StatusCode::OK);
    assert_eq!(probe.calls(), 1);
}

#[tokio::test]
async fn signature_expiring_exactly_now_is_rejected() {
    let f = Fixture::new();
    let probe = f.probe();
    let req = Req::new("GET", "/probe").expires(NOW).build();

    let (status, _) = send(&probe.router, req).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(probe.calls(), 0);
}
