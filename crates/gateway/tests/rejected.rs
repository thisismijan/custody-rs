mod common;

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use common::{Fixture, Req, content_digest, flip_signature_byte, send, unregistered_signing_key};

async fn assert_rejected(f: &Fixture, req: Request<Body>) {
    let probe = f.probe();
    let (status, _) = send(&probe.router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(probe.calls(), 0);
}

#[tokio::test]
async fn unsigned_request_is_rejected() {
    let f = Fixture::new();
    let req = Request::builder()
        .method("GET")
        .uri("/probe")
        .header("host", common::AUTHORITY)
        .body(Body::empty())
        .unwrap();
    assert_rejected(&f, req).await;
}

#[tokio::test]
async fn body_altered_after_signing_is_rejected() {
    let f = Fixture::new();
    let mut req = Req::new("POST", "/probe").body(b"original").build();
    *req.body_mut() = Body::from("tampered");
    assert_rejected(&f, req).await;
}

#[tokio::test]
async fn method_altered_after_signing_is_rejected() {
    let f = Fixture::new();
    let mut req = Req::new("POST", "/probe").body(b"payload").build();
    *req.method_mut() = "PUT".parse().unwrap();
    assert_rejected(&f, req).await;
}

#[tokio::test]
async fn authority_altered_after_signing_is_rejected() {
    let f = Fixture::new();
    let mut req = Req::new("GET", "/probe").build();
    req.headers_mut()
        .insert("host", HeaderValue::from_static("other.test"));
    assert_rejected(&f, req).await;
}

#[tokio::test]
async fn request_signed_for_another_gateway_is_rejected() {
    let f = Fixture::new();
    let req = Req::new("GET", "/probe").host("other.test").build();
    assert_rejected(&f, req).await;
}

#[tokio::test]
async fn extra_content_digest_line_for_an_altered_body_is_rejected() {
    let f = Fixture::new();
    let mut req = Req::new("POST", "/probe").body(b"original").build();
    *req.body_mut() = Body::from("altered");
    req.headers_mut().append(
        "content-digest",
        HeaderValue::from_str(&content_digest(b"altered")).unwrap(),
    );
    assert_rejected(&f, req).await;
}

#[tokio::test]
async fn path_altered_after_signing_is_rejected() {
    let f = Fixture::new();
    let mut req = Req::new("GET", "/probe").build();
    *req.uri_mut() = "/probe2".parse().unwrap();
    assert_rejected(&f, req).await;
}

#[tokio::test]
async fn query_altered_after_signing_is_rejected() {
    let f = Fixture::new();
    let mut req = Req::new("GET", "/probe").query("a=1").build();
    *req.uri_mut() = "/probe?a=2".parse().unwrap();
    assert_rejected(&f, req).await;
}

#[tokio::test]
async fn signature_with_one_byte_changed_is_rejected() {
    let f = Fixture::new();
    let mut req = Req::new("GET", "/probe").build();
    flip_signature_byte(&mut req);
    assert_rejected(&f, req).await;
}

#[tokio::test]
async fn request_signed_by_an_unknown_key_is_rejected() {
    let f = Fixture::new();
    let req = Req::new("GET", "/probe")
        .keyid("stranger")
        .key(unregistered_signing_key())
        .build();
    assert_rejected(&f, req).await;
}

#[tokio::test]
async fn rejections_do_not_reveal_the_failed_check() {
    let f = Fixture::new();
    let app = f.app();

    let unsigned = Request::builder()
        .method("GET")
        .uri("/v1/whoami")
        .header("host", common::AUTHORITY)
        .body(Body::empty())
        .unwrap();

    let mut body_altered = Req::new("POST", "/v1/whoami").body(b"original").build();
    *body_altered.body_mut() = Body::from("tampered");

    let unknown_key = Req::whoami()
        .keyid("stranger")
        .key(unregistered_signing_key())
        .build();

    let (s1, b1) = send(&app, unsigned).await;
    let (s2, b2) = send(&app, body_altered).await;
    let (s3, b3) = send(&app, unknown_key).await;

    assert_eq!(s1, StatusCode::UNAUTHORIZED);
    assert_eq!(s2, StatusCode::UNAUTHORIZED);
    assert_eq!(s3, StatusCode::UNAUTHORIZED);
    assert_eq!(b1, br#"{"error":"unauthorized"}"#);
    assert_eq!(b1, b2);
    assert_eq!(b2, b3);
}
