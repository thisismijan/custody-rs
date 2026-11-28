mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use common::{Req, public_key_pem, registered_signing_key};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("gateway-startup-{}-{}", std::process::id(), label));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn gateway_command(key_file: &Path, listen: &str, authority: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gateway"));
    cmd.env_clear()
        .env("GATEWAY_BOOTSTRAP_KEY_FILE", key_file)
        .env("GATEWAY_LISTEN_ADDR", listen)
        .env("GATEWAY_AUTHORITY", authority);
    cmd
}

fn raw_get(addr: &str, req: &axum::http::Request<axum::body::Body>) -> (u16, serde_json::Value) {
    let mut wire = format!("{} {} HTTP/1.1\r\n", req.method(), req.uri());
    for (name, value) in req.headers() {
        wire.push_str(&format!("{}: {}\r\n", name, value.to_str().unwrap()));
    }
    wire.push_str("connection: close\r\n\r\n");

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(wire.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();

    let status = response
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .unwrap_or_else(|| panic!("unexpected response: {response}"))
        .parse()
        .unwrap();
    let start = response.find('{').unwrap_or(0);
    let end = response.rfind('}').map(|i| i + 1).unwrap_or(0);
    let json = serde_json::from_str(&response[start..end]).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[test]
fn gateway_started_with_a_valid_key_file_serves_signed_whoami() {
    let dir = TempDir::new("valid");
    let key_file = dir.path().join("bootstrap.pem");
    std::fs::write(&key_file, public_key_pem(&registered_signing_key())).unwrap();

    let port = free_port();
    let authority = format!("127.0.0.1:{port}");
    let mut child = gateway_command(&key_file, &authority, &authority)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = Running(child);

    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).unwrap();
    let bound = line
        .trim_end()
        .strip_prefix("gateway listening on ")
        .unwrap_or_else(|| panic!("unexpected startup line: {line:?}"))
        .to_string();

    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let req = Req::whoami().host(&authority).created(created).build();
    let (status, json) = raw_get(&bound, &req);

    assert_eq!(status, 200);
    assert_eq!(json["client_id"], "bootstrap");
}

#[test]
fn gateway_refuses_to_start_when_the_key_file_is_missing() {
    let dir = TempDir::new("missing");
    let key_file = dir.path().join("does-not-exist.pem");

    let output = gateway_command(&key_file, "127.0.0.1:0", "localhost:8080")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(key_file.to_str().unwrap()),
        "stderr was: {stderr}"
    );
}

#[test]
fn gateway_refuses_to_start_when_the_key_file_is_invalid() {
    let dir = TempDir::new("invalid");
    let key_file = dir.path().join("bootstrap.pem");
    std::fs::write(&key_file, "this is not a public key\n").unwrap();

    let output = gateway_command(&key_file, "127.0.0.1:0", "localhost:8080")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(key_file.to_str().unwrap()),
        "stderr was: {stderr}"
    );
}
