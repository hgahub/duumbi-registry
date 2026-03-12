//! End-to-end integration tests for the registry server.
//!
//! Each test spins up an embedded axum server with an in-memory SQLite
//! database and a temp directory for storage, then exercises the API
//! via reqwest HTTP calls.

use std::net::SocketAddr;
use std::sync::Arc;

use duumbi_registry::{build_app, db::Database, storage::Storage, AppState};
use reqwest::Client;
use tempfile::TempDir;
use tokio::net::TcpListener;

/// Starts an embedded test server, returns (base_url, token, temp_dir).
///
/// The temp_dir must be kept alive for the duration of the test.
async fn start_test_server() -> (String, String, TempDir) {
    let tmp = TempDir::new().expect("temp dir");

    let database = Database::open(":memory:").expect("in-memory db");
    database.migrate().expect("migration");

    // Create a test token
    let token = "test_token_abc123";
    database
        .create_token("testuser", token)
        .expect("create token");

    let storage = Storage::new(tmp.path().join("modules").to_str().unwrap()).expect("storage");

    let state = Arc::new(AppState {
        db: database,
        storage,
    });

    let app = build_app(state);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind to random port");
    let addr: SocketAddr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let base = format!("http://{addr}");
    (base, token.to_string(), tmp)
}

/// Creates a minimal .tar.gz archive containing a manifest.toml.
fn make_test_tarball(name: &str, version: &str, description: &str) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let manifest = format!(
        r#"name = "{name}"
version = "{version}"
description = "{description}"
"#
    );

    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut tar = tar::Builder::new(&mut enc);
        let manifest_bytes = manifest.as_bytes();

        let mut header = tar::Header::new_gnu();
        header.set_size(manifest_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();

        tar.append_data(&mut header, "manifest.toml", manifest_bytes)
            .expect("append manifest");
        tar.finish().expect("finish tar");
    }

    enc.finish().expect("finish gzip")
}

// ---------------------------------------------------------------------------
// Test 1: Health check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_check() {
    let (base, _token, _tmp) = start_test_server().await;
    let client = Client::new();

    let resp = client
        .get(format!("{base}/health"))
        .send()
        .await
        .expect("health");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

// ---------------------------------------------------------------------------
// Test 2: Publish -> Fetch -> Download round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_fetch_download() {
    let (base, token, _tmp) = start_test_server().await;
    let client = Client::new();

    let tarball = make_test_tarball("@test/hello", "1.0.0", "A hello module");

    // Publish
    let resp = client
        .put(format!("{base}/api/v1/modules/@test/hello"))
        .header("Authorization", format!("Bearer {token}"))
        .body(tarball.clone())
        .send()
        .await
        .expect("publish");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "@test/hello");
    assert_eq!(body["version"], "1.0.0");

    // Fetch module info
    let resp = client
        .get(format!("{base}/api/v1/modules/@test/hello"))
        .send()
        .await
        .expect("fetch");
    assert_eq!(resp.status(), 200);

    let info: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(info["name"], "@test/hello");
    assert_eq!(info["description"], "A hello module");
    assert_eq!(info["versions"][0]["version"], "1.0.0");
    assert!(!info["versions"][0]["yanked"].as_bool().unwrap());
    assert!(info["versions"][0]["integrity"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    // Download
    let resp = client
        .get(format!("{base}/api/v1/modules/@test/hello/1.0.0/download"))
        .send()
        .await
        .expect("download");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/gzip"
    );

    let downloaded = resp.bytes().await.unwrap();
    assert_eq!(downloaded.as_ref(), tarball.as_slice());
}

// ---------------------------------------------------------------------------
// Test 3: SemVer — multiple versions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multiple_versions() {
    let (base, token, _tmp) = start_test_server().await;
    let client = Client::new();

    // Publish three versions
    for ver in &["1.0.0", "1.1.0", "2.0.0"] {
        let tarball = make_test_tarball("@test/multi", ver, "Multi-version module");
        let resp = client
            .put(format!("{base}/api/v1/modules/@test/multi"))
            .header("Authorization", format!("Bearer {token}"))
            .body(tarball)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "publish {ver}");
    }

    // Fetch — should show all 3 versions
    let resp = client
        .get(format!("{base}/api/v1/modules/@test/multi"))
        .send()
        .await
        .unwrap();
    let info: serde_json::Value = resp.json().await.unwrap();
    let versions: Vec<&str> = info["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions.len(), 3);
    // Newest first (ordered by published_at DESC)
    assert_eq!(versions[0], "2.0.0");
}

// ---------------------------------------------------------------------------
// Test 4: Duplicate version rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn duplicate_version_rejected() {
    let (base, token, _tmp) = start_test_server().await;
    let client = Client::new();

    let tarball = make_test_tarball("@test/dup", "1.0.0", "First publish");

    // First publish — OK
    let resp = client
        .put(format!("{base}/api/v1/modules/@test/dup"))
        .header("Authorization", format!("Bearer {token}"))
        .body(tarball.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Second publish — conflict
    let resp = client
        .put(format!("{base}/api/v1/modules/@test/dup"))
        .header("Authorization", format!("Bearer {token}"))
        .body(tarball)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

// ---------------------------------------------------------------------------
// Test 5: Yank
// ---------------------------------------------------------------------------

#[tokio::test]
async fn yank_version() {
    let (base, token, _tmp) = start_test_server().await;
    let client = Client::new();

    let tarball = make_test_tarball("@test/yankme", "1.0.0", "Will be yanked");
    client
        .put(format!("{base}/api/v1/modules/@test/yankme"))
        .header("Authorization", format!("Bearer {token}"))
        .body(tarball)
        .send()
        .await
        .unwrap();

    // Yank
    let resp = client
        .delete(format!("{base}/api/v1/modules/@test/yankme/1.0.0"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Verify yanked flag
    let resp = client
        .get(format!("{base}/api/v1/modules/@test/yankme"))
        .send()
        .await
        .unwrap();
    let info: serde_json::Value = resp.json().await.unwrap();
    assert!(info["versions"][0]["yanked"].as_bool().unwrap());
}

// ---------------------------------------------------------------------------
// Test 6: Search
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_modules() {
    let (base, token, _tmp) = start_test_server().await;
    let client = Client::new();

    // Publish two modules
    let t1 = make_test_tarball("@test/math-utils", "1.0.0", "Math utility functions");
    client
        .put(format!("{base}/api/v1/modules/@test/math-utils"))
        .header("Authorization", format!("Bearer {token}"))
        .body(t1)
        .send()
        .await
        .unwrap();

    let t2 = make_test_tarball("@test/string-utils", "1.0.0", "String utility functions");
    client
        .put(format!("{base}/api/v1/modules/@test/string-utils"))
        .header("Authorization", format!("Bearer {token}"))
        .body(t2)
        .send()
        .await
        .unwrap();

    // Search by name
    let resp = client
        .get(format!("{base}/api/v1/search?q=math"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["name"], "@test/math-utils");

    // Search by description
    let resp = client
        .get(format!("{base}/api/v1/search?q=utility"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["results"].as_array().unwrap().len(), 2);
}

// ---------------------------------------------------------------------------
// Test 7: Auth — missing token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_required_for_publish() {
    let (base, _token, _tmp) = start_test_server().await;
    let client = Client::new();

    let tarball = make_test_tarball("@test/noauth", "1.0.0", "No auth");

    // No token → 401
    let resp = client
        .put(format!("{base}/api/v1/modules/@test/noauth"))
        .body(tarball.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Invalid token → 401
    let resp = client
        .put(format!("{base}/api/v1/modules/@test/noauth"))
        .header("Authorization", "Bearer bad_token_xyz")
        .body(tarball)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ---------------------------------------------------------------------------
// Test 8: Auth — missing token for yank
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_required_for_yank() {
    let (base, token, _tmp) = start_test_server().await;
    let client = Client::new();

    let tarball = make_test_tarball("@test/yankauth", "1.0.0", "Auth test");
    client
        .put(format!("{base}/api/v1/modules/@test/yankauth"))
        .header("Authorization", format!("Bearer {token}"))
        .body(tarball)
        .send()
        .await
        .unwrap();

    // No token → 401
    let resp = client
        .delete(format!("{base}/api/v1/modules/@test/yankauth/1.0.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ---------------------------------------------------------------------------
// Test 9: 404 for nonexistent module
// ---------------------------------------------------------------------------

#[tokio::test]
async fn not_found_for_nonexistent() {
    let (base, _token, _tmp) = start_test_server().await;
    let client = Client::new();

    let resp = client
        .get(format!("{base}/api/v1/modules/@test/doesnotexist"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Test 10: Web frontend pages return HTML
// ---------------------------------------------------------------------------

#[tokio::test]
async fn web_pages_return_html() {
    let (base, token, _tmp) = start_test_server().await;
    let client = Client::new();

    // Publish a module so the module page works
    let tarball = make_test_tarball("@test/webmod", "1.0.0", "Web test module");
    client
        .put(format!("{base}/api/v1/modules/@test/webmod"))
        .header("Authorization", format!("Bearer {token}"))
        .body(tarball)
        .send()
        .await
        .unwrap();

    // Landing page
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("duumbi registry"));

    // Search page
    let resp = client
        .get(format!("{base}/search?q=webmod"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    assert!(html.contains("@test/webmod"));

    // Module page
    let resp = client
        .get(format!("{base}/@test/webmod"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    assert!(html.contains("@test/webmod"));
    assert!(html.contains("1.0.0"));

    // Version page
    let resp = client
        .get(format!("{base}/@test/webmod/1.0.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    assert!(html.contains("1.0.0"));
    assert!(html.contains("sha256:"));

    // Publish guide
    let resp = client.get(format!("{base}/publish")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    assert!(html.contains("Publishing"));
}
