//! HTTP-level integration coverage for the OCI blob upload `Range` response
//! header (issue #1410, follow-up to #1345/#1349).
//!
//! `upload_progress_range()` already has strong unit coverage, but nothing
//! previously drove a real request/response cycle through
//! `handle_start_upload` / `handle_patch_upload` to pin the actual `Range`
//! header value a client observes. A refactor that dropped the helper call
//! and inlined `format!("0-{}", new_bytes)` again would regress silently.
//! This file exercises `POST /v2/<name>/blobs/uploads/`, `PATCH
//! /v2/<name>/blobs/uploads/<uuid>`, and the resume contract where a client
//! honors the returned inclusive `Range` to pick the next `Content-Range`
//! offset.
//!
//! Requires a PostgreSQL database with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test oci_upload_range_test -- --ignored
//! ```

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::oci_v2;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;

// ===========================================================================
// Test helpers
//
// Duplicated (rather than shared) from oci_chunked_upload_cross_repo_tests.rs:
// `test_db_helpers` is `pub(crate)` inside the library crate and not visible
// to this external `backend/tests/*` crate, and this file is narrow enough
// that a new shared test-support module isn't worth the extra surface.
// ===========================================================================

fn test_config(storage_path: &str) -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        ..Default::default()
    }
}

fn basic_auth_header(username: &str, password: &str) -> String {
    use base64::Engine;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password));
    format!("Basic {}", encoded)
}

async fn create_test_user(pool: &PgPool, username: &str, password: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash = bcrypt::hash(password, 4).expect("bcrypt hash failed");
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active)
        VALUES ($1, $2, $3, $4, 'local', true, true)
        "#,
    )
    .bind(id)
    .bind(username)
    .bind(format!("{}@test.local", username))
    .bind(&hash)
    .execute(pool)
    .await
    .expect("failed to create test user");
    id
}

/// Create a docker-format local repo. Returns (repo_id, key, storage_path).
async fn create_docker_repo(pool: &PgPool, label: &str) -> (Uuid, String, PathBuf) {
    let id = Uuid::new_v4();
    let key = format!("oci1410-{}-{}", label, &id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("oci1410-{}", id));
    std::fs::create_dir_all(&storage_path).expect("create storage dir");
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
         VALUES ($1, $2, $2, $3, 'local', 'docker'::repository_format, true)",
    )
    .bind(id)
    .bind(&key)
    .bind(storage_path.to_string_lossy().as_ref())
    .execute(pool)
    .await
    .expect("insert docker repo");
    (id, key, storage_path)
}

fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(
        test_config(storage_path),
        pool,
        storage,
        registry,
    ))
}

async fn cleanup(pool: &PgPool, repo_ids: &[Uuid], user_id: Uuid, storage_dirs: &[PathBuf]) {
    for id in repo_ids {
        sqlx::query("DELETE FROM oci_upload_sessions WHERE repository_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM oci_blobs WHERE repository_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .ok();
    for dir in storage_dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Parse a `Range: <start>-<end>` response header into `(start, end)`.
fn parse_range_header(value: &str) -> (i64, i64) {
    let (start, end) = value
        .split_once('-')
        .expect("Range header must be start-end");
    (
        start.parse().expect("Range start must be an integer"),
        end.parse().expect("Range end must be an integer"),
    )
}

/// Deterministic, non-zero filler bytes so digests differ per length.
fn filler_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

// ===========================================================================
// Issue #1410: HTTP-level coverage for the OCI blob upload `Range` response
// header, pinning the inclusive-range contract outside of the pure
// `upload_progress_range()` unit tests.
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_upload_start_range_header_for_various_body_lengths() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("oci1410-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "pushpass").await;
    let (repo_id, key, storage_path) = create_docker_repo(&pool, "start").await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "pushpass");

    let make_app = || oci_v2::router().with_state(state.clone());

    for len in [1usize, 2, 4435] {
        let body = filler_bytes(len);
        let req = Request::builder()
            .method("POST")
            .uri(format!("/{}/range-len-{}/blobs/uploads/", key, len))
            .header("Authorization", &auth)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", body.len().to_string())
            .body(Body::from(body.clone()))
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "POST start with a {}-byte body should return 202: {}",
            len,
            String::from_utf8_lossy(&body_bytes)
        );
        assert!(
            headers.get("Docker-Upload-UUID").is_some(),
            "202 response must carry Docker-Upload-UUID for a {}-byte start",
            len
        );
        assert_eq!(
            headers
                .get("Range")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
            format!("0-{}", len - 1),
            "Range header must be the inclusive span of a {}-byte initial body",
            len
        );
    }

    // Empty start preserves the existing helper contract: Range must be "0-0".
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{}/range-empty/blobs/uploads/", key))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert_eq!(
        resp.headers()
            .get("Range")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default(),
        "0-0",
        "empty POST start must report Range: 0-0"
    );

    cleanup(&pool, &[repo_id], user_id, &[storage_path]).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_patch_chunk_range_header_is_cumulative() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("oci1410-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "pushpass").await;
    let (repo_id, key, storage_path) = create_docker_repo(&pool, "patch").await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "pushpass");

    let make_app = || oci_v2::router().with_state(state.clone());

    // Empty POST start so every PATCH below exercises the chunk-upload path.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{}/myimage/blobs/uploads/", key))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let session_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM oci_upload_sessions WHERE repository_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("session row must exist after POST start");

    // Table of PATCH chunk lengths; Range must reflect the cumulative total
    // received so far after each successful PATCH, not just the latest chunk.
    let chunk_lens = [1usize, 2, 4435];
    let mut cumulative = 0usize;
    for len in chunk_lens {
        let chunk = filler_bytes(len);
        let req = Request::builder()
            .method("PATCH")
            .uri(format!("/{}/myimage/blobs/uploads/{}", key, session_id))
            .header("Authorization", &auth)
            .header("Content-Length", chunk.len().to_string())
            .body(Body::from(chunk.clone()))
            .unwrap();
        let resp = make_app().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "PATCH chunk of {} bytes should return 202: {}",
            len,
            String::from_utf8_lossy(&body_bytes)
        );
        cumulative += len;
        assert_eq!(
            headers
                .get("Range")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
            format!("0-{}", cumulative - 1),
            "Range after a {}-byte PATCH must cover the cumulative {} bytes received",
            len,
            cumulative
        );
    }

    cleanup(&pool, &[repo_id], user_id, &[storage_path]).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_patch_resume_contract_uses_returned_range_for_next_offset() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("oci1410-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "pushpass").await;
    let (repo_id, key, storage_path) = create_docker_repo(&pool, "resume").await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "pushpass");

    let make_app = || oci_v2::router().with_state(state.clone());

    // Empty POST start.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{}/myimage/blobs/uploads/", key))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let session_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM oci_upload_sessions WHERE repository_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("session row must exist after POST start");

    // First PATCH chunk.
    let first = b"abcd".to_vec();
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/myimage/blobs/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .header("Content-Length", first.len().to_string())
        .body(Body::from(first.clone()))
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let range = resp
        .headers()
        .get("Range")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        range, "0-3",
        "first PATCH Range must be 0-3 for a 4-byte chunk"
    );
    let (_, first_end) = parse_range_header(&range);

    // Resume: the client computes the next Content-Range strictly from the
    // server's returned inclusive Range, never from a locally tracked offset
    // (that's the whole point of the resume contract this issue pins).
    let next_start = first_end + 1;
    let second = b"efghijkl".to_vec();
    let next_end = next_start + second.len() as i64 - 1;
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/myimage/blobs/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .header("Content-Length", second.len().to_string())
        .header("Content-Range", format!("{}-{}", next_start, next_end))
        .body(Body::from(second.clone()))
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "resume PATCH honoring the returned Range should succeed: {}",
        String::from_utf8_lossy(&body_bytes)
    );

    let mut combined = first.clone();
    combined.extend_from_slice(&second);
    assert_eq!(
        headers
            .get("Range")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default(),
        format!("0-{}", combined.len() - 1),
        "Range after the resume PATCH must cover all bytes received so far"
    );

    // Complete the upload with the digest of the concatenated bytes.
    let digest = format!("sha256:{}", sha256_hex(&combined));
    let req = Request::builder()
        .method("PUT")
        .uri(format!(
            "/{}/myimage/blobs/uploads/{}?digest={}",
            key, session_id, digest
        ))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "PUT complete with the digest of the concatenated resumed bytes should return 201: {}",
        String::from_utf8_lossy(&body_bytes)
    );

    let blob_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
    )
    .bind(repo_id)
    .bind(&digest)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        blob_rows, 1,
        "oci_blobs row must be recorded for the resumed upload"
    );

    cleanup(&pool, &[repo_id], user_id, &[storage_path]).await;
}
