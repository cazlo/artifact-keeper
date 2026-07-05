//! Integration tests for the age-based proxy quality gate.
//!
//! Requires PostgreSQL:
//!   DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!     cargo test --test age_gate_tests -- --ignored

use artifact_keeper_backend::models::repository::{RepositoryFormat, RepositoryType};
use artifact_keeper_backend::services::age_gate_service::{
    AgeGateDecision, AgeGateMode, AgeGateRepoParams, AgeGateService, AUTO_APPROVE_REASON,
};
use artifact_keeper_backend::services::event_bus::EventBus;
use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn connect_db() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set; see module docstring for setup");
    PgPool::connect(&url)
        .await
        .expect("failed to connect to test database")
}

async fn create_remote_npm_repo(pool: &PgPool, suffix: &str, min_age_days: i32) -> Uuid {
    let id = Uuid::new_v4();
    // Include the random id so the unique `repositories.key` constraint does not
    // collide with rows left behind by a previous (uncleaned) test run, keeping
    // these `--ignored` integration tests repeatable.
    let key = format!("age-gate-npm-{suffix}-{id}");
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url, age_gate_enabled, age_gate_min_age_days)
         VALUES ($1, $2, $2, $3, 'remote', 'npm', 'https://registry.npmjs.org', true, $4)",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("/tmp/test-artifacts/{id}"))
    .bind(min_age_days)
    .execute(pool)
    .await
    .expect("insert repo");
    id
}

fn npm_repo_params(id: Uuid, min_age_days: i32) -> AgeGateRepoParams {
    AgeGateRepoParams::from_parts(
        id,
        "age-gate-npm",
        RepositoryType::Remote,
        RepositoryFormat::Npm,
        true,
        min_age_days,
    )
}

async fn create_reviewer(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("age-gate-reviewer-{id}");
    let email = format!("{username}@test.local");
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active)
         VALUES ($1, $2, $3, 'unused', 'local', true, true)",
    )
    .bind(id)
    .bind(&username)
    .bind(&email)
    .execute(pool)
    .await
    .expect("insert reviewer");
    id
}

async fn insert_pending_review(
    pool: &PgPool,
    repo_id: Uuid,
    package: &str,
    version: &str,
    published_at: Option<DateTime<Utc>>,
) {
    sqlx::query(
        "INSERT INTO age_gate_reviews (repository_id, package_name, package_version, upstream_published_at, status)
         VALUES ($1, $2, $3, $4, 'pending')",
    )
    .bind(repo_id)
    .bind(package)
    .bind(version)
    .bind(published_at)
    .execute(pool)
    .await
    .expect("insert pending review");
}

async fn review_status(pool: &PgPool, repo_id: Uuid, package: &str, version: &str) -> String {
    let status: String = sqlx::query_scalar(
        "SELECT status FROM age_gate_reviews WHERE repository_id = $1 AND package_name = $2 AND package_version = $3",
    )
    .bind(repo_id)
    .bind(package)
    .bind(version)
    .fetch_one(pool)
    .await
    .expect("review status");
    status
}

fn young_packument(version: &str, published_at: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "debounce-pkg",
        "dist-tags": { "latest": version },
        "versions": { version: { "name": "debounce-pkg", "version": version } },
        "time": { version: published_at },
    })
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn young_version_is_blocked_and_queued() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_npm_repo(&pool, "young", 7).await;
    let params = npm_repo_params(repo_id, 7);

    let published = Utc::now() - Duration::days(1);
    let decision = svc
        .check(&params, "lodash", "4.18.2", Some(published))
        .await
        .expect("check");

    match decision {
        AgeGateDecision::Block { review_id, .. } => {
            let review = svc.get_review_by_id(review_id).await.expect("review");
            assert_eq!(review.status, "pending");
            assert_eq!(review.package_name, "lodash");
        }
        AgeGateDecision::Allow => panic!("expected block for young version"),
    }
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn lazy_auto_approve_after_threshold() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_npm_repo(&pool, "auto", 7).await;
    let params = npm_repo_params(repo_id, 7);

    let young = Utc::now() - Duration::days(1);
    assert!(matches!(
        svc.check(&params, "express", "4.18.2", Some(young))
            .await
            .expect("first check"),
        AgeGateDecision::Block { .. }
    ));

    let old = Utc::now() - Duration::days(10);
    assert!(matches!(
        svc.check(&params, "express", "4.18.2", Some(old))
            .await
            .expect("second check"),
        AgeGateDecision::Allow
    ));

    let review = sqlx::query(
        "SELECT status, review_reason FROM age_gate_reviews WHERE repository_id = $1 AND package_name = 'express' AND package_version = '4.18.2'",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("review row");
    let status: String = review.get("status");
    let review_reason: Option<String> = review.get("review_reason");
    assert_eq!(status, "approved");
    assert_eq!(review_reason.as_deref(), Some(AUTO_APPROVE_REASON));
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn rejected_review_stays_blocked_after_threshold() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_npm_repo(&pool, "reject", 7).await;
    let params = npm_repo_params(repo_id, 7);

    let young = Utc::now() - Duration::days(1);
    let decision = svc
        .check(&params, "left-pad", "1.0.0", Some(young))
        .await
        .expect("check");
    let review_id = match decision {
        AgeGateDecision::Block { review_id, .. } => review_id,
        AgeGateDecision::Allow => panic!("expected block"),
    };

    let reviewer = create_reviewer(&pool).await;
    svc.reject(review_id, reviewer, Some("too risky"))
        .await
        .expect("reject");

    let old = Utc::now() - Duration::days(30);
    assert!(matches!(
        svc.check(&params, "left-pad", "1.0.0", Some(old))
            .await
            .expect("recheck"),
        AgeGateDecision::Block { .. }
    ));
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn per_repo_threshold_is_respected() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo7 = create_remote_npm_repo(&pool, "d7", 7).await;
    let repo15 = create_remote_npm_repo(&pool, "d15", 15).await;

    let published = Utc::now() - Duration::days(10);
    assert!(matches!(
        svc.check(&npm_repo_params(repo7, 7), "pkg", "1.0.0", Some(published))
            .await
            .expect("repo7"),
        AgeGateDecision::Allow
    ));
    assert!(matches!(
        svc.check(
            &npm_repo_params(repo15, 15),
            "pkg",
            "1.0.0",
            Some(published)
        )
        .await
        .expect("repo15"),
        AgeGateDecision::Block { .. }
    ));
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn scheduler_sweep_auto_approves_only_aged_pending_reviews() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_npm_repo(&pool, "sweep", 7).await;

    // Aged pending review: the sweep should approve it.
    insert_pending_review(
        &pool,
        repo_id,
        "aged-pkg",
        "1.0.0",
        Some(Utc::now() - Duration::days(30)),
    )
    .await;
    // Young pending review: still under threshold, must stay pending.
    insert_pending_review(
        &pool,
        repo_id,
        "young-pkg",
        "2.0.0",
        Some(Utc::now() - Duration::days(1)),
    )
    .await;
    // No upstream timestamp: age cannot be proven, must stay pending (fail closed).
    insert_pending_review(&pool, repo_id, "notime-pkg", "3.0.0", None).await;

    let approved = svc.auto_approve_aged_reviews().await.expect("sweep");
    assert!(
        approved >= 1,
        "expected the sweep to approve at least the aged review"
    );

    assert_eq!(
        review_status(&pool, repo_id, "aged-pkg", "1.0.0").await,
        "approved"
    );
    assert_eq!(
        review_status(&pool, repo_id, "young-pkg", "2.0.0").await,
        "pending"
    );
    assert_eq!(
        review_status(&pool, repo_id, "notime-pkg", "3.0.0").await,
        "pending"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn metadata_filter_debounces_request_count() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_npm_repo(&pool, "debounce", 7).await;
    let params = npm_repo_params(repo_id, 7);

    let young = (Utc::now() - Duration::days(1)).to_rfc3339();

    // First listing creates the pending review (request_count = 1) and withholds 1.0.0.
    let mut p1 = young_packument("1.0.0", &young);
    svc.filter_npm_packument(&params, "debounce-pkg", &mut p1)
        .await
        .expect("filter 1");
    assert!(
        p1["versions"].get("1.0.0").is_none(),
        "young version must be withheld from the listing"
    );

    // Second listing within the debounce window must NOT re-bump request_count.
    let mut p2 = young_packument("1.0.0", &young);
    svc.filter_npm_packument(&params, "debounce-pkg", &mut p2)
        .await
        .expect("filter 2");
    assert!(
        p2["versions"].get("1.0.0").is_none(),
        "young version must still be withheld"
    );

    let count: i32 = sqlx::query_scalar(
        "SELECT request_count FROM age_gate_reviews WHERE repository_id = $1 AND package_name = 'debounce-pkg' AND package_version = '1.0.0'",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("request_count");
    assert_eq!(
        count, 1,
        "request_count must be debounced (not bumped on the second listing within the window)"
    );
}

// ===========================================================================
// Listing-path filtering against a mock upstream (hermetic, no internet).
//
// These exercise the metadata *listing* path end to end with realistic
// upstream payloads and deliberately controlled publish times (one version a
// day old, one ten years old), so they are reproducible without depending on
// real-world package release dates. The PyPI case in particular reproduces the
// `#sha256=` hash-fragment anchor that made `filter_pypi_simple_index` a silent
// no-op before the fragment-stripping fix.
// ===========================================================================

async fn create_remote_pypi_repo(
    pool: &PgPool,
    suffix: &str,
    upstream_url: &str,
    min_age_days: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("age-gate-pypi-{suffix}-{id}");
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url, age_gate_enabled, age_gate_min_age_days)
         VALUES ($1, $2, $2, $3, 'remote', 'pypi', $4, true, $5)",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("/tmp/test-artifacts/{id}"))
    .bind(upstream_url)
    .bind(min_age_days)
    .execute(pool)
    .await
    .expect("insert pypi repo");
    id
}

fn pypi_repo_params(id: Uuid, min_age_days: i32) -> AgeGateRepoParams {
    AgeGateRepoParams::from_parts(
        id,
        "age-gate-pypi",
        RepositoryType::Remote,
        RepositoryFormat::Pypi,
        true,
        min_age_days,
    )
}

/// A PEP 503 simple-index page exactly as the proxy serves it after rewriting:
/// repo-relative hrefs **carrying the `#sha256=` hash fragment**. The fragment
/// is the detail that made the filter a silent no-op — a fragment-less href (as
/// the parser's unit test used) parses fine, so only a realistic anchor catches
/// the regression.
fn pypi_simple_index_html(repo_key: &str, pkg: &str, versions: &[&str]) -> String {
    let mut body = String::from("<!DOCTYPE html><html><body>\n");
    for v in versions {
        let file = format!("{pkg}-{v}-py3-none-any.whl");
        body.push_str(&format!(
            "<a href=\"/pypi/{repo_key}/simple/{pkg}/{file}#sha256=deadbeefcafe\">{file}</a>\n"
        ));
    }
    body.push_str("</body></html>\n");
    body
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn pypi_simple_index_withholds_young_version_via_real_anchors() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);

    let pkg = "agegatepkg";
    let young = (Utc::now() - Duration::days(1)).to_rfc3339();
    let old = (Utc::now() - Duration::days(3650)).to_rfc3339();

    // Mock the PyPI JSON metadata endpoint the gate consults for publish times.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path(format!("/pypi/{pkg}/json")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "info": { "version": "9.9.9" },
            "releases": {
                "1.0.0": [{ "upload_time_iso_8601": old }],
                "9.9.9": [{ "upload_time_iso_8601": young }],
            }
        })))
        .mount(&server)
        .await;

    let repo_id = create_remote_pypi_repo(&pool, "listing", &server.uri(), 7).await;
    let params = pypi_repo_params(repo_id, 7);

    // Fetch publish times from the mock upstream exactly as the handler does,
    // then filter a realistic (rewritten, hash-fragmented) simple index.
    let client = reqwest::Client::new();
    let times = svc
        .metadata_cache()
        .fetch_pypi_publish_times(&client, repo_id, &server.uri(), pkg)
        .await
        .expect("fetch publish times");
    assert_eq!(
        times.len(),
        2,
        "mock upstream should yield two publish times"
    );

    let html = pypi_simple_index_html("age-gate-pypi", pkg, &["1.0.0", "9.9.9"]);
    let filtered = svc
        .filter_pypi_simple_index(&params, pkg, &times, &html)
        .await
        .expect("filter simple index");

    assert!(
        !filtered.contains(&format!("{pkg}-9.9.9-")),
        "young version must be withheld from the simple index (regression: #sha256 fragment)"
    );
    assert!(
        filtered.contains(&format!("{pkg}-1.0.0-")),
        "aged version must remain listed"
    );
    assert_eq!(
        review_status(&pool, repo_id, pkg, "9.9.9").await,
        "pending",
        "the withheld young version must be queued for review"
    );
}

/// A rewritten PEP 691 JSON simple index as `rewrite_upstream_simple_json`
/// produces it: proxied `url`s plus whatever PEP 700 `upload-time` values the
/// upstream provided (`None` omits the field, as non-Warehouse upstreams do).
fn pypi_simple_index_json(
    repo_key: &str,
    pkg: &str,
    versions: &[(&str, Option<&str>)],
) -> serde_json::Value {
    let files: Vec<serde_json::Value> = versions
        .iter()
        .map(|(v, upload_time)| {
            let file = format!("{pkg}-{v}-py3-none-any.whl");
            let mut entry = serde_json::json!({
                "filename": file,
                "url": format!("/pypi/{repo_key}/simple/{pkg}/{file}"),
                "hashes": { "sha256": "deadbeefcafe" },
            });
            if let Some(ts) = upload_time {
                entry["upload-time"] = serde_json::json!(ts);
            }
            entry
        })
        .collect();
    serde_json::json!({
        "meta": { "api-version": "1.1" },
        "name": pkg,
        "files": files,
        "versions": versions.iter().map(|(v, _)| *v).collect::<Vec<_>>(),
    })
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn pep691_json_index_withholds_young_version_using_document_upload_times() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);

    let pkg = "agegatejsonpkg";
    let young = (Utc::now() - Duration::days(1)).to_rfc3339();
    let old = (Utc::now() - Duration::days(3650)).to_rfc3339();

    // Every file carries PEP 700 upload-time, so the filter must decide from
    // the document alone — no upstream JSON metadata fetch (the upstream URL
    // below would fail any attempted fetch, which is the point).
    let repo_id = create_remote_pypi_repo(&pool, "json-listing", "http://127.0.0.1:9", 7).await;
    let params = pypi_repo_params(repo_id, 7);

    let mut index = pypi_simple_index_json(
        "age-gate-pypi",
        pkg,
        &[
            ("1.0.0", Some(old.as_str())),
            ("9.9.9", Some(young.as_str())),
        ],
    );
    svc.filter_pypi_simple_json(&params, pkg, "http://127.0.0.1:9", &mut index)
        .await
        .expect("filter PEP 691 simple index");

    let listed: Vec<&str> = index["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["filename"].as_str().unwrap())
        .collect();
    assert_eq!(
        listed,
        vec![format!("{pkg}-1.0.0-py3-none-any.whl")],
        "young version must be withheld from the JSON index, aged one kept"
    );
    assert_eq!(
        index["versions"],
        serde_json::json!(["1.0.0"]),
        "PEP 700 versions list must not reveal the withheld version"
    );
    assert_eq!(
        review_status(&pool, repo_id, pkg, "9.9.9").await,
        "pending",
        "the withheld young version must be queued for review"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn pep691_json_index_falls_back_to_upstream_json_for_missing_upload_times() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);

    let pkg = "agegatejsonfallbackpkg";
    let young = (Utc::now() - Duration::days(1)).to_rfc3339();
    let old = (Utc::now() - Duration::days(3650)).to_rfc3339();

    // Upstream that serves a PEP 691 index WITHOUT upload-time: the filter
    // must fall back to the JSON metadata endpoint for publish times, like
    // the HTML path always does.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path(format!("/pypi/{pkg}/json")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "info": { "version": "9.9.9" },
            "releases": {
                "1.0.0": [{ "upload_time_iso_8601": old }],
                "9.9.9": [{ "upload_time_iso_8601": young }],
            }
        })))
        .mount(&server)
        .await;

    let repo_id = create_remote_pypi_repo(&pool, "json-fallback", &server.uri(), 7).await;
    let params = pypi_repo_params(repo_id, 7);

    let mut index =
        pypi_simple_index_json("age-gate-pypi", pkg, &[("1.0.0", None), ("9.9.9", None)]);
    svc.filter_pypi_simple_json(&params, pkg, &server.uri(), &mut index)
        .await
        .expect("filter PEP 691 simple index with fallback times");

    let listed: Vec<&str> = index["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["filename"].as_str().unwrap())
        .collect();
    assert_eq!(
        listed,
        vec![format!("{pkg}-1.0.0-py3-none-any.whl")],
        "fallback publish times must drive the same withholding as document times"
    );
    assert_eq!(
        review_status(&pool, repo_id, pkg, "9.9.9").await,
        "pending",
        "the withheld young version must be queued for review"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn npm_packument_withholds_young_keeps_old_and_reconciles_tags() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_npm_repo(&pool, "listing", 7).await;
    let params = npm_repo_params(repo_id, 7);

    let young = (Utc::now() - Duration::days(1)).to_rfc3339();
    let old = (Utc::now() - Duration::days(3650)).to_rfc3339();
    let pkg = "agegatepkg";

    // npm carries publish times inline in the packument `time` map, so the
    // listing filter needs no upstream fetch — the document is self-contained.
    let mut packument = serde_json::json!({
        "name": pkg,
        "dist-tags": { "latest": "9.9.9", "stable": "1.0.0" },
        "versions": {
            "1.0.0": { "name": pkg, "version": "1.0.0" },
            "9.9.9": { "name": pkg, "version": "9.9.9" },
        },
        "time": {
            "created": old,
            "modified": young,
            "1.0.0": old,
            "9.9.9": young,
        }
    });

    svc.filter_npm_packument(&params, pkg, &mut packument)
        .await
        .expect("filter packument");

    assert!(
        packument["versions"].get("9.9.9").is_none(),
        "young version must be withheld from the packument"
    );
    assert!(
        packument["versions"].get("1.0.0").is_some(),
        "aged version must remain in the packument"
    );
    assert_eq!(
        packument["dist-tags"]["latest"],
        serde_json::json!("1.0.0"),
        "dist-tags.latest must be repointed to the newest surviving version"
    );
    assert_eq!(
        review_status(&pool, repo_id, pkg, "9.9.9").await,
        "pending",
        "the withheld young version must be queued for review"
    );
}

// ---------------------------------------------------------------------------
// first_seen mode + format expansion (Go, NuGet)
// ---------------------------------------------------------------------------

async fn create_remote_repo_with_mode(
    pool: &PgPool,
    suffix: &str,
    format: &str,
    upstream_url: &str,
    min_age_days: i32,
    mode: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("age-gate-{format}-{suffix}-{id}");
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url, age_gate_enabled, age_gate_min_age_days, age_gate_mode)
         VALUES ($1, $2, $2, $3, 'remote', $4::repository_format, $5, true, $6, $7)",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("/tmp/test-artifacts/{id}"))
    .bind(format)
    .bind(upstream_url)
    .bind(min_age_days)
    .bind(mode)
    .execute(pool)
    .await
    .expect("insert repo with mode");
    id
}

fn repo_params_with_mode(
    id: Uuid,
    key: &str,
    format: RepositoryFormat,
    min_age_days: i32,
    mode: AgeGateMode,
) -> AgeGateRepoParams {
    AgeGateRepoParams::from_parts(id, key, RepositoryType::Remote, format, true, min_age_days)
        .with_mode(mode)
}

/// Backdate a first-seen observation so a "locally aged" version can be
/// simulated without waiting out a real cooldown.
async fn backdate_observation(
    pool: &PgPool,
    repo_id: Uuid,
    package: &str,
    version: &str,
    days: i64,
) {
    sqlx::query(
        "UPDATE age_gate_version_observations
         SET first_seen_at = NOW() - make_interval(days => $4::int)
         WHERE repository_id = $1 AND package_name = $2 AND package_version = $3",
    )
    .bind(repo_id)
    .bind(package)
    .bind(version)
    .bind(days as i32)
    .execute(pool)
    .await
    .expect("backdate observation");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn first_seen_observation_is_stable_and_concurrency_safe() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_repo_with_mode(
        &pool,
        "obs",
        "nuget",
        "https://api.nuget.org/v3",
        7,
        "first_seen",
    )
    .await;

    let versions = vec!["1.0.0".to_string(), "2.0.0".to_string()];
    let first = svc
        .observe_versions_first_seen(repo_id, "demo", &versions)
        .await
        .expect("first observation");
    assert_eq!(first.len(), 2, "both versions observed");

    // Concurrent re-observations must neither error nor move the timestamps.
    let (a, b, c, d) = tokio::join!(
        svc.observe_versions_first_seen(repo_id, "demo", &versions),
        svc.observe_versions_first_seen(repo_id, "demo", &versions),
        svc.observe_versions_first_seen(repo_id, "demo", &versions),
        svc.observe_versions_first_seen(repo_id, "demo", &versions),
    );
    for map in [
        a.expect("concurrent observe"),
        b.expect("concurrent observe"),
        c.expect("concurrent observe"),
        d.expect("concurrent observe"),
    ] {
        assert_eq!(
            map, first,
            "first_seen_at must be stable across observations"
        );
    }

    let row_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM age_gate_version_observations
         WHERE repository_id = $1 AND package_name = 'demo'",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("count observations");
    assert_eq!(row_count, 2, "exactly one row per version");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn nuget_first_seen_blocks_until_local_age_crosses_threshold() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_repo_with_mode(
        &pool,
        "flat",
        "nuget",
        "https://api.nuget.org/v3",
        7,
        "first_seen",
    )
    .await;
    let params = repo_params_with_mode(
        repo_id,
        "age-gate-nuget-flat",
        RepositoryFormat::Nuget,
        7,
        AgeGateMode::FirstSeen,
    );
    let pkg = "contoso.widgets";

    // First sight: every version is young by definition and must be withheld.
    let mut versions = vec!["1.0.0".to_string(), "2.0.0".to_string()];
    svc.filter_nuget_version_list(&params, pkg, &mut versions)
        .await
        .expect("filter flatcontainer versions");
    assert!(
        versions.is_empty(),
        "first-seen versions are all young; got {versions:?}"
    );
    assert_eq!(review_status(&pool, repo_id, pkg, "1.0.0").await, "pending");
    assert_eq!(review_status(&pool, repo_id, pkg, "2.0.0").await, "pending");

    // Locally age one version past the threshold.
    backdate_observation(&pool, repo_id, pkg, "1.0.0", 10).await;

    let mut versions = vec!["1.0.0".to_string(), "2.0.0".to_string()];
    svc.filter_nuget_version_list(&params, pkg, &mut versions)
        .await
        .expect("filter after backdate");
    assert_eq!(
        versions,
        vec!["1.0.0".to_string()],
        "locally aged version serves, the fresh one stays withheld"
    );

    // Download-path agreement: check() with the first_seen time decides the
    // same way the listing did.
    let aged_time = svc
        .first_seen_time(repo_id, pkg, "1.0.0")
        .await
        .expect("first_seen_time");
    assert!(matches!(
        svc.check(&params, pkg, "1.0.0", aged_time)
            .await
            .expect("check aged"),
        AgeGateDecision::Allow
    ));
    let fresh_time = svc
        .first_seen_time(repo_id, pkg, "2.0.0")
        .await
        .expect("first_seen_time fresh");
    assert!(matches!(
        svc.check(&params, pkg, "2.0.0", fresh_time)
            .await
            .expect("check fresh"),
        AgeGateDecision::Block { .. }
    ));
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn nuget_registration_inline_pages_filtered_by_first_seen() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_repo_with_mode(
        &pool,
        "reg",
        "nuget",
        "https://api.nuget.org/v3",
        7,
        "first_seen",
    )
    .await;
    let params = repo_params_with_mode(
        repo_id,
        "age-gate-nuget-reg",
        RepositoryFormat::Nuget,
        7,
        AgeGateMode::FirstSeen,
    );
    let pkg = "contoso.registration";

    // Pre-observe and locally age 1.0.0; 2.0.0 is first seen by the filter.
    svc.observe_versions_first_seen(repo_id, pkg, &["1.0.0".to_string()])
        .await
        .expect("pre-observe");
    backdate_observation(&pool, repo_id, pkg, "1.0.0", 10).await;

    let mut doc = serde_json::json!({
        "@id": "reg-index",
        "count": 2,
        "items": [
            {
                "@id": "page0",
                "count": 2,
                "lower": "1.0.0",
                "upper": "2.0.0",
                "items": [
                    { "catalogEntry": { "id": pkg, "version": "1.0.0" } },
                    { "catalogEntry": { "id": pkg, "version": "2.0.0" } },
                ],
            },
            { "@id": "https://upstream.example/page1", "count": 64,
              "lower": "3.0.0", "upper": "4.0.0" },
        ],
    });

    svc.filter_nuget_registration_index(&params, pkg, &mut doc)
        .await
        .expect("filter registration index");

    let page0 = &doc["items"][0];
    let remaining: Vec<&str> = page0["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["catalogEntry"]["version"].as_str().unwrap())
        .collect();
    assert_eq!(remaining, vec!["1.0.0"], "young inline item withheld");
    assert_eq!(page0["count"], serde_json::json!(1));
    assert_eq!(page0["upper"], serde_json::json!("1.0.0"));
    assert_eq!(
        doc["items"][1]["@id"],
        serde_json::json!("https://upstream.example/page1"),
        "external page reference untouched"
    );
    assert_eq!(review_status(&pool, repo_id, pkg, "2.0.0").await, "pending");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn go_version_list_filters_on_upstream_info_times() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);

    // Upstream GOPROXY double: v1.0.0 is old, v2.0.0 is young, v3.0.0 has no
    // .info (fetch fails -> timeless -> withheld, fail-closed).
    let server = MockServer::start().await;
    let old = (Utc::now() - Duration::days(3650)).to_rfc3339();
    let young = (Utc::now() - Duration::days(1)).to_rfc3339();
    Mock::given(method("GET"))
        .and(wm_path("/example.com/mod/@v/v1.0.0.info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Version": "v1.0.0", "Time": old
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(wm_path("/example.com/mod/@v/v2.0.0.info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Version": "v2.0.0", "Time": young
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(wm_path("/example.com/mod/@v/v3.0.0.info"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let repo_id = create_remote_repo_with_mode(
        &pool,
        "list",
        "go",
        &server.uri(),
        7,
        "upstream_publish_time",
    )
    .await;
    let params = repo_params_with_mode(
        repo_id,
        "age-gate-go-list",
        RepositoryFormat::Go,
        7,
        AgeGateMode::UpstreamPublishTime,
    );
    let module = "example.com/mod";

    let filtered = svc
        .filter_go_version_list(
            &params,
            module,
            module, // no capitals: encoded == decoded
            &server.uri(),
            "v1.0.0\nv2.0.0\nv3.0.0",
        )
        .await
        .expect("filter go list");

    assert_eq!(
        filtered, "v1.0.0",
        "old version serves; young and timeless versions are withheld"
    );
    assert_eq!(
        review_status(&pool, repo_id, module, "v2.0.0").await,
        "pending"
    );
    assert_eq!(
        review_status(&pool, repo_id, module, "v3.0.0").await,
        "pending"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn go_first_seen_mode_filters_list_without_upstream_fetch() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);

    // Unroutable upstream: first_seen mode must never fetch .info documents.
    let dead_upstream = "http://127.0.0.1:1";
    let repo_id =
        create_remote_repo_with_mode(&pool, "fs", "go", dead_upstream, 7, "first_seen").await;
    let params = repo_params_with_mode(
        repo_id,
        "age-gate-go-fs",
        RepositoryFormat::Go,
        7,
        AgeGateMode::FirstSeen,
    );
    let module = "example.com/fsmod";

    let filtered = svc
        .filter_go_version_list(&params, module, module, dead_upstream, "v1.0.0\nv2.0.0")
        .await
        .expect("filter go list first-seen");
    assert_eq!(filtered, "", "first sight withholds everything");

    backdate_observation(&pool, repo_id, module, "v1.0.0", 10).await;
    let filtered = svc
        .filter_go_version_list(&params, module, module, dead_upstream, "v1.0.0\nv2.0.0")
        .await
        .expect("filter go list after backdate");
    assert_eq!(filtered, "v1.0.0", "locally aged version becomes visible");
}
