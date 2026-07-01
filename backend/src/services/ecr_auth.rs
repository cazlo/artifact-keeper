//! Dynamic AWS ECR upstream authentication.
//!
//! ECR registries authenticate with plain HTTP Basic auth: username `AWS` and a
//! short-lived password minted by the AWS `ecr:GetAuthorizationToken` API. They
//! do NOT issue a `WWW-Authenticate: Bearer` token-endpoint challenge the way
//! Docker Hub does, so this is the simpler case — the resolver attaches the
//! decoded Basic credential directly at the proxy fetch sites.
//!
//! Unlike static Basic/Bearer credentials, the on-wire secret is never stored:
//! only non-secret provider *config* (region, optional registry/account id) is
//! persisted. The token is resolved at request time from the AWS default
//! credential chain, cached in memory, and refreshed before expiry.
//!
//! This module deliberately isolates the only AWS-SDK-touching code
//! ([`RealEcrTokenProvider`]) behind the [`EcrTokenProvider`] trait so the rest
//! of the resolution logic (config parsing, host validation, token decoding,
//! caching) is hermetically unit-testable with a fake provider — no network, no
//! AWS, no LocalStack.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::error::{AppError, Result};

/// Stored, non-secret provider config for an `aws_ecr` upstream.
///
/// Persisted (encrypted, for uniformity with static creds) under the existing
/// `upstream_auth_credentials` key. Contains NO secrets: AWS credentials come
/// from the default credential chain at runtime, never from this config.
#[derive(Debug, Clone, PartialEq)]
pub struct AwsEcrConfig {
    /// AWS region of the ECR registry, e.g. `us-west-2`. Required.
    pub region: String,
    /// Optional 12-digit AWS account id of the registry. Config/safety metadata
    /// only: it is NOT sent to `GetAuthorizationToken` (the `registryIds`
    /// parameter is deprecated and the returned token is principal-scoped, not
    /// registry-scoped). Used for the cache key and host validation.
    pub registry_id: Option<String>,
}

/// Parse stored `aws_ecr` provider config from its JSON shape.
pub fn parse_aws_ecr_config(credentials_json: &str) -> Result<AwsEcrConfig> {
    let v: serde_json::Value = serde_json::from_str(credentials_json)
        .map_err(|e| AppError::Internal(format!("Invalid aws_ecr config JSON: {e}")))?;

    let region = v["region"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Config("aws_ecr config requires a non-empty 'region'".to_string())
        })?
        .to_string();

    let registry_id = v["registry_id"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    Ok(AwsEcrConfig {
        region,
        registry_id,
    })
}

/// Serialize stored `aws_ecr` provider config to its JSON shape. Inverse of
/// [`parse_aws_ecr_config`]. Contains no secrets.
pub fn build_aws_ecr_config_json(cfg: &AwsEcrConfig) -> String {
    serde_json::json!({
        "region": cfg.region,
        "registry_id": cfg.registry_id,
    })
    .to_string()
}

/// Validate that `upstream_url`'s host is a well-formed ECR registry endpoint
/// consistent with `cfg`, before any ECR credential is attached to it.
///
/// Accepts `<account>.dkr.ecr[-fips].<region>.amazonaws.com[.cn]`, requires the
/// host region to match `cfg.region`, and — if `cfg.registry_id` is set —
/// requires the host account to match it. This is a host-SHAPE check: it does
/// NOT require the host account to equal the principal's default registry
/// (`proxyEndpoint`), because with `registryIds` omitted the minted token can
/// pull cross-account from any registry the IAM principal may access. Gating on
/// `proxyEndpoint == host` would break legitimate cross-account pull-through.
pub fn validate_ecr_upstream_host(upstream_url: &str, cfg: &AwsEcrConfig) -> Result<()> {
    let parsed = url::Url::parse(upstream_url)
        .map_err(|e| AppError::Validation(format!("Invalid upstream URL: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::Validation("Upstream URL has no host".to_string()))?;

    let (account, region) = parse_ecr_host(host).ok_or_else(|| {
        AppError::Validation(format!(
            "Upstream host '{host}' is not a recognized ECR registry endpoint \
             (expected <account>.dkr.ecr.<region>.amazonaws.com)"
        ))
    })?;

    if region != cfg.region {
        return Err(AppError::Validation(format!(
            "ECR upstream host region '{region}' does not match configured region '{}'",
            cfg.region
        )));
    }

    if let Some(ref rid) = cfg.registry_id {
        if account != *rid {
            return Err(AppError::Validation(format!(
                "ECR upstream host account '{account}' does not match configured registry_id '{rid}'"
            )));
        }
    }

    Ok(())
}

/// Parse an ECR host into `(account_id, region)`, or `None` if it is not an
/// ECR-shaped endpoint. Pure string parsing — no DNS, no allocation beyond the
/// returned owned strings.
fn parse_ecr_host(host: &str) -> Option<(String, String)> {
    let host = host.to_ascii_lowercase();
    // Strip the partition suffix first (standard and China partitions).
    let rest = host
        .strip_suffix(".amazonaws.com.cn")
        .or_else(|| host.strip_suffix(".amazonaws.com"))?;
    // `rest` == "<account>.dkr.ecr[-fips].<region>"
    let parts: Vec<&str> = rest.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let account = parts[0];
    if parts[1] != "dkr" {
        return None;
    }
    if parts[2] != "ecr" && parts[2] != "ecr-fips" {
        return None;
    }
    let region = parts[3];
    // Account must be a 12-digit AWS account id.
    if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if region.is_empty() {
        return None;
    }
    Some((account.to_string(), region.to_string()))
}

/// Decode the base64 ECR `authorizationToken` into `(username, password)`.
///
/// ECR returns base64("AWS:<password>"). Rejects invalid base64, non-UTF-8
/// payloads, a missing `:` separator, or an unexpected (non-`AWS`) username with
/// a clean error rather than silently producing empty/malformed Basic
/// credentials. The decoded password is secret and must never be logged.
pub fn decode_ecr_authorization_token(authorization_token: &str) -> Result<(String, String)> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(authorization_token.trim())
        .map_err(|e| {
            AppError::Storage(format!("ECR authorization token is not valid base64: {e}"))
        })?;
    let decoded = String::from_utf8(decoded)
        .map_err(|_| AppError::Storage("ECR authorization token is not valid UTF-8".to_string()))?;
    let (username, password) = decoded.split_once(':').ok_or_else(|| {
        AppError::Storage("ECR authorization token missing ':' separator".to_string())
    })?;
    if username != "AWS" {
        // Do not echo the unexpected username; keep the error free of
        // token-derived material.
        return Err(AppError::Storage(
            "ECR authorization token has an unexpected username (expected 'AWS')".to_string(),
        ));
    }
    Ok((username.to_string(), password.to_string()))
}

/// A minted ECR authorization, mirroring one `authorizationData` entry from
/// `ecr:GetAuthorizationToken`.
#[derive(Clone)]
pub struct EcrAuthorizationData {
    /// Base64-encoded "AWS:<password>" exactly as returned by ECR. Secret.
    pub authorization_token: String,
    /// Absolute expiry (`expiresAt`). Used directly for cache freshness.
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for EcrAuthorizationData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the token; keep only the non-secret expiry.
        f.debug_struct("EcrAuthorizationData")
            .field("authorization_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Mockable boundary over `ecr:GetAuthorizationToken`. The real impl wraps
/// `aws_sdk_ecr`; unit tests inject a fake returning canned tokens/expiries and
/// error variants. This is what keeps the resolution logic testable without AWS.
#[async_trait]
pub trait EcrTokenProvider: Send + Sync {
    async fn get_authorization_token(&self, cfg: &AwsEcrConfig) -> Result<EcrAuthorizationData>;
}

/// Production [`EcrTokenProvider`] backed by `aws_sdk_ecr` and the AWS default
/// credential chain (environment, shared config, IRSA / EKS Pod Identity,
/// ECS/EC2 instance roles). No AWS keys are ever read from repository config.
///
/// The base [`aws_config::SdkConfig`] (credential provider, HTTP connector) is
/// loaded lazily once and shared; per call an ECR client is built with the
/// request region so repos in different regions reuse the same credential
/// resolution without reloading the chain.
#[derive(Default)]
pub struct RealEcrTokenProvider {
    base_config: tokio::sync::OnceCell<aws_config::SdkConfig>,
}

impl RealEcrTokenProvider {
    pub fn new() -> Self {
        Self::default()
    }

    async fn base_config(&self) -> &aws_config::SdkConfig {
        self.base_config
            .get_or_init(|| async {
                aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await
            })
            .await
    }
}

#[async_trait]
impl EcrTokenProvider for RealEcrTokenProvider {
    async fn get_authorization_token(&self, cfg: &AwsEcrConfig) -> Result<EcrAuthorizationData> {
        let base = self.base_config().await;
        let ecr_config = aws_sdk_ecr::config::Builder::from(base)
            .region(aws_sdk_ecr::config::Region::new(cfg.region.clone()))
            .build();
        let client = aws_sdk_ecr::Client::from_conf(ecr_config);

        // Do NOT pass registry_ids: the `registryIds` parameter is deprecated
        // and the returned token is principal-scoped, usable across any registry
        // the IAM principal can access.
        let output = client
            .get_authorization_token()
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("ECR GetAuthorizationToken failed: {e}")))?;

        let data = output
            .authorization_data()
            .first()
            .ok_or_else(|| AppError::Storage("ECR returned no authorization data".to_string()))?;

        let authorization_token = data
            .authorization_token()
            .ok_or_else(|| AppError::Storage("ECR authorization data has no token".to_string()))?
            .to_string();

        let expires_at = data
            .expires_at()
            .ok_or_else(|| AppError::Storage("ECR authorization data has no expiry".to_string()))?;
        let expires_at = DateTime::from_timestamp(expires_at.secs(), expires_at.subsec_nanos())
            .ok_or_else(|| AppError::Storage("ECR expiry timestamp out of range".to_string()))?;

        Ok(EcrAuthorizationData {
            authorization_token,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }

    // -----------------------------------------------------------------------
    // parse_aws_ecr_config
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_config_region_only() {
        let cfg = parse_aws_ecr_config(r#"{"region":"us-west-2"}"#).unwrap();
        assert_eq!(cfg.region, "us-west-2");
        assert_eq!(cfg.registry_id, None);
    }

    #[test]
    fn test_parse_config_with_registry_id() {
        let cfg = parse_aws_ecr_config(r#"{"region":"eu-central-1","registry_id":"123456789012"}"#)
            .unwrap();
        assert_eq!(cfg.region, "eu-central-1");
        assert_eq!(cfg.registry_id.as_deref(), Some("123456789012"));
    }

    #[test]
    fn test_parse_config_trims_whitespace() {
        let cfg = parse_aws_ecr_config(r#"{"region":"  us-east-1  ","registry_id":"  "}"#).unwrap();
        assert_eq!(cfg.region, "us-east-1");
        // Whitespace-only registry_id collapses to None.
        assert_eq!(cfg.registry_id, None);
    }

    #[test]
    fn test_parse_config_missing_region_errors() {
        let err = parse_aws_ecr_config(r#"{"registry_id":"123456789012"}"#).unwrap_err();
        assert!(err.to_string().contains("region"), "got: {err}");
    }

    #[test]
    fn test_parse_config_empty_region_errors() {
        let err = parse_aws_ecr_config(r#"{"region":""}"#).unwrap_err();
        assert!(err.to_string().contains("region"), "got: {err}");
    }

    #[test]
    fn test_parse_config_invalid_json_errors() {
        let err = parse_aws_ecr_config("not-json{{{").unwrap_err();
        assert!(
            err.to_string().contains("Invalid aws_ecr config JSON"),
            "got: {err}"
        );
    }

    #[test]
    fn test_build_then_parse_config_roundtrip() {
        for cfg in [
            AwsEcrConfig {
                region: "us-west-2".to_string(),
                registry_id: Some("123456789012".to_string()),
            },
            AwsEcrConfig {
                region: "eu-west-1".to_string(),
                registry_id: None,
            },
        ] {
            let json = build_aws_ecr_config_json(&cfg);
            assert_eq!(parse_aws_ecr_config(&json).unwrap(), cfg);
            // The serialized config must never carry secret material.
            assert!(!json.to_lowercase().contains("password"));
            assert!(!json.to_lowercase().contains("token"));
        }
    }

    // -----------------------------------------------------------------------
    // parse_ecr_host / validate_ecr_upstream_host
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_ecr_host_standard() {
        let (account, region) =
            parse_ecr_host("123456789012.dkr.ecr.us-west-2.amazonaws.com").unwrap();
        assert_eq!(account, "123456789012");
        assert_eq!(region, "us-west-2");
    }

    #[test]
    fn test_parse_ecr_host_fips() {
        let (account, region) =
            parse_ecr_host("123456789012.dkr.ecr-fips.us-gov-west-1.amazonaws.com").unwrap();
        assert_eq!(account, "123456789012");
        assert_eq!(region, "us-gov-west-1");
    }

    #[test]
    fn test_parse_ecr_host_china_partition() {
        let (account, region) =
            parse_ecr_host("123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn").unwrap();
        assert_eq!(account, "123456789012");
        assert_eq!(region, "cn-north-1");
    }

    #[test]
    fn test_parse_ecr_host_rejects_non_ecr() {
        assert!(parse_ecr_host("registry-1.docker.io").is_none());
        assert!(parse_ecr_host("ghcr.io").is_none());
        // Right suffix, wrong service segment.
        assert!(parse_ecr_host("123456789012.dkr.s3.us-west-2.amazonaws.com").is_none());
        // Non-12-digit account.
        assert!(parse_ecr_host("12345.dkr.ecr.us-west-2.amazonaws.com").is_none());
        // Non-numeric account.
        assert!(parse_ecr_host("notanaccount.dkr.ecr.us-west-2.amazonaws.com").is_none());
    }

    #[test]
    fn test_validate_host_ok() {
        let cfg = AwsEcrConfig {
            region: "us-west-2".to_string(),
            registry_id: Some("123456789012".to_string()),
        };
        validate_ecr_upstream_host(
            "https://123456789012.dkr.ecr.us-west-2.amazonaws.com/v2/",
            &cfg,
        )
        .unwrap();
    }

    #[test]
    fn test_validate_host_region_mismatch() {
        let cfg = AwsEcrConfig {
            region: "us-east-1".to_string(),
            registry_id: None,
        };
        let err = validate_ecr_upstream_host(
            "https://123456789012.dkr.ecr.us-west-2.amazonaws.com",
            &cfg,
        )
        .unwrap_err();
        assert!(err.to_string().contains("region"), "got: {err}");
    }

    #[test]
    fn test_validate_host_registry_id_mismatch() {
        let cfg = AwsEcrConfig {
            region: "us-west-2".to_string(),
            registry_id: Some("999999999999".to_string()),
        };
        let err = validate_ecr_upstream_host(
            "https://123456789012.dkr.ecr.us-west-2.amazonaws.com",
            &cfg,
        )
        .unwrap_err();
        assert!(err.to_string().contains("registry_id"), "got: {err}");
    }

    #[test]
    fn test_validate_host_cross_account_allowed_when_registry_id_unset() {
        // Regression guard: with registry_id unset, a valid ECR host for any
        // account must pass — the minted token is principal-scoped and can pull
        // cross-account. We must NOT require host == default proxyEndpoint.
        let cfg = AwsEcrConfig {
            region: "us-west-2".to_string(),
            registry_id: None,
        };
        validate_ecr_upstream_host(
            "https://210987654321.dkr.ecr.us-west-2.amazonaws.com/v2/repo",
            &cfg,
        )
        .unwrap();
    }

    #[test]
    fn test_validate_host_rejects_non_ecr_upstream() {
        let cfg = AwsEcrConfig {
            region: "us-west-2".to_string(),
            registry_id: None,
        };
        let err = validate_ecr_upstream_host("https://registry-1.docker.io/v2/", &cfg).unwrap_err();
        assert!(
            err.to_string()
                .contains("not a recognized ECR registry endpoint"),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // decode_ecr_authorization_token
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_token_ok() {
        let (user, pass) = decode_ecr_authorization_token(&b64("AWS:s3cr3t-password")).unwrap();
        assert_eq!(user, "AWS");
        assert_eq!(pass, "s3cr3t-password");
    }

    #[test]
    fn test_decode_token_password_may_contain_colon() {
        // split_once on the FIRST ':' keeps colons in the password intact.
        let (user, pass) = decode_ecr_authorization_token(&b64("AWS:pa:ss:word")).unwrap();
        assert_eq!(user, "AWS");
        assert_eq!(pass, "pa:ss:word");
    }

    #[test]
    fn test_decode_token_invalid_base64() {
        let err = decode_ecr_authorization_token("!!!not-base64!!!").unwrap_err();
        assert!(err.to_string().contains("base64"), "got: {err}");
    }

    #[test]
    fn test_decode_token_missing_colon() {
        let err = decode_ecr_authorization_token(&b64("AWSnocolon")).unwrap_err();
        assert!(err.to_string().contains("separator"), "got: {err}");
    }

    #[test]
    fn test_decode_token_wrong_username_rejected() {
        let err = decode_ecr_authorization_token(&b64("notaws:password")).unwrap_err();
        assert!(
            err.to_string().contains("unexpected username"),
            "got: {err}"
        );
        // The error must not echo the decoded secret.
        assert!(!err.to_string().contains("password"), "got: {err}");
    }

    // -----------------------------------------------------------------------
    // EcrAuthorizationData Debug redaction
    // -----------------------------------------------------------------------

    #[test]
    fn test_authorization_data_debug_redacts_token() {
        let data = EcrAuthorizationData {
            authorization_token: "s3cr3t-token-value-xyz".to_string(),
            expires_at: Utc::now(),
        };
        let dbg = format!("{data:?}");
        assert!(
            !dbg.contains("s3cr3t-token-value-xyz"),
            "token must not appear in Debug output: {dbg}"
        );
        assert!(dbg.contains("redacted"));
    }
}
