//! Password expiry notification service.
//!
//! Provides pure-function helpers for deciding when to notify users about
//! upcoming password expiration, plus a background task that queries the
//! database and sends emails via `SmtpService`.

use chrono::{DateTime, Duration, Utc};

// ---------------------------------------------------------------------------
// Pure helpers (no I/O, easy to unit-test)
// ---------------------------------------------------------------------------

/// Compute how many days remain until a password expires.
///
/// Returns `None` when password expiration is disabled (`expiry_days == 0`).
/// A negative value means the password has already expired.
pub fn days_until_expiry(
    password_changed_at: DateTime<Utc>,
    expiry_days: u32,
    now: DateTime<Utc>,
) -> Option<i64> {
    if expiry_days == 0 {
        return None;
    }
    let expiry = password_changed_at + Duration::days(expiry_days as i64);
    Some((expiry - now).num_days())
}

/// Determine whether a notification should be sent for a given warning tier.
///
/// Returns `true` when all of these are true:
///   1. Password expiry is enabled (`expiry_days > 0`).
///   2. The remaining days are at or below `warning_days`.
///   3. The password has not already expired (remaining >= 0).
pub fn should_notify(
    password_changed_at: DateTime<Utc>,
    expiry_days: u32,
    warning_days: u32,
    now: DateTime<Utc>,
) -> bool {
    match days_until_expiry(password_changed_at, expiry_days, now) {
        Some(remaining) => remaining >= 0 && remaining <= warning_days as i64,
        None => false,
    }
}

/// Build the plain-text body for a password expiry warning email.
pub fn build_notification_text(username: &str, days_remaining: i64) -> String {
    if days_remaining <= 0 {
        format!(
            "Hello {username},\n\n\
             Your password has expired. Please log in and change your password \
             as soon as possible to avoid losing access to your account.\n\n\
             Artifact Keeper"
        )
    } else if days_remaining == 1 {
        format!(
            "Hello {username},\n\n\
             Your password will expire tomorrow. Please log in and change your \
             password to avoid any disruption.\n\n\
             Artifact Keeper"
        )
    } else {
        format!(
            "Hello {username},\n\n\
             Your password will expire in {days_remaining} days. Please log in \
             and change your password before it expires.\n\n\
             Artifact Keeper"
        )
    }
}

/// Build the HTML body for a password expiry warning email.
pub fn build_notification_html(username: &str, days_remaining: i64) -> String {
    let urgency_note = if days_remaining <= 0 {
        "Your password has <strong>expired</strong>. Please change it immediately.".to_string()
    } else if days_remaining == 1 {
        "Your password will expire <strong>tomorrow</strong>.".to_string()
    } else {
        format!("Your password will expire in <strong>{days_remaining} days</strong>.")
    };

    format!(
        "<h2>Password Expiry Notice</h2>\
         <p>Hello {username},</p>\
         <p>{urgency_note}</p>\
         <p>Please log in and change your password to avoid any disruption to \
         your account access.</p>\
         <p>Artifact Keeper</p>"
    )
}

// ---------------------------------------------------------------------------
// Database + SMTP logic (used by the scheduler)
// ---------------------------------------------------------------------------

/// Row returned by the user query in `send_expiry_notifications`.
#[derive(Debug, sqlx::FromRow)]
pub struct ExpiringUser {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub password_changed_at: DateTime<Utc>,
}

/// TTL for one notification send claim, in seconds.
///
/// One SMTP send takes seconds; if the claiming replica dies mid-send the
/// notification becomes retryable after this long. Comfortably shorter than
/// the default hourly check interval so a crashed claim retries on the next
/// tick.
const NOTIFICATION_CLAIM_TTL_SECS: f64 = 300.0;

/// Proof that this process owns one notification send.
#[derive(Debug)]
pub(crate) struct NotificationClaim {
    pub id: uuid::Uuid,
    pub claim_token: uuid::Uuid,
}

/// Claim the `(user, tier, password_changed_at)` notification BEFORE the SMTP
/// send. Returns `None` when another replica owns it: already sent, or a
/// send is in flight under a live claim. A 'failed' row or an expired
/// 'claimed' row is re-claimed in place (retry).
pub(crate) async fn claim_notification(
    db: &sqlx::PgPool,
    user_id: uuid::Uuid,
    warning_days: i32,
    password_changed_at: DateTime<Utc>,
    claimed_by: &str,
    claim_ttl_secs: f64,
) -> Result<Option<NotificationClaim>, sqlx::Error> {
    let row: Option<(uuid::Uuid, uuid::Uuid)> = sqlx::query_as(
        r#"
        INSERT INTO password_expiry_notifications
            (user_id, warning_days, password_changed_at, status,
             claimed_by, claim_token, claimed_at, claim_expires_at, sent_at)
        VALUES ($1, $2, $3, 'claimed',
                $4, gen_random_uuid(), NOW(), NOW() + make_interval(secs => $5), NULL)
        ON CONFLICT (user_id, warning_days, password_changed_at) DO UPDATE
        SET status = 'claimed',
            claimed_by = EXCLUDED.claimed_by,
            claim_token = EXCLUDED.claim_token,
            claimed_at = NOW(),
            claim_expires_at = EXCLUDED.claim_expires_at
        WHERE password_expiry_notifications.status = 'failed'
           OR (password_expiry_notifications.status = 'claimed'
               AND password_expiry_notifications.claim_expires_at <= NOW())
        RETURNING id, claim_token
        "#,
    )
    .bind(user_id)
    .bind(warning_days)
    .bind(password_changed_at)
    .bind(claimed_by)
    .bind(claim_ttl_secs)
    .fetch_optional(db)
    .await?;

    Ok(row.map(|(id, claim_token)| NotificationClaim { id, claim_token }))
}

/// Token-guarded 'sent' transition. Returns `false` if the claim was lost.
pub(crate) async fn mark_notification_sent(db: &sqlx::PgPool, claim: &NotificationClaim) -> bool {
    let result = sqlx::query(
        r#"
        UPDATE password_expiry_notifications
        SET status = 'sent', sent_at = NOW(), claim_expires_at = NULL, last_error = NULL
        WHERE id = $1
          AND claim_token = $2
          AND status = 'claimed'
        "#,
    )
    .bind(claim.id)
    .bind(claim.claim_token)
    .execute(db)
    .await;
    matches!(result, Ok(ref r) if r.rows_affected() == 1)
}

/// Token-guarded 'failed' transition; the row becomes retryable next cycle.
pub(crate) async fn mark_notification_failed(
    db: &sqlx::PgPool,
    claim: &NotificationClaim,
    error: &str,
) {
    let _ = sqlx::query(
        r#"
        UPDATE password_expiry_notifications
        SET status = 'failed', claim_expires_at = NULL, last_error = $3
        WHERE id = $1
          AND claim_token = $2
          AND status = 'claimed'
        "#,
    )
    .bind(claim.id)
    .bind(claim.claim_token)
    .bind(error)
    .execute(db)
    .await;
}

/// Run one cycle of the password expiry notification job.
///
/// For each configured warning tier, queries local users whose password is
/// within the warning window, checks the `password_expiry_notifications` table
/// for duplicates, sends an email, and records the notification.
pub async fn send_expiry_notifications(
    db: &sqlx::PgPool,
    smtp: &crate::services::smtp_service::SmtpService,
    expiry_days: u32,
    warning_tiers: &[u32],
) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
    if expiry_days == 0 || warning_tiers.is_empty() || !smtp.is_configured() {
        return Ok(0);
    }

    let now = Utc::now();
    let mut sent_count: u32 = 0;

    for &tier in warning_tiers {
        // Compute cutoff dates in Rust to avoid PG interval binding issues.
        //
        // A user's password enters the warning window when:
        //   password_changed_at <= now - (expiry_days - tier)
        // And the password has not yet expired when:
        //   password_changed_at > now - expiry_days
        let effective_tier = tier.min(expiry_days);
        let warning_cutoff = now - Duration::days((expiry_days - effective_tier) as i64);
        let expiry_cutoff = now - Duration::days(expiry_days as i64);

        let users: Vec<ExpiringUser> = sqlx::query_as::<_, ExpiringUser>(
            r#"
            SELECT u.id, u.username, u.email, u.password_changed_at
            FROM users u
            WHERE u.auth_provider = 'local'
              AND u.is_active = true
              AND u.is_service_account = false
              AND u.password_changed_at <= $1
              AND u.password_changed_at > $2
              AND NOT EXISTS (
                  SELECT 1 FROM password_expiry_notifications n
                  WHERE n.user_id = u.id
                    AND n.warning_days = $3
                    AND n.password_changed_at = u.password_changed_at
                    AND (
                        n.status = 'sent'
                        OR (n.status = 'claimed' AND n.claim_expires_at > NOW())
                    )
              )
            "#,
        )
        .bind(warning_cutoff)
        .bind(expiry_cutoff)
        .bind(tier as i32)
        .fetch_all(db)
        .await?;

        for user in &users {
            let remaining =
                days_until_expiry(user.password_changed_at, expiry_days, now).unwrap_or(0);

            let subject = if remaining <= 0 {
                "Your Artifact Keeper password has expired".to_string()
            } else if remaining == 1 {
                "Your Artifact Keeper password expires tomorrow".to_string()
            } else {
                format!(
                    "Your Artifact Keeper password expires in {} days",
                    remaining
                )
            };

            let body_text = build_notification_text(&user.username, remaining);
            let body_html = build_notification_html(&user.username, remaining);

            // Claim the notification BEFORE the send: the claim row (not a
            // post-send marker) is what stops other replicas from emailing
            // the same user for the same tier in this window.
            let claim = match claim_notification(
                db,
                user.id,
                tier as i32,
                user.password_changed_at,
                crate::services::cluster_work::WorkerIdentity::for_process().as_str(),
                NOTIFICATION_CLAIM_TTL_SECS,
            )
            .await
            {
                Ok(Some(claim)) => claim,
                Ok(None) => {
                    // Sent, or in flight on another replica.
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        user = %user.username,
                        tier = tier,
                        "Failed to claim password expiry notification: {}",
                        e,
                    );
                    continue;
                }
            };

            if let Err(e) = smtp
                .send_email(&user.email, &subject, &body_html, &body_text)
                .await
            {
                tracing::warn!(
                    user = %user.username,
                    tier = tier,
                    "Failed to send password expiry notification: {}",
                    e,
                );
                // Release as retryable with the error recorded.
                mark_notification_failed(db, &claim, &e.to_string()).await;
                continue;
            }

            // Record the sent notification (token-guarded).
            if !mark_notification_sent(db, &claim).await {
                tracing::warn!(
                    user = %user.username,
                    tier = tier,
                    "Password expiry email sent but the claim was lost; \
                     the user may receive a duplicate from the new claim owner"
                );
            }

            tracing::info!(
                user = %user.username,
                days_remaining = remaining,
                tier = tier,
                "Sent password expiry warning email"
            );

            sent_count += 1;
        }
    }

    Ok(sent_count)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    // -------------------------------------------------------------------
    // days_until_expiry
    // -------------------------------------------------------------------

    #[test]
    fn test_days_until_expiry_disabled_when_zero() {
        let now = Utc::now();
        assert_eq!(days_until_expiry(now, 0, now), None);
    }

    #[test]
    fn test_days_until_expiry_future() {
        let now = Utc::now();
        let changed = now - Duration::days(80);
        let remaining = days_until_expiry(changed, 90, now);
        assert_eq!(remaining, Some(10));
    }

    #[test]
    fn test_days_until_expiry_exact() {
        let now = Utc::now();
        let changed = now - Duration::days(90);
        let remaining = days_until_expiry(changed, 90, now);
        assert_eq!(remaining, Some(0));
    }

    #[test]
    fn test_days_until_expiry_past() {
        let now = Utc::now();
        let changed = now - Duration::days(95);
        let remaining = days_until_expiry(changed, 90, now);
        assert_eq!(remaining, Some(-5));
    }

    #[test]
    fn test_days_until_expiry_just_changed() {
        let now = Utc::now();
        let remaining = days_until_expiry(now, 90, now);
        assert_eq!(remaining, Some(90));
    }

    // -------------------------------------------------------------------
    // should_notify
    // -------------------------------------------------------------------

    #[test]
    fn test_should_notify_disabled_when_expiry_zero() {
        let now = Utc::now();
        assert!(!should_notify(now, 0, 14, now));
    }

    #[test]
    fn test_should_notify_too_early() {
        let now = Utc::now();
        // Password changed today, 90-day expiry, 14-day warning.
        // 90 days remaining, which is > 14, so no notification.
        assert!(!should_notify(now, 90, 14, now));
    }

    #[test]
    fn test_should_notify_within_window() {
        let now = Utc::now();
        // Changed 80 days ago, 90-day expiry, 14-day warning.
        // 10 days remaining, which is <= 14.
        let changed = now - Duration::days(80);
        assert!(should_notify(changed, 90, 14, now));
    }

    #[test]
    fn test_should_notify_on_exact_boundary() {
        let now = Utc::now();
        // Changed 76 days ago, 90-day expiry, 14-day warning.
        // 14 days remaining == 14, should notify.
        let changed = now - Duration::days(76);
        assert!(should_notify(changed, 90, 14, now));
    }

    #[test]
    fn test_should_notify_one_day_remaining() {
        let now = Utc::now();
        let changed = now - Duration::days(89);
        assert!(should_notify(changed, 90, 1, now));
    }

    #[test]
    fn test_should_not_notify_when_already_expired() {
        let now = Utc::now();
        let changed = now - Duration::days(95);
        // -5 days remaining, so password already expired.
        assert!(!should_notify(changed, 90, 14, now));
    }

    #[test]
    fn test_should_notify_exact_expiry_day() {
        let now = Utc::now();
        // 0 days remaining (expires today).
        let changed = now - Duration::days(90);
        assert!(should_notify(changed, 90, 1, now));
    }

    // -------------------------------------------------------------------
    // build_notification_text
    // -------------------------------------------------------------------

    #[test]
    fn test_notification_text_multiple_days() {
        let text = build_notification_text("alice", 7);
        assert!(text.contains("alice"));
        assert!(text.contains("7 days"));
    }

    #[test]
    fn test_notification_text_one_day() {
        let text = build_notification_text("bob", 1);
        assert!(text.contains("bob"));
        assert!(text.contains("tomorrow"));
    }

    #[test]
    fn test_notification_text_expired() {
        let text = build_notification_text("carol", 0);
        assert!(text.contains("carol"));
        assert!(text.contains("expired"));
    }

    // -------------------------------------------------------------------
    // build_notification_html
    // -------------------------------------------------------------------

    #[test]
    fn test_notification_html_multiple_days() {
        let html = build_notification_html("alice", 7);
        assert!(html.contains("alice"));
        assert!(html.contains("7 days"));
        assert!(html.contains("<strong>"));
    }

    #[test]
    fn test_notification_html_one_day() {
        let html = build_notification_html("bob", 1);
        assert!(html.contains("bob"));
        assert!(html.contains("tomorrow"));
    }

    #[test]
    fn test_notification_html_expired() {
        let html = build_notification_html("carol", 0);
        assert!(html.contains("carol"));
        assert!(html.contains("expired"));
    }

    // -------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_warning_tier_larger_than_expiry() {
        let now = Utc::now();
        // 7-day expiry with a 14-day warning tier: the entire expiry window
        // falls inside the warning window, so any non-expired password should
        // trigger a notification.
        let changed = now - Duration::days(3);
        assert!(should_notify(changed, 7, 14, now));
    }

    #[test]
    fn test_days_until_expiry_large_value() {
        let now = Utc::now();
        let changed = now;
        let remaining = days_until_expiry(changed, 3650, now);
        assert_eq!(remaining, Some(3650));
    }

    #[test]
    fn test_days_until_expiry_one_day_policy() {
        let now = Utc::now();
        let changed = now;
        let remaining = days_until_expiry(changed, 1, now);
        assert_eq!(remaining, Some(1));
    }

    // -------------------------------------------------------------------
    // build_notification_text (additional edge cases)
    // -------------------------------------------------------------------

    #[test]
    fn test_notification_text_negative_days() {
        let text = build_notification_text("dave", -3);
        assert!(text.contains("dave"));
        assert!(text.contains("expired"));
        assert!(!text.contains("-3"));
    }

    #[test]
    fn test_notification_text_many_days() {
        let text = build_notification_text("eve", 30);
        assert!(text.contains("eve"));
        assert!(text.contains("30 days"));
        assert!(!text.contains("tomorrow"));
        assert!(!text.contains("expired"));
    }

    #[test]
    fn test_notification_text_two_days() {
        let text = build_notification_text("frank", 2);
        assert!(text.contains("frank"));
        assert!(text.contains("2 days"));
        assert!(!text.contains("tomorrow"));
    }

    // -------------------------------------------------------------------
    // build_notification_html (additional edge cases)
    // -------------------------------------------------------------------

    #[test]
    fn test_notification_html_negative_days() {
        let html = build_notification_html("dave", -3);
        assert!(html.contains("dave"));
        assert!(html.contains("expired"));
        assert!(html.contains("<strong>"));
    }

    #[test]
    fn test_notification_html_many_days() {
        let html = build_notification_html("eve", 30);
        assert!(html.contains("eve"));
        assert!(html.contains("30 days"));
        assert!(html.contains("<strong>"));
    }

    #[test]
    fn test_notification_html_contains_structure() {
        let html = build_notification_html("test_user", 5);
        assert!(html.contains("<h2>"));
        assert!(html.contains("<p>"));
        assert!(html.contains("Password Expiry Notice"));
        assert!(html.contains("Artifact Keeper"));
    }

    #[test]
    fn test_notification_text_contains_signature() {
        let text = build_notification_text("test_user", 5);
        assert!(text.contains("Artifact Keeper"));
        assert!(text.contains("Hello test_user"));
    }

    // -------------------------------------------------------------------
    // should_notify (additional edge cases)
    // -------------------------------------------------------------------

    #[test]
    fn test_should_notify_warning_equals_expiry() {
        let now = Utc::now();
        // 7-day expiry with 7-day warning: notify for the entire lifecycle
        let changed = now - Duration::days(3);
        assert!(should_notify(changed, 7, 7, now));
    }

    #[test]
    fn test_should_not_notify_warning_zero() {
        let now = Utc::now();
        // 0-day warning tier should only notify on expiry day
        let changed = now - Duration::days(89);
        assert!(!should_notify(changed, 90, 0, now));
    }

    #[test]
    fn test_should_notify_warning_zero_on_expiry_day() {
        let now = Utc::now();
        // 0-day warning tier, password expires today (remaining = 0)
        let changed = now - Duration::days(90);
        assert!(should_notify(changed, 90, 0, now));
    }

    // -------------------------------------------------------------------
    // ExpiringUser struct
    // -------------------------------------------------------------------

    #[test]
    fn test_expiring_user_debug() {
        let user = ExpiringUser {
            id: uuid::Uuid::nil(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_changed_at: Utc::now(),
        };
        let debug_output = format!("{:?}", user);
        assert!(debug_output.contains("testuser"));
        assert!(debug_output.contains("test@example.com"));
    }

    // -------------------------------------------------------------------
    // Notification send claims (Tier-2: no-op without DATABASE_URL)
    // -------------------------------------------------------------------

    async fn notification_status(db: &sqlx::PgPool, id: uuid::Uuid) -> String {
        sqlx::query_scalar("SELECT status FROM password_expiry_notifications WHERE id = $1")
            .bind(id)
            .fetch_one(db)
            .await
            .expect("fetch notification status")
    }

    /// The claim (taken BEFORE the SMTP send) is exclusive: a second replica
    /// cannot claim the same (user, tier, changed_at) while a send is in
    /// flight, nor after it succeeded.
    #[tokio::test]
    async fn notification_claim_is_exactly_once() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _username) = tdh::create_user(&pool).await;
        let changed_at = Utc::now();

        let claim = claim_notification(&pool, user_id, 7, changed_at, "replica-a", 300.0)
            .await
            .expect("claim query ok")
            .expect("first claim wins");

        // In flight: blocked.
        assert!(
            claim_notification(&pool, user_id, 7, changed_at, "replica-b", 300.0)
                .await
                .expect("claim query ok")
                .is_none(),
            "a live claim must block a second replica"
        );

        // A different tier is an independent notification.
        assert!(
            claim_notification(&pool, user_id, 3, changed_at, "replica-b", 300.0)
                .await
                .expect("claim query ok")
                .is_some(),
            "another warning tier must be independently claimable"
        );

        // Sent: blocked forever.
        assert!(mark_notification_sent(&pool, &claim).await);
        assert_eq!(notification_status(&pool, claim.id).await, "sent");
        assert!(
            claim_notification(&pool, user_id, 7, changed_at, "replica-b", 300.0)
                .await
                .expect("claim query ok")
                .is_none(),
            "a sent notification must never be claimable again"
        );

        let _ = sqlx::query("DELETE FROM password_expiry_notifications WHERE user_id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
    }

    /// Failed sends and expired claims are retryable, and a stale owner's
    /// token cannot flip a re-claimed row to 'sent'.
    #[tokio::test]
    async fn notification_failed_and_expired_claims_are_retryable() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _username) = tdh::create_user(&pool).await;
        let changed_at = Utc::now();

        // Dead owner: claim born expired.
        let stale = claim_notification(&pool, user_id, 7, changed_at, "replica-dead", -1.0)
            .await
            .expect("claim query ok")
            .expect("claim");

        // Reclaimed in place by a live replica.
        let fresh = claim_notification(&pool, user_id, 7, changed_at, "replica-new", 300.0)
            .await
            .expect("claim query ok")
            .expect("expired claim must be reclaimable");
        assert_eq!(stale.id, fresh.id, "reclaim must reuse the dedup row");

        // Stale owner is fenced out of the sent transition.
        assert!(
            !mark_notification_sent(&pool, &stale).await,
            "stale owner must not mark a re-claimed notification sent"
        );

        // SMTP failure releases the row as retryable with the error recorded.
        mark_notification_failed(&pool, &fresh, "smtp boom").await;
        assert_eq!(notification_status(&pool, fresh.id).await, "failed");
        assert!(
            claim_notification(&pool, user_id, 7, changed_at, "replica-c", 300.0)
                .await
                .expect("claim query ok")
                .is_some(),
            "a failed send must be claimable for retry"
        );

        let _ = sqlx::query("DELETE FROM password_expiry_notifications WHERE user_id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
    }
}
