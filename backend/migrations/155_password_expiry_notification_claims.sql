-- Claim-before-send for password expiry notification emails.
--
-- The notification job used to SELECT users in a warning window (filtered by
-- NOT EXISTS on this table), send the email, and only afterwards insert the
-- dedup row, so with N replicas a user could receive the same warning email
-- up to N times per tick. Rows are now inserted as a *claim* before SMTP:
-- 'claimed' (in flight, guarded by claim_expires_at), then 'sent' or
-- 'failed'. Failed sends and expired claims are retryable; 'sent' is final.
--
-- Existing rows were only ever inserted after a successful send, so the
-- status default 'sent' backfills them correctly.
ALTER TABLE password_expiry_notifications
    ADD COLUMN status TEXT NOT NULL DEFAULT 'sent'
        CHECK (status IN ('claimed', 'sent', 'failed')),
    ADD COLUMN claimed_by TEXT,
    ADD COLUMN claim_token UUID,
    ADD COLUMN claimed_at TIMESTAMPTZ,
    ADD COLUMN claim_expires_at TIMESTAMPTZ,
    ADD COLUMN last_error TEXT;

-- sent_at now means "when the email was actually sent": NULL while a claim
-- is in flight or after a failure, set by the token-guarded sent transition.
ALTER TABLE password_expiry_notifications
    ALTER COLUMN sent_at DROP DEFAULT,
    ALTER COLUMN sent_at DROP NOT NULL;

COMMENT ON COLUMN password_expiry_notifications.status IS
    'claimed = send in flight (see claim_expires_at); sent = final; failed = retryable';
COMMENT ON COLUMN password_expiry_notifications.claim_token IS
    'Random per-claim token; sent/failed transitions must match it';
