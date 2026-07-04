-- Durable per-due-time runs for backup schedules (DueRun pattern).
--
-- execute_due_backup_schedules used to select due schedules and immediately
-- create + execute a backup, updating last_run_at/next_run_at only afterwards,
-- so with N replicas one due schedule produced N backup archives per tick.
-- The process-local BackupService mutex cannot help because each execution
-- constructs a fresh service, and it never coordinated across replicas anyway.
--
-- Each due occurrence now claims exactly one row keyed by
-- (schedule_id, scheduled_for): the INSERT wins the race, a completed/failed
-- run is never re-claimed for that due time, and an expired 'running' claim
-- (crashed replica) is reclaimable in place. The row doubles as run history.
CREATE TABLE backup_schedule_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schedule_id UUID NOT NULL REFERENCES backup_schedules(id) ON DELETE CASCADE,
    scheduled_for TIMESTAMPTZ NOT NULL,
    claimed_by TEXT NOT NULL,
    claim_token UUID NOT NULL,
    claim_expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'completed', 'failed')),
    backup_id UUID,
    error_message TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    UNIQUE (schedule_id, scheduled_for)
);

CREATE INDEX idx_backup_schedule_runs_schedule
    ON backup_schedule_runs (schedule_id, started_at DESC);

COMMENT ON TABLE backup_schedule_runs IS
    'One durable run per (schedule, due time); claim before creating/executing the backup';
COMMENT ON COLUMN backup_schedule_runs.scheduled_for IS
    'The due time this run satisfies (next_run_at at claim time; epoch for a never-run schedule)';
COMMENT ON COLUMN backup_schedule_runs.claim_token IS
    'Random per-claim token; run finalize and schedule bookkeeping require it';
