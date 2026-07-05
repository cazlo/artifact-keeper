-- Age-gate source modes (#1558 follow-up): where the cooldown timer starts.
--   upstream_publish_time: the registry-reported publish timestamp (the
--     original #2066 model; npm packument `time`, PyPI `upload-time`,
--     Go `.info` `Time`).
--   first_seen: the first time THIS server observed the version for the
--     repository. An AK-local freshness control for formats whose upstream
--     metadata has no per-version publish time, or where that time is
--     publisher-supplied and untrusted.
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS age_gate_mode TEXT NOT NULL DEFAULT 'upstream_publish_time'
        CHECK (age_gate_mode IN ('upstream_publish_time', 'first_seen'));

-- First-observation records for `first_seen` mode. Insert-once semantics:
-- rows are written with ON CONFLICT DO NOTHING and never updated, so the
-- earliest observation wins across concurrent requests and replicas.
CREATE TABLE age_gate_version_observations (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    package_version TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, package_name, package_version)
);
