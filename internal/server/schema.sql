-- bbb server mode schema.
--
-- A `job` is a user submitted copy request (`src` -> `dst`), for example
-- `az://acct/container/a` -> `az://acct/container/b`. The leader expands a job
-- into individual file level `tasks` which are leased to workers (the leader
-- itself and any follower processes) and executed independently.

CREATE TABLE IF NOT EXISTS jobs (
    id               TEXT PRIMARY KEY,
    src              TEXT    NOT NULL,
    dst              TEXT    NOT NULL,
    state            TEXT    NOT NULL, -- pending|expanding|running|succeeded|failed|cancelled
    overwrite        INTEGER NOT NULL DEFAULT 0,
    concurrency      INTEGER NOT NULL DEFAULT 0,
    retry_count      INTEGER NOT NULL DEFAULT 0,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    total_tasks      INTEGER NOT NULL DEFAULT 0,
    done_tasks       INTEGER NOT NULL DEFAULT 0,
    failed_tasks     INTEGER NOT NULL DEFAULT 0,
    total_bytes      INTEGER NOT NULL DEFAULT 0,
    copied_bytes     INTEGER NOT NULL DEFAULT 0,
    error            TEXT    NOT NULL DEFAULT '',
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    started_at       INTEGER,
    finished_at      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs (state, created_at);

CREATE TABLE IF NOT EXISTS tasks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id       TEXT    NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    src          TEXT    NOT NULL,
    dst          TEXT    NOT NULL,
    size         INTEGER NOT NULL DEFAULT 0,
    state        TEXT    NOT NULL, -- pending|running|succeeded|failed|cancelled
    attempts     INTEGER NOT NULL DEFAULT 0,
    copied_bytes INTEGER NOT NULL DEFAULT 0,
    -- Set when a previous attempt may have written partial data to dst (worker
    -- crash, or a failure after bytes were copied). The next attempt is then
    -- allowed to overwrite that leftover output even when the job did not ask
    -- for --overwrite, since it is clobbering this job's own partial file
    -- rather than pre-existing data.
    force_overwrite INTEGER NOT NULL DEFAULT 0,
    worker_id    TEXT    NOT NULL DEFAULT '',
    lease_expire INTEGER NOT NULL DEFAULT 0,
    error        TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    UNIQUE (job_id, src, dst)
);

CREATE INDEX IF NOT EXISTS idx_tasks_job ON tasks (job_id, state);
CREATE INDEX IF NOT EXISTS idx_tasks_pending ON tasks (state, id);
CREATE INDEX IF NOT EXISTS idx_tasks_lease ON tasks (state, lease_expire);

CREATE TABLE IF NOT EXISTS workers (
    id         TEXT PRIMARY KEY,
    mode       TEXT    NOT NULL DEFAULT 'follower', -- leader|follower
    addr       TEXT    NOT NULL DEFAULT '',
    version    TEXT    NOT NULL DEFAULT '',
    capacity   INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_workers_last_seen ON workers (last_seen);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1');
