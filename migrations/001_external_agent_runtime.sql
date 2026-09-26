CREATE TABLE IF NOT EXISTS external_agents (
  id VARCHAR(40) PRIMARY KEY, name VARCHAR(120) NOT NULL, version VARCHAR(40) NOT NULL,
  protocol_version VARCHAR(16) NOT NULL, description TEXT NOT NULL, transport VARCHAR(16) NOT NULL,
  endpoint VARCHAR(500) NOT NULL, health_endpoint VARCHAR(500), capabilities JSON NOT NULL,
  scopes JSON NOT NULL, auth JSON NOT NULL, limits JSON NOT NULL, metadata JSON NOT NULL,
  enabled BOOLEAN NOT NULL, status VARCHAR(24) NOT NULL, last_health_check TIMESTAMPTZ,
  last_error TEXT, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT uq_external_agent_name_version UNIQUE (name, version)
);
CREATE TABLE IF NOT EXISTS external_agent_credentials (
  id VARCHAR(40) PRIMARY KEY, agent_id VARCHAR(40) NOT NULL REFERENCES external_agents(id) ON DELETE CASCADE,
  key_hash VARCHAR(64) NOT NULL UNIQUE, scopes JSON NOT NULL, enabled BOOLEAN NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS external_agent_routes (
  capability VARCHAR(120) PRIMARY KEY, agent_ids JSON NOT NULL, strategy VARCHAR(24) NOT NULL,
  enabled BOOLEAN NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS external_agent_invocations (
  id VARCHAR(40) PRIMARY KEY, idempotency_key VARCHAR(160) NOT NULL UNIQUE,
  agent_id VARCHAR(40) NOT NULL REFERENCES external_agents(id), capability VARCHAR(120) NOT NULL,
  run_id VARCHAR(40), status VARCHAR(24) NOT NULL, request JSON NOT NULL, result JSON,
  attempts INTEGER NOT NULL, duration_ms DOUBLE PRECISION, error TEXT, available_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_external_agent_invocations_status ON external_agent_invocations(status);
CREATE INDEX IF NOT EXISTS ix_external_agent_invocations_agent_id ON external_agent_invocations(agent_id);
