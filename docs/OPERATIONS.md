# Production Operations

## High availability

Run at least three stateless API pods and three workers across failure domains. PostgreSQL and Redis must be managed, multi-zone services with TLS, authentication, automatic failover, monitoring, and tested restore procedures. Use an ingress or API gateway for OAuth/OIDC validation, WAF policy, rate limiting, and mTLS where required.

## Migrations

Apply `migrations/001_external_agent_runtime.sql` once before deploying this release. Development uses SQLAlchemy `create_all`; production change control must execute reviewed SQL using the platform migration job and retain its output with the release record.

## Backup and recovery

- PostgreSQL: continuous WAL archiving plus daily snapshots; target RPO 5 minutes and RTO 60 minutes.
- Redis: append-only persistence and snapshots; Redis is transport state, while PostgreSQL remains authoritative.
- Secrets: back up references and provider configuration in the enterprise vault, never plaintext secret values in Git.
- Configuration: version ConfigMaps, policy, model profiles, routes, and deployment manifests.
- Quarterly: restore PostgreSQL into an isolated namespace, rotate all agent credentials, replay queued invocations, verify the audit chain, and record achieved RPO/RTO.

## Rollout and rollback

Use a rolling or canary deployment. Apply additive schema changes before application rollout. Validate `/ready`, error rate, queue age, dead-letter count, external-agent latency, circuit-open count, and audit verification. Roll back application images independently; do not drop newly added columns or tables during an emergency rollback.

## Incident runbook

1. Disable a compromised agent registration and rotate its credential.
2. Remove it from active routes and inspect invocations by agent ID.
3. Quarantine dead-letter messages; never replay until the root cause is understood.
4. Verify the hash-chained audit log and export the affected case evidence packs.
5. Restore routing gradually and monitor callback ownership failures, timeouts, and circuit state.
