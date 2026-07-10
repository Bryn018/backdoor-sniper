-- Backdoor Sniper — D1 (Cloudflare SQLite) schema
-- Equivalent to prisma/schema.prisma. Booleans are INTEGER 0/1,
-- JSON columns are TEXT. Created with `wrangler d1 execute`.

CREATE TABLE IF NOT EXISTS "User" (
  "id" TEXT PRIMARY KEY,
  "email" TEXT NOT NULL UNIQUE,
  "name" TEXT,
  "role" TEXT NOT NULL DEFAULT 'analyst',
  "createdAt" INTEGER NOT NULL DEFAULT 0,
  "updatedAt" INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS "Post" (
  "id" TEXT PRIMARY KEY,
  "title" TEXT NOT NULL,
  "content" TEXT,
  "published" INTEGER NOT NULL DEFAULT 0,
  "authorId" TEXT NOT NULL,
  "createdAt" INTEGER NOT NULL DEFAULT 0,
  "updatedAt" INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS "ScanRecord" (
  "id" TEXT PRIMARY KEY,
  "sourceHash" TEXT NOT NULL,
  "fileName" TEXT,
  "riskScore" INTEGER NOT NULL,
  "verdict" TEXT NOT NULL,
  "totalLines" INTEGER NOT NULL,
  "findings" TEXT NOT NULL,
  "sourcePreview" TEXT,
  "apiKeyId" TEXT,
  "actorIp" TEXT,
  "policyName" TEXT,
  "policyPassed" INTEGER,
  "policyViolations" TEXT,
  "scanMode" TEXT NOT NULL DEFAULT 'manual',
  "createdAt" INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS "ScanRecord_createdAt_idx" ON "ScanRecord"("createdAt");
CREATE INDEX IF NOT EXISTS "ScanRecord_verdict_idx" ON "ScanRecord"("verdict");
CREATE INDEX IF NOT EXISTS "ScanRecord_sourceHash_idx" ON "ScanRecord"("sourceHash");
CREATE INDEX IF NOT EXISTS "ScanRecord_apiKeyId_idx" ON "ScanRecord"("apiKeyId");

CREATE TABLE IF NOT EXISTS "ApiKey" (
  "id" TEXT PRIMARY KEY,
  "name" TEXT NOT NULL,
  "keyHash" TEXT NOT NULL UNIQUE,
  "prefix" TEXT NOT NULL,
  "scopes" TEXT NOT NULL DEFAULT '["scan:run","scan:read"]',
  "createdBy" TEXT NOT NULL DEFAULT 'system',
  "createdAt" INTEGER NOT NULL DEFAULT 0,
  "lastUsedAt" INTEGER,
  "revokedAt" INTEGER,
  "expiresAt" INTEGER,
  "useCount" INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS "ApiKey_prefix_idx" ON "ApiKey"("prefix");

CREATE TABLE IF NOT EXISTS "AuditLog" (
  "id" TEXT PRIMARY KEY,
  "createdAt" INTEGER NOT NULL DEFAULT 0,
  "actorType" TEXT NOT NULL,
  "actorId" TEXT,
  "actorName" TEXT,
  "actorIp" TEXT,
  "action" TEXT NOT NULL,
  "target" TEXT,
  "outcome" TEXT NOT NULL DEFAULT 'success',
  "verdict" TEXT,
  "riskScore" INTEGER,
  "policyPassed" INTEGER,
  "metadata" TEXT
);
CREATE INDEX IF NOT EXISTS "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");
CREATE INDEX IF NOT EXISTS "AuditLog_action_idx" ON "AuditLog"("action");
CREATE INDEX IF NOT EXISTS "AuditLog_actorId_idx" ON "AuditLog"("actorId");

CREATE TABLE IF NOT EXISTS "ScanPolicy" (
  "id" TEXT PRIMARY KEY,
  "name" TEXT NOT NULL UNIQUE,
  "description" TEXT,
  "rules" TEXT NOT NULL,
  "isDefault" INTEGER NOT NULL DEFAULT 0,
  "createdBy" TEXT NOT NULL DEFAULT 'system',
  "createdAt" INTEGER NOT NULL DEFAULT 0,
  "updatedAt" INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS "Suppression" (
  "id" TEXT PRIMARY KEY,
  "ruleId" TEXT NOT NULL,
  "sourceHash" TEXT,
  "fileName" TEXT,
  "line" INTEGER,
  "reason" TEXT NOT NULL,
  "createdBy" TEXT NOT NULL DEFAULT 'system',
  "createdAt" INTEGER NOT NULL DEFAULT 0,
  "expiresAt" INTEGER
);
CREATE INDEX IF NOT EXISTS "Suppression_ruleId_idx" ON "Suppression"("ruleId");
CREATE INDEX IF NOT EXISTS "Suppression_sourceHash_idx" ON "Suppression"("sourceHash");
CREATE UNIQUE INDEX IF NOT EXISTS "Suppression_uniq" ON "Suppression"("ruleId","sourceHash","line");

CREATE TABLE IF NOT EXISTS "WebhookEndpoint" (
  "id" TEXT PRIMARY KEY,
  "name" TEXT NOT NULL,
  "url" TEXT NOT NULL,
  "sinkType" TEXT NOT NULL DEFAULT 'generic',
  "events" TEXT NOT NULL DEFAULT '[]',
  "signingSecret" TEXT,
  "enabled" INTEGER NOT NULL DEFAULT 1,
  "lastStatus" TEXT,
  "lastDeliveryAt" INTEGER,
  "lastError" TEXT,
  "successCount" INTEGER NOT NULL DEFAULT 0,
  "failureCount" INTEGER NOT NULL DEFAULT 0,
  "createdBy" TEXT NOT NULL DEFAULT 'system',
  "createdAt" INTEGER NOT NULL DEFAULT 0,
  "updatedAt" INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS "WebhookEndpoint_enabled_idx" ON "WebhookEndpoint"("enabled");

CREATE TABLE IF NOT EXISTS "WebhookDelivery" (
  "id" TEXT PRIMARY KEY,
  "webhookId" TEXT NOT NULL,
  "eventType" TEXT NOT NULL,
  "payload" TEXT NOT NULL,
  "statusCode" INTEGER,
  "response" TEXT,
  "errorMessage" TEXT,
  "deliveredAt" INTEGER NOT NULL DEFAULT 0,
  "durationMs" INTEGER
);
CREATE INDEX IF NOT EXISTS "WebhookDelivery_webhookId_idx" ON "WebhookDelivery"("webhookId");
CREATE INDEX IF NOT EXISTS "WebhookDelivery_deliveredAt_idx" ON "WebhookDelivery"("deliveredAt");

CREATE TABLE IF NOT EXISTS "ScheduledScan" (
  "id" TEXT PRIMARY KEY,
  "name" TEXT NOT NULL,
  "schedule" TEXT NOT NULL,
  "sourceType" TEXT NOT NULL DEFAULT 'paste',
  "sourceData" TEXT NOT NULL,
  "policyName" TEXT,
  "notifyOnFail" INTEGER NOT NULL DEFAULT 1,
  "notifyOnCritical" INTEGER NOT NULL DEFAULT 0,
  "enabled" INTEGER NOT NULL DEFAULT 1,
  "lastRunAt" INTEGER,
  "lastRunStatus" TEXT,
  "lastScanId" TEXT,
  "nextRunAt" INTEGER,
  "createdBy" TEXT NOT NULL DEFAULT 'system',
  "createdAt" INTEGER NOT NULL DEFAULT 0,
  "updatedAt" INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS "ScheduledScan_enabled_idx" ON "ScheduledScan"("enabled");
CREATE INDEX IF NOT EXISTS "ScheduledScan_nextRunAt_idx" ON "ScheduledScan"("nextRunAt");

CREATE TABLE IF NOT EXISTS "ScheduledScanRun" (
  "id" TEXT PRIMARY KEY,
  "scheduledScanId" TEXT NOT NULL,
  "scanRecordId" TEXT,
  "startedAt" INTEGER NOT NULL DEFAULT 0,
  "finishedAt" INTEGER,
  "status" TEXT NOT NULL,
  "error" TEXT,
  "riskScore" INTEGER,
  "verdict" TEXT,
  "findingCount" INTEGER,
  "policyPassed" INTEGER
);
CREATE INDEX IF NOT EXISTS "ScheduledScanRun_scheduledScanId_idx" ON "ScheduledScanRun"("scheduledScanId");
CREATE INDEX IF NOT EXISTS "ScheduledScanRun_startedAt_idx" ON "ScheduledScanRun"("startedAt");
