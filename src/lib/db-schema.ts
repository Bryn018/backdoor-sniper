// Drizzle schema for Cloudflare D1 (SQLite).
// Mirrors prisma/schema.prisma 1:1. SQLite has no native boolean/JSON,
// so booleans are stored as 0/1 integers and JSON columns as TEXT.
import {
  sqliteTable,
  text,
  integer,
  index,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";

// Boolean helper: store as integer 0/1.
const bool = (name: string, def = false) =>
  integer(name, { mode: "boolean" }).notNull().default(def);

// JSON stored as text.
const jsonText = (name: string) => text(name);

export const users = sqliteTable("User", {
  id: text("id").primaryKey(), // cuid
  email: text("email").notNull().unique(),
  name: text("name"),
  role: text("role").notNull().default("analyst"),
  createdAt: integer("createdAt")
    .notNull()
    .default(0),
  updatedAt: integer("updatedAt")
    .notNull()
    .default(0),
});

export const posts = sqliteTable("Post", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  content: text("content"),
  published: bool("published", false),
  authorId: text("authorId").notNull(),
  createdAt: integer("createdAt")
    .notNull()
    .default(0),
  updatedAt: integer("updatedAt")
    .notNull()
    .default(0),
});

export const scanRecords = sqliteTable(
  "ScanRecord",
  {
    id: text("id").primaryKey(),
    sourceHash: text("sourceHash").notNull(),
    fileName: text("fileName"),
    riskScore: integer("riskScore").notNull(),
    verdict: text("verdict").notNull(),
    totalLines: integer("totalLines").notNull(),
    findings: jsonText("findings").notNull(),
    sourcePreview: text("sourcePreview"),
    apiKeyId: text("apiKeyId"),
    actorIp: text("actorIp"),
    policyName: text("policyName"),
    policyPassed: integer("policyPassed", { mode: "boolean" }),
    policyViolations: text("policyViolations"),
    scanMode: text("scanMode").notNull().default("manual"),
    createdAt: integer("createdAt")
      .notNull()
      .default(0),
  },
  (t) => ({
    createdAtIdx: index("ScanRecord_createdAt_idx").on(t.createdAt),
    verdictIdx: index("ScanRecord_verdict_idx").on(t.verdict),
    sourceHashIdx: index("ScanRecord_sourceHash_idx").on(t.sourceHash),
    apiKeyIdIdx: index("ScanRecord_apiKeyId_idx").on(t.apiKeyId),
  }),
);

export const apiKeys = sqliteTable(
  "ApiKey",
  {
    id: text("id").primaryKey(),
    name: text("name").notNull(),
    keyHash: text("keyHash").notNull().unique(),
    prefix: text("prefix").notNull(),
    scopes: jsonText("scopes").notNull().default('["scan:run","scan:read"]'),
    createdBy: text("createdBy").notNull().default("system"),
    createdAt: integer("createdAt")
      .notNull()
      .default(0),
    lastUsedAt: integer("lastUsedAt"),
    revokedAt: integer("revokedAt"),
    expiresAt: integer("expiresAt"),
    useCount: integer("useCount").notNull().default(0),
  },
  (t) => ({ prefixIdx: index("ApiKey_prefix_idx").on(t.prefix) }),
);

export const auditLogs = sqliteTable(
  "AuditLog",
  {
    id: text("id").primaryKey(),
    createdAt: integer("createdAt")
      .notNull()
      .default(0),
    actorType: text("actorType").notNull(),
    actorId: text("actorId"),
    actorName: text("actorName"),
    actorIp: text("actorIp"),
    action: text("action").notNull(),
    target: text("target"),
    outcome: text("outcome").notNull().default("success"),
    verdict: text("verdict"),
    riskScore: integer("riskScore"),
    policyPassed: integer("policyPassed", { mode: "boolean" }),
    metadata: text("metadata"),
  },
  (t) => ({
    createdAtIdx: index("AuditLog_createdAt_idx").on(t.createdAt),
    actionIdx: index("AuditLog_action_idx").on(t.action),
    actorIdIdx: index("AuditLog_actorId_idx").on(t.actorId),
  }),
);

export const scanPolicies = sqliteTable("ScanPolicy", {
  id: text("id").primaryKey(),
  name: text("name").notNull().unique(),
  description: text("description"),
  rules: jsonText("rules").notNull(),
  isDefault: bool("isDefault", false),
  createdBy: text("createdBy").notNull().default("system"),
  createdAt: integer("createdAt")
    .notNull()
    .default(0),
  updatedAt: integer("updatedAt")
    .notNull()
    .default(0),
});

export const suppressions = sqliteTable(
  "Suppression",
  {
    id: text("id").primaryKey(),
    ruleId: text("ruleId").notNull(),
    sourceHash: text("sourceHash"),
    fileName: text("fileName"),
    line: integer("line"),
    reason: text("reason").notNull(),
    createdBy: text("createdBy").notNull().default("system"),
    createdAt: integer("createdAt")
      .notNull()
      .default(0),
    expiresAt: integer("expiresAt"),
  },
  (t) => ({
    ruleIdIdx: index("Suppression_ruleId_idx").on(t.ruleId),
    sourceHashIdx: index("Suppression_sourceHash_idx").on(t.sourceHash),
    uniq: uniqueIndex("Suppression_uniq").on(
      t.ruleId,
      t.sourceHash,
      t.line,
    ),
  }),
);

export const webhookEndpoints = sqliteTable(
  "WebhookEndpoint",
  {
    id: text("id").primaryKey(),
    name: text("name").notNull(),
    url: text("url").notNull(),
    sinkType: text("sinkType").notNull().default("generic"),
    events: jsonText("events").notNull().default("[]"),
    signingSecret: text("signingSecret"),
    enabled: bool("enabled", true),
    lastStatus: text("lastStatus"),
    lastDeliveryAt: integer("lastDeliveryAt"),
    lastError: text("lastError"),
    successCount: integer("successCount").notNull().default(0),
    failureCount: integer("failureCount").notNull().default(0),
    createdBy: text("createdBy").notNull().default("system"),
    createdAt: integer("createdAt")
      .notNull()
      .default(0),
    updatedAt: integer("updatedAt")
      .notNull()
      .default(0),
  },
  (t) => ({ enabledIdx: index("WebhookEndpoint_enabled_idx").on(t.enabled) }),
);

export const webhookDeliveries = sqliteTable(
  "WebhookDelivery",
  {
    id: text("id").primaryKey(),
    webhookId: text("webhookId").notNull(),
    eventType: text("eventType").notNull(),
    payload: jsonText("payload").notNull(),
    statusCode: integer("statusCode"),
    response: text("response"),
    errorMessage: text("errorMessage"),
    deliveredAt: integer("deliveredAt")
      .notNull()
      .default(0),
    durationMs: integer("durationMs"),
  },
  (t) => ({
    webhookIdIdx: index("WebhookDelivery_webhookId_idx").on(t.webhookId),
    deliveredAtIdx: index("WebhookDelivery_deliveredAt_idx").on(t.deliveredAt),
  }),
);

export const scheduledScans = sqliteTable(
  "ScheduledScan",
  {
    id: text("id").primaryKey(),
    name: text("name").notNull(),
    schedule: text("schedule").notNull(),
    sourceType: text("sourceType").notNull().default("paste"),
    sourceData: text("sourceData").notNull(),
    policyName: text("policyName"),
    notifyOnFail: bool("notifyOnFail", true),
    notifyOnCritical: bool("notifyOnCritical", false),
    enabled: bool("enabled", true),
    lastRunAt: integer("lastRunAt"),
    lastRunStatus: text("lastRunStatus"),
    lastScanId: text("lastScanId"),
    nextRunAt: integer("nextRunAt"),
    createdBy: text("createdBy").notNull().default("system"),
    createdAt: integer("createdAt")
      .notNull()
      .default(0),
    updatedAt: integer("updatedAt")
      .notNull()
      .default(0),
  },
  (t) => ({
    enabledIdx: index("ScheduledScan_enabled_idx").on(t.enabled),
    nextRunAtIdx: index("ScheduledScan_nextRunAt_idx").on(t.nextRunAt),
  }),
);

export const scheduledScanRuns = sqliteTable(
  "ScheduledScanRun",
  {
    id: text("id").primaryKey(),
    scheduledScanId: text("scheduledScanId").notNull(),
    scanRecordId: text("scanRecordId"),
    startedAt: integer("startedAt")
      .notNull()
      .default(0),
    finishedAt: integer("finishedAt"),
    status: text("status").notNull(),
    error: text("error"),
    riskScore: integer("riskScore"),
    verdict: text("verdict"),
    findingCount: integer("findingCount"),
    policyPassed: integer("policyPassed", { mode: "boolean" }),
  },
  (t) => ({
    sscanIdIdx: index("ScheduledScanRun_scheduledScanId_idx").on(
      t.scheduledScanId,
    ),
    startedAtIdx: index("ScheduledScanRun_startedAt_idx").on(t.startedAt),
  }),
);

// Mapping Prisma model name -> drizzle table (for the compatibility facade).
export const tables = {
  user: users,
  post: posts,
  scanRecord: scanRecords,
  apiKey: apiKeys,
  auditLog: auditLogs,
  scanPolicy: scanPolicies,
  suppression: suppressions,
  webhookEndpoint: webhookEndpoints,
  webhookDelivery: webhookDeliveries,
  scheduledScan: scheduledScans,
  scheduledScanRun: scheduledScanRuns,
} as const;

export type TableName = keyof typeof tables;
