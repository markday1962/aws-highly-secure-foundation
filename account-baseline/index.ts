import * as pulumi from "@pulumi/pulumi";
import { AuditLogs } from "./src/auditLogs";
import { Detection } from "./src/detection";
import { Hardening } from "./src/hardening";

const config = new pulumi.Config();
const awsConfig = new pulumi.Config("aws");

// The account this stack is pinned to. The provider refuses to run against
// any other, and policies use it to scope access to this account only.
const [accountId] = awsConfig.requireObject<string[]>("allowedAccountIds");
if (!/^\d{12}$/.test(accountId ?? "")) {
	throw new Error("aws:allowedAccountIds must hold the 12-digit account ID this stack deploys to");
}
const region = awsConfig.require("region");

const objectLockMode = config.get("objectLockMode") ?? "GOVERNANCE";
if (objectLockMode !== "GOVERNANCE" && objectLockMode !== "COMPLIANCE") {
	throw new Error(`objectLockMode must be GOVERNANCE or COMPLIANCE, got "${objectLockMode}"`);
}

const audit = new AuditLogs("learning-audit", {
	accountId,
	region,
	retentionDays: config.getNumber("logRetentionDays") ?? 365,
	objectLockMode,
});

new Detection("learning-detection", { accountId, region, logBucket: audit.bucket, logKey: audit.key });

new Hardening("learning-hardening", { imdsHopLimit: config.getNumber("imdsHopLimit") ?? 1 });

export const auditBucket = audit.bucket.id;
export const auditKeyArn = audit.key.arn;
export const trailArn = audit.trail.arn;
