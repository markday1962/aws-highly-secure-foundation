import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import * as pulumi from "@pulumi/pulumi";

const created: pulumi.runtime.MockResourceArgs[] = [];

// Mocks must be set before the components are loaded.
pulumi.runtime.setMocks(
	{
		newResource: (args) => {
			created.push(args);
			return { id: `${args.name}_id`, state: { ...args.inputs, arn: `arn:aws:mock:::${args.name}` } };
		},
		call: (args) => args.inputs,
	},
	"secure-foundation-account-baseline",
	"test",
	false,
);

const ACCOUNT = "123456789012";

/** Child resources register asynchronously; wait until one with this name reaches the mock. */
async function registered(type: string, name: string): Promise<pulumi.runtime.MockResourceArgs> {
	for (let i = 0; i < 400; i++) {
		const match = created.find((r) => r.type === type && r.name === name);
		if (match) return match;
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
	const seen = created.filter((r) => r.type === type).map((r) => r.name);
	throw new Error(`${type} "${name}" was never registered (saw: ${seen.join(", ") || "none"})`);
}

describe("account baseline", () => {
	before(async () => {
		const { AuditLogs } = await import("../src/auditLogs");
		const { Detection } = await import("../src/detection");
		const { Hardening } = await import("../src/hardening");
		const audit = new AuditLogs("audit", { accountId: ACCOUNT, region: "eu-west-1", retentionDays: 365, objectLockMode: "GOVERNANCE" });
		new Detection("detect", { accountId: ACCOUNT, region: "eu-west-1", logBucket: audit.bucket, logKey: audit.key });
		new Hardening("harden", { imdsHopLimit: 1 });
	});

	it("keeps a tamper-evident, multi-region CloudTrail", async () => {
		const trail = await registered("aws:cloudtrail/trail:Trail", "audit");
		assert.equal(trail.inputs.isMultiRegionTrail, true);
		assert.equal(trail.inputs.includeGlobalServiceEvents, true);
		assert.equal(trail.inputs.enableLogFileValidation, true);
		assert.equal(trail.inputs.kmsKeyId, "arn:aws:mock:::audit");
	});

	it("locks audit logs against deletion for the retention period", async () => {
		const bucket = await registered("aws:s3/bucket:Bucket", "audit");
		assert.equal(bucket.inputs.objectLockEnabled, true);
		const lock = await registered("aws:s3/bucketObjectLockConfiguration:BucketObjectLockConfiguration", "audit");
		assert.deepEqual(lock.inputs.rule.defaultRetention, { mode: "GOVERNANCE", days: 365 });
	});

	it("lets only this account's trail write to the bucket", async () => {
		const policy = await registered("aws:s3/bucketPolicy:BucketPolicy", "audit");
		const statements = JSON.parse(policy.inputs.policy).Statement;
		const write = statements.find((s: { Sid: string }) => s.Sid === "CloudTrailWrite");
		assert.equal(write.Condition.StringEquals["aws:SourceArn"], `arn:aws:cloudtrail:eu-west-1:${ACCOUNT}:trail/audit-trail`);
		const tls = statements.find((s: { Sid: string }) => s.Sid === "DenyInsecureTransport");
		assert.equal(tls.Effect, "Deny");
	});

	it("enables GuardDuty runtime monitoring with managed agents", async () => {
		const runtime = await registered("aws:guardduty/detectorFeature:DetectorFeature", "detect-runtime_monitoring");
		assert.equal(runtime.inputs.status, "ENABLED");
		assert.equal(runtime.inputs.additionalConfigurations.length, 3);
		await registered("aws:guardduty/detectorFeature:DetectorFeature", "detect-s3_data_events");
	});

	it("subscribes Security Hub to FSBP and CIS 5.0.0", async () => {
		const cis = await registered("aws:securityhub/standardsSubscription:StandardsSubscription", "detect-cis-5-0-0");
		assert.equal(cis.inputs.standardsArn, "arn:aws:securityhub:eu-west-1::standards/cis-aws-foundations-benchmark/v/5.0.0");
		await registered("aws:securityhub/standardsSubscription:StandardsSubscription", "detect-fsbp");
	});

	it("records every resource type in AWS Config", async () => {
		const recorder = await registered("aws:cfg/recorder:Recorder", "detect");
		assert.deepEqual(recorder.inputs.recordingGroup, { allSupported: true, includeGlobalResourceTypes: true });
	});

	it("hardens account defaults", async () => {
		const imds = await registered("aws:ec2/instanceMetadataDefaults:InstanceMetadataDefaults", "harden");
		assert.equal(imds.inputs.httpTokens, "required");
		assert.equal(imds.inputs.httpPutResponseHopLimit, 1);
		const ebs = await registered("aws:ebs/encryptionByDefault:EncryptionByDefault", "harden");
		assert.equal(ebs.inputs.enabled, true);
		const s3 = await registered("aws:s3/accountPublicAccessBlock:AccountPublicAccessBlock", "harden");
		assert.equal(s3.inputs.restrictPublicBuckets, true);
	});
});
