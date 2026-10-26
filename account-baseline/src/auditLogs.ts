import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { policyDocument } from "./policy";

export interface AuditLogsArgs {
	accountId: string;
	region: string;
	/** Days each log object is locked against deletion and overwrite. */
	retentionDays: number;
	objectLockMode: "GOVERNANCE" | "COMPLIANCE";
}

/**
 * The account's audit trail (SEC04): a multi-region CloudTrail writing to a
 * write-once S3 bucket, encrypted with a customer-managed KMS key. AWS Config
 * delivers to the same bucket under its own prefix.
 *
 * The key and bucket are `protect`ed: they're meant to outlive this stack,
 * and Object Lock stops the logs being deleted for the retention period anyway.
 */
export class AuditLogs extends pulumi.ComponentResource {
	public readonly key: aws.kms.Key;
	public readonly bucket: aws.s3.Bucket;
	public readonly trail: aws.cloudtrail.Trail;

	constructor(name: string, args: AuditLogsArgs, opts?: pulumi.ComponentResourceOptions) {
		super("learning:baseline:AuditLogs", name, {}, opts);

		const childOpts = { parent: this };
		const keep = { parent: this, protect: true };
		const trailName = `${name}-trail`;
		const trailArn = `arn:aws:cloudtrail:${args.region}:${args.accountId}:trail/${trailName}`;

		this.key = new aws.kms.Key(
			name,
			{
				description: "Encrypts CloudTrail and AWS Config logs",
				enableKeyRotation: true,
				deletionWindowInDays: 30,
				policy: policyDocument([
					{
						sid: "AccountAdministration",
						principals: { type: "AWS", identifiers: [`arn:aws:iam::${args.accountId}:root`] },
						actions: ["kms:*"],
						resources: ["*"],
					},
					{
						// CloudTrail may encrypt logs only for this account's trail.
						sid: "CloudTrailEncrypt",
						principals: { type: "Service", identifiers: ["cloudtrail.amazonaws.com"] },
						actions: ["kms:GenerateDataKey*"],
						resources: ["*"],
						conditions: {
							StringEquals: { "aws:SourceArn": trailArn },
							StringLike: { "kms:EncryptionContext:aws:cloudtrail:arn": `arn:aws:cloudtrail:*:${args.accountId}:trail/*` },
						},
					},
					{
						sid: "CloudTrailDescribe",
						principals: { type: "Service", identifiers: ["cloudtrail.amazonaws.com"] },
						actions: ["kms:DescribeKey"],
						resources: ["*"],
						conditions: { StringEquals: { "aws:SourceArn": trailArn } },
					},
				]),
			},
			keep,
		);
		new aws.kms.Alias(name, { name: `alias/${name}`, targetKeyId: this.key.keyId }, childOpts);

		// Object Lock can only be switched on when a bucket is created.
		this.bucket = new aws.s3.Bucket(
			name,
			{ bucket: `${name}-${args.accountId}-${args.region}`, objectLockEnabled: true, forceDestroy: false },
			keep,
		);
		const bucketOpts = { parent: this, dependsOn: [this.bucket] };

		const publicAccessBlock = new aws.s3.BucketPublicAccessBlock(
			name,
			{ bucket: this.bucket.id, blockPublicAcls: true, blockPublicPolicy: true, ignorePublicAcls: true, restrictPublicBuckets: true },
			bucketOpts,
		);
		new aws.s3.BucketOwnershipControls(
			name,
			{ bucket: this.bucket.id, rule: { objectOwnership: "BucketOwnerEnforced" } },
			bucketOpts,
		);
		new aws.s3.BucketVersioning(name, { bucket: this.bucket.id, versioningConfiguration: { status: "Enabled" } }, bucketOpts);
		new aws.s3.BucketServerSideEncryptionConfiguration(
			name,
			{
				bucket: this.bucket.id,
				rules: [{ applyServerSideEncryptionByDefault: { sseAlgorithm: "aws:kms", kmsMasterKeyId: this.key.arn }, bucketKeyEnabled: true }],
			},
			bucketOpts,
		);
		new aws.s3.BucketObjectLockConfiguration(
			name,
			{
				bucket: this.bucket.id,
				objectLockEnabled: "Enabled",
				rule: { defaultRetention: { mode: args.objectLockMode, days: args.retentionDays } },
			},
			bucketOpts,
		);
		new aws.s3.BucketLifecycleConfiguration(
			name,
			{
				bucket: this.bucket.id,
				rules: [
					{
						// Logs are deleted a month after their lock expires, to keep storage costs bounded.
						id: "expire-after-retention",
						status: "Enabled",
						filter: {},
						expiration: { days: args.retentionDays + 30 },
						noncurrentVersionExpiration: { noncurrentDays: 30 },
					},
				],
			},
			bucketOpts,
		);

		const bucketPolicy = new aws.s3.BucketPolicy(
			name,
			{
				bucket: this.bucket.id,
				policy: policyDocument([
					{
						sid: "DenyInsecureTransport",
						effect: "Deny",
						principals: { type: "AWS", identifiers: ["*"] },
						actions: ["s3:*"],
						resources: [this.bucket.arn, pulumi.interpolate`${this.bucket.arn}/*`],
						conditions: { Bool: { "aws:SecureTransport": "false" } },
					},
					{
						sid: "CloudTrailAclCheck",
						principals: { type: "Service", identifiers: ["cloudtrail.amazonaws.com"] },
						actions: ["s3:GetBucketAcl"],
						resources: [this.bucket.arn],
						conditions: { StringEquals: { "aws:SourceArn": trailArn } },
					},
					{
						sid: "CloudTrailWrite",
						principals: { type: "Service", identifiers: ["cloudtrail.amazonaws.com"] },
						actions: ["s3:PutObject"],
						resources: [pulumi.interpolate`${this.bucket.arn}/cloudtrail/AWSLogs/${args.accountId}/*`],
						conditions: {
							StringEquals: { "s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceArn": trailArn },
						},
					},
				]),
			},
			{ parent: this, dependsOn: [publicAccessBlock] },
		);

		this.trail = new aws.cloudtrail.Trail(
			name,
			{
				name: trailName,
				s3BucketName: this.bucket.id,
				s3KeyPrefix: "cloudtrail",
				// Every region, plus global services such as IAM and STS.
				isMultiRegionTrail: true,
				includeGlobalServiceEvents: true,
				// Signed digest files prove the logs haven't been altered.
				enableLogFileValidation: true,
				kmsKeyId: this.key.arn,
				enableLogging: true,
			},
			{ parent: this, dependsOn: [bucketPolicy] },
		);

		this.registerOutputs({ bucket: this.bucket.id, trailArn: this.trail.arn });
	}
}
