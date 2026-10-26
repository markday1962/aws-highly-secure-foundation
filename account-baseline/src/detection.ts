import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { policyDocument } from "./policy";

export interface DetectionArgs {
	accountId: string;
	region: string;
	/** Where AWS Config delivers configuration snapshots and history. */
	logBucket: aws.s3.Bucket;
	logKey: aws.kms.Key;
}

const GUARDDUTY_FEATURES = ["S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION", "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS"];

/**
 * Detection (SEC04): AWS Config records every resource change, GuardDuty
 * watches for threats, Security Hub scores the account against AWS FSBP and
 * the CIS benchmark, and IAM Access Analyzer flags anything shared outside
 * the account.
 */
export class Detection extends pulumi.ComponentResource {
	constructor(name: string, args: DetectionArgs, opts?: pulumi.ComponentResourceOptions) {
		super("learning:baseline:Detection", name, {}, opts);

		const childOpts = { parent: this };

		// ── AWS Config: the inventory and change history Security Hub evaluates.
		const configRole = new aws.iam.Role(
			`${name}-config`,
			{
				assumeRolePolicy: policyDocument([
					{
						principals: { type: "Service", identifiers: ["config.amazonaws.com"] },
						actions: ["sts:AssumeRole"],
						conditions: { StringEquals: { "aws:SourceAccount": args.accountId } },
					},
				]),
			},
			childOpts,
		);
		new aws.iam.RolePolicyAttachment(
			`${name}-config`,
			{ role: configRole.name, policyArn: "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole" },
			childOpts,
		);
		new aws.iam.RolePolicy(
			`${name}-config-delivery`,
			{
				role: configRole.name,
				policy: policyDocument([
					{ actions: ["s3:GetBucketAcl"], resources: [args.logBucket.arn] },
					{
						actions: ["s3:PutObject"],
						resources: [pulumi.interpolate`${args.logBucket.arn}/config/AWSLogs/${args.accountId}/*`],
						conditions: { StringEquals: { "s3:x-amz-acl": "bucket-owner-full-control" } },
					},
					{ actions: ["kms:GenerateDataKey", "kms:Decrypt"], resources: [args.logKey.arn] },
				]),
			},
			childOpts,
		);

		const recorder = new aws.cfg.Recorder(
			name,
			{
				name: "default",
				roleArn: configRole.arn,
				// Global resources (IAM) are recorded here; record them in one region only.
				recordingGroup: { allSupported: true, includeGlobalResourceTypes: true },
			},
			childOpts,
		);
		const channel = new aws.cfg.DeliveryChannel(
			name,
			{
				name: "default",
				s3BucketName: args.logBucket.id,
				s3KeyPrefix: "config",
				s3KmsKeyArn: args.logKey.arn,
				snapshotDeliveryProperties: { deliveryFrequency: "TwentyFour_Hours" },
			},
			{ parent: this, dependsOn: [recorder] },
		);
		const recording = new aws.cfg.RecorderStatus(
			name,
			{ name: recorder.name, isEnabled: true },
			{ parent: this, dependsOn: [channel] },
		);

		// ── GuardDuty: threat detection from CloudTrail, VPC flow, DNS and runtime signals.
		const detector = new aws.guardduty.Detector(name, { enable: true, findingPublishingFrequency: "FIFTEEN_MINUTES" }, childOpts);
		for (const feature of GUARDDUTY_FEATURES) {
			new aws.guardduty.DetectorFeature(
				`${name}-${feature.toLowerCase()}`,
				{ detectorId: detector.id, name: feature, status: "ENABLED" },
				childOpts,
			);
		}
		new aws.guardduty.DetectorFeature(
			`${name}-runtime_monitoring`,
			{
				detectorId: detector.id,
				name: "RUNTIME_MONITORING",
				status: "ENABLED",
				// GuardDuty installs and manages its own agents on EKS, ECS Fargate and EC2.
				additionalConfigurations: ["EKS_ADDON_MANAGEMENT", "ECS_FARGATE_AGENT_MANAGEMENT", "EC2_AGENT_MANAGEMENT"].map((n) => ({
					name: n,
					status: "ENABLED",
				})),
			},
			childOpts,
		);

		// ── Security Hub: continuous checks against best-practice standards.
		const hub = new aws.securityhub.Account(
			name,
			{
				// Subscribe to the chosen standards explicitly, below.
				enableDefaultStandards: false,
				// One finding per control, however many standards include it.
				controlFindingGenerator: "SECURITY_CONTROL",
				autoEnableControls: true,
			},
			{ parent: this, dependsOn: [recording] },
		);
		for (const [id, arn] of [
			["fsbp", `arn:aws:securityhub:${args.region}::standards/aws-foundational-security-best-practices/v/1.0.0`],
			["cis-5-0-0", `arn:aws:securityhub:${args.region}::standards/cis-aws-foundations-benchmark/v/5.0.0`],
		]) {
			new aws.securityhub.StandardsSubscription(`${name}-${id}`, { standardsArn: arn }, { parent: this, dependsOn: [hub] });
		}

		// ── IAM Access Analyzer: flags resources shared with principals outside the account.
		new aws.accessanalyzer.Analyzer(name, { analyzerName: `${name}-external-access`, type: "ACCOUNT" }, childOpts);

		this.registerOutputs({ detectorId: detector.id });
	}
}
