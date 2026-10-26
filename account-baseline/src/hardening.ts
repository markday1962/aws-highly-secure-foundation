import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";

export interface HardeningArgs {
	/** IMDSv2 hop limit: 1 is strictest; containers on EC2 need 2. */
	imdsHopLimit: number;
}

/**
 * Account and region defaults that make the insecure option unavailable,
 * rather than relying on every resource being configured correctly.
 */
export class Hardening extends pulumi.ComponentResource {
	constructor(name: string, args: HardeningArgs, opts?: pulumi.ComponentResourceOptions) {
		super("learning:baseline:Hardening", name, {}, opts);

		const childOpts = { parent: this };

		// New EBS volumes and snapshot copies are always encrypted.
		new aws.ebs.EncryptionByDefault(name, { enabled: true }, childOpts);

		// EBS snapshots and AMIs can't be shared publicly.
		new aws.ebs.SnapshotBlockPublicAccess(name, { state: "block-all-sharing" }, childOpts);
		new aws.ec2.ImageBlockPublicAccess(name, { state: "block-new-sharing" }, childOpts);

		// New instances default to IMDSv2 (session tokens), which blocks the
		// SSRF-to-credentials attacks that IMDSv1 allows.
		new aws.ec2.InstanceMetadataDefaults(
			name,
			{ httpTokens: "required", httpPutResponseHopLimit: args.imdsHopLimit, httpEndpoint: "enabled", instanceMetadataTags: "disabled" },
			childOpts,
		);

		// No interactive serial console access to instances.
		new aws.ec2.SerialConsoleAccess(name, { enabled: false }, childOpts);

		// No S3 bucket or object in the account can be made public.
		new aws.s3.AccountPublicAccessBlock(
			name,
			{ blockPublicAcls: true, blockPublicPolicy: true, ignorePublicAcls: true, restrictPublicBuckets: true },
			childOpts,
		);

		// For any IAM users that exist (prefer IAM Identity Center): CIS benchmark password rules.
		new aws.iam.AccountPasswordPolicy(
			name,
			{
				minimumPasswordLength: 14,
				requireLowercaseCharacters: true,
				requireUppercaseCharacters: true,
				requireNumbers: true,
				requireSymbols: true,
				allowUsersToChangePassword: true,
				passwordReusePrevention: 24,
			},
			childOpts,
		);

		this.registerOutputs({});
	}
}
