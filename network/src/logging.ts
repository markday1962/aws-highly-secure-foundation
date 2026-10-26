import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { policyDocument } from "./policy";

export interface LogEncryptionArgs {
	accountId: string;
	region: string;
	/** Days CloudWatch keeps each log group. */
	retentionDays: number;
}

/**
 * A customer-managed KMS key for this VPC's logs (flow logs, firewall logs,
 * DNS query logs), and a factory for log groups encrypted with it.
 */
export class LogEncryption extends pulumi.ComponentResource {
	public readonly key: aws.kms.Key;
	private readonly retentionDays: number;

	constructor(name: string, args: LogEncryptionArgs, opts?: pulumi.ComponentResourceOptions) {
		super("learning:network:LogEncryption", name, {}, opts);

		this.retentionDays = args.retentionDays;
		const accountRoot = `arn:aws:iam::${args.accountId}:root`;

		this.key = new aws.kms.Key(
			name,
			{
				description: "Encrypts VPC flow, firewall and DNS query logs",
				enableKeyRotation: true,
				deletionWindowInDays: 30,
				policy: policyDocument([
					{
						// Lets IAM policies in this account govern the key. Without it the
						// key can become unmanageable.
						sid: "AccountAdministration",
						principals: { type: "AWS", identifiers: [accountRoot] },
						actions: ["kms:*"],
						resources: ["*"],
					},
					{
						// CloudWatch Logs encrypts log groups in this account and region only.
						sid: "CloudWatchLogsUse",
						principals: { type: "Service", identifiers: [`logs.${args.region}.amazonaws.com`] },
						actions: ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"],
						resources: ["*"],
						conditions: {
							ArnLike: {
								"kms:EncryptionContext:aws:logs:arn": `arn:aws:logs:${args.region}:${args.accountId}:log-group:*`,
							},
						},
					},
				]),
			},
			{ parent: this },
		);

		new aws.kms.Alias(name, { name: `alias/${name}`, targetKeyId: this.key.keyId }, { parent: this });

		this.registerOutputs({ keyArn: this.key.arn });
	}

	/** A KMS-encrypted log group with this component's retention. */
	logGroup(name: string, logGroupName: string): aws.cloudwatch.LogGroup {
		return new aws.cloudwatch.LogGroup(
			name,
			{ name: logGroupName, retentionInDays: this.retentionDays, kmsKeyId: this.key.arn },
			{ parent: this },
		);
	}
}
