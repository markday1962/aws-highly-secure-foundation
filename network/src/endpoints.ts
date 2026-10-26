import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { policyDocument, Statement } from "./policy";

/** Services whose interface endpoints accept an endpoint policy. */
const SUPPORTS_POLICY = new Set(["ssm", "sts", "kms", "logs", "secretsmanager", "ecr.api", "ecr.dkr", "sqs", "sns", "monitoring"]);

export interface VpcEndpointsArgs {
	vpcId: pulumi.Input<string>;
	region: string;
	accountId: string;
	/** Route tables that get the free S3 and DynamoDB gateway endpoints. */
	gatewayRouteTableIds: pulumi.Input<string>[];
	/** Interface endpoints: one ENI per subnet. Empty to skip them. */
	interfaceServices: string[];
	interfaceSubnetIds: pulumi.Input<string>[];
	securityGroupId: pulumi.Input<string>;
}

/**
 * Private connectivity to AWS APIs, so that traffic never crosses the internet
 * (or the NAT). Endpoint policies only allow principals from this account,
 * which stops stolen credentials from another account using the endpoint to
 * exfiltrate data (a "data perimeter").
 */
export class VpcEndpoints extends pulumi.ComponentResource {
	constructor(name: string, args: VpcEndpointsArgs, opts?: pulumi.ComponentResourceOptions) {
		super("learning:network:VpcEndpoints", name, {}, opts);

		const childOpts = { parent: this };
		const thisAccountOnly: Statement = {
			sid: "ThisAccountPrincipalsOnly",
			principals: { type: "AWS", identifiers: ["*"] },
			actions: ["*"],
			resources: ["*"],
			conditions: { StringEquals: { "aws:PrincipalAccount": args.accountId } },
		};

		new aws.ec2.VpcEndpoint(
			`${name}-s3`,
			{
				vpcId: args.vpcId,
				serviceName: `com.amazonaws.${args.region}.s3`,
				vpcEndpointType: "Gateway",
				routeTableIds: args.gatewayRouteTableIds,
				policy: policyDocument([
					thisAccountOnly,
					{
						// Amazon Linux package repositories are AWS-owned S3 buckets read
						// anonymously, so they need their own exception.
						sid: "AmazonLinuxRepositories",
						principals: { type: "AWS", identifiers: ["*"] },
						actions: ["s3:GetObject"],
						resources: [
							`arn:aws:s3:::al2023-repos-${args.region}-*/*`,
							`arn:aws:s3:::amazonlinux-2-repos-${args.region}/*`,
						],
					},
				]),
				tags: { Name: `${name}-s3` },
			},
			childOpts,
		);

		new aws.ec2.VpcEndpoint(
			`${name}-dynamodb`,
			{
				vpcId: args.vpcId,
				serviceName: `com.amazonaws.${args.region}.dynamodb`,
				vpcEndpointType: "Gateway",
				routeTableIds: args.gatewayRouteTableIds,
				policy: policyDocument([thisAccountOnly]),
				tags: { Name: `${name}-dynamodb` },
			},
			childOpts,
		);

		for (const service of args.interfaceServices) {
			new aws.ec2.VpcEndpoint(
				`${name}-${service}`,
				{
					vpcId: args.vpcId,
					serviceName: `com.amazonaws.${args.region}.${service}`,
					vpcEndpointType: "Interface",
					subnetIds: args.interfaceSubnetIds,
					securityGroupIds: [args.securityGroupId],
					// Resolve the service's normal hostname to the private endpoint.
					privateDnsEnabled: true,
					policy: SUPPORTS_POLICY.has(service) ? policyDocument([thisAccountOnly]) : undefined,
					tags: { Name: `${name}-${service}` },
				},
				childOpts,
			);
		}

		this.registerOutputs({});
	}
}
