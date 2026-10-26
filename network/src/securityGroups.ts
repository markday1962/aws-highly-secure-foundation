import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";

export interface TierSecurityGroupsArgs {
	vpcId: pulumi.Input<string>;
	/** Port the application listens on behind the load balancer. */
	appPort: number;
	/** Ports the data tier listens on, e.g. [5432] for PostgreSQL. */
	dataPorts: number[];
}

/**
 * One security group per tier, chained by reference rather than by CIDR:
 *
 *   internet ─443→ alb ─appPort→ app ─dataPorts→ data
 *                              app ─443→ endpoints, internet (through NAT + firewall)
 *
 * Groups start with no rules (the provider removes AWS's default allow-all
 * egress), so each rule below is the only way traffic is permitted.
 */
export class TierSecurityGroups extends pulumi.ComponentResource {
	public readonly alb: aws.ec2.SecurityGroup;
	public readonly app: aws.ec2.SecurityGroup;
	public readonly data: aws.ec2.SecurityGroup;
	public readonly endpoints: aws.ec2.SecurityGroup;

	constructor(name: string, args: TierSecurityGroupsArgs, opts?: pulumi.ComponentResourceOptions) {
		super("learning:network:TierSecurityGroups", name, {}, opts);

		const childOpts = { parent: this };
		const group = (tier: string, description: string) =>
			new aws.ec2.SecurityGroup(
				`${name}-${tier}`,
				{ vpcId: args.vpcId, name: `${name}-${tier}`, description, tags: { Name: `${name}-${tier}` } },
				childOpts,
			);

		this.alb = group("alb", "Internet-facing load balancers");
		this.app = group("app", "Application workloads");
		this.data = group("data", "Databases and caches");
		this.endpoints = group("endpoints", "Interface VPC endpoints");

		// Every rule here is TCP.
		const ingress = (id: string, rule: Omit<aws.vpc.SecurityGroupIngressRuleArgs, "ipProtocol">) =>
			new aws.vpc.SecurityGroupIngressRule(`${name}-${id}`, { ipProtocol: "tcp", ...rule }, childOpts);
		const egress = (id: string, rule: Omit<aws.vpc.SecurityGroupEgressRuleArgs, "ipProtocol">) =>
			new aws.vpc.SecurityGroupEgressRule(`${name}-${id}`, { ipProtocol: "tcp", ...rule }, childOpts);

		ingress("alb-in-https", {
			securityGroupId: this.alb.id,
			cidrIpv4: "0.0.0.0/0",
			fromPort: 443,
			toPort: 443,
			description: "HTTPS from the internet",
		});
		egress("alb-out-app", {
			securityGroupId: this.alb.id,
			referencedSecurityGroupId: this.app.id,
			fromPort: args.appPort,
			toPort: args.appPort,
			description: "To application targets",
		});

		ingress("app-in-alb", {
			securityGroupId: this.app.id,
			referencedSecurityGroupId: this.alb.id,
			fromPort: args.appPort,
			toPort: args.appPort,
			description: "From load balancers",
		});
		egress("app-out-https", {
			securityGroupId: this.app.id,
			cidrIpv4: "0.0.0.0/0",
			fromPort: 443,
			toPort: 443,
			description: "HTTPS to AWS APIs and allow-listed domains (filtered by Network Firewall)",
		});

		for (const port of args.dataPorts) {
			egress(`app-out-data-${port}`, {
				securityGroupId: this.app.id,
				referencedSecurityGroupId: this.data.id,
				fromPort: port,
				toPort: port,
				description: `To the data tier on ${port}`,
			});
			ingress(`data-in-app-${port}`, {
				securityGroupId: this.data.id,
				referencedSecurityGroupId: this.app.id,
				fromPort: port,
				toPort: port,
				description: `From the app tier on ${port}`,
			});
		}

		ingress("endpoints-in-app", {
			securityGroupId: this.endpoints.id,
			referencedSecurityGroupId: this.app.id,
			fromPort: 443,
			toPort: 443,
			description: "HTTPS from the app tier",
		});

		this.registerOutputs({});
	}
}
