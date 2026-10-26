import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { LogEncryption } from "./logging";

export interface DnsFirewallArgs {
	vpcId: pulumi.Input<string>;
	/** Domains the VPC may resolve. Each allows the domain and all its subdomains. */
	allowedDomains: string[];
	/**
	 * IDs of AWS managed domain lists to block first (they vary by region):
	 *   aws route53resolver list-firewall-domain-lists --region eu-west-1 \
	 *     --query "FirewallDomainLists[?ManagedOwnerName=='Route 53 Resolver DNS Firewall']"
	 */
	managedBlockListIds: string[];
	logs: LogEncryption;
}

/**
 * Route 53 Resolver DNS Firewall as a "walled garden": block known-bad domains,
 * allow only the approved list, and answer NXDOMAIN for everything else. Also
 * logs every DNS query the VPC makes.
 */
export class DnsFirewall extends pulumi.ComponentResource {
	constructor(name: string, args: DnsFirewallArgs, opts?: pulumi.ComponentResourceOptions) {
		super("learning:network:DnsFirewall", name, {}, opts);

		const childOpts = { parent: this };

		const allowed = new aws.route53.ResolverFirewallDomainList(
			`${name}-allowed`,
			{
				name: `${name}-allowed`,
				domains: [
					...args.allowedDomains.flatMap((d) => [d, `*.${d}`]),
					// VPC-internal names (EC2 hostnames, private hosted zones under .internal).
					"*.internal",
				],
			},
			childOpts,
		);

		const everything = new aws.route53.ResolverFirewallDomainList(
			`${name}-everything`,
			{ name: `${name}-everything`, domains: ["*"] },
			childOpts,
		);

		const ruleGroup = new aws.route53.ResolverFirewallRuleGroup(name, { name }, childOpts);

		args.managedBlockListIds.forEach((listId, i) => {
			new aws.route53.ResolverFirewallRule(
				`${name}-block-managed-${i}`,
				{
					name: `block-managed-${i}`,
					firewallRuleGroupId: ruleGroup.id,
					firewallDomainListId: listId,
					priority: 100 + i,
					action: "BLOCK",
					blockResponse: "NXDOMAIN",
				},
				childOpts,
			);
		});

		new aws.route53.ResolverFirewallRule(
			`${name}-allow`,
			{
				name: "allow-approved",
				firewallRuleGroupId: ruleGroup.id,
				firewallDomainListId: allowed.id,
				priority: 200,
				action: "ALLOW",
			},
			childOpts,
		);

		new aws.route53.ResolverFirewallRule(
			`${name}-block-rest`,
			{
				name: "block-everything-else",
				firewallRuleGroupId: ruleGroup.id,
				firewallDomainListId: everything.id,
				priority: 300,
				action: "BLOCK",
				blockResponse: "NXDOMAIN",
			},
			childOpts,
		);

		new aws.route53.ResolverFirewallRuleGroupAssociation(
			name,
			{ name, firewallRuleGroupId: ruleGroup.id, vpcId: args.vpcId, priority: 101 },
			childOpts,
		);

		// Fail closed: if DNS Firewall is unavailable, queries are blocked rather than allowed.
		new aws.route53.ResolverFirewallConfig(name, { resourceId: args.vpcId, firewallFailOpen: "DISABLED" }, childOpts);

		const queryLogs = args.logs.logGroup(`${name}-queries`, `/learning/dns/queries`);
		const queryLogConfig = new aws.route53.ResolverQueryLogConfig(
			name,
			{ name, destinationArn: queryLogs.arn },
			childOpts,
		);
		new aws.route53.ResolverQueryLogConfigAssociation(
			name,
			{ resolverQueryLogConfigId: queryLogConfig.id, resourceId: args.vpcId },
			childOpts,
		);

		this.registerOutputs({});
	}
}
