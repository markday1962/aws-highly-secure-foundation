import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { LogEncryption } from "./logging";

export interface EgressFirewallArgs {
	vpcId: pulumi.Input<string>;
	region: string;
	/** One firewall subnet per AZ, in AZ order. */
	subnets: { az: string; subnet: aws.ec2.Subnet }[];
	/**
	 * Domains workloads may reach over HTTPS/HTTP, e.g. "amazonaws.com". Each
	 * allows the domain and all its subdomains. Everything else is dropped.
	 */
	allowedDomains: string[];
	/** AWS managed stateful rule groups (strict-order variants), checked before the allow-list. */
	managedRuleGroups: string[];
	logs: LogEncryption;
}

/**
 * AWS Network Firewall inspecting all traffic between the public subnets and
 * the Internet Gateway. Policy, in strict order:
 *
 *   1. AWS managed threat intelligence (malware, botnet C2, exploits, ...) drops known-bad traffic
 *   2. a domain allow-list (TLS SNI / HTTP Host) passes approved destinations
 *   3. everything else on an established connection is dropped and alerted
 */
export class EgressFirewall extends pulumi.ComponentResource {
	public readonly firewall: aws.networkfirewall.Firewall;

	constructor(name: string, args: EgressFirewallArgs, opts?: pulumi.ComponentResourceOptions) {
		super("learning:network:EgressFirewall", name, {}, opts);

		const childOpts = { parent: this };

		if (args.allowedDomains.length === 0) {
			throw new Error("EgressFirewall needs at least one allowed domain; with none, all egress is blocked");
		}

		// "example.com" matches only that host; ".example.com" matches its subdomains.
		const targets = args.allowedDomains.flatMap((d) => {
			const domain = d.replace(/^\.+/, "");
			return [domain, `.${domain}`];
		});

		const allowList = new aws.networkfirewall.RuleGroup(
			`${name}-allow-domains`,
			{
				name: `${name}-allow-domains`,
				type: "STATEFUL",
				capacity: 100,
				ruleGroup: {
					rulesSource: {
						rulesSourceList: {
							generatedRulesType: "ALLOWLIST",
							targetTypes: ["TLS_SNI", "HTTP_HOST"],
							targets,
						},
					},
					statefulRuleOptions: { ruleOrder: "STRICT_ORDER" },
				},
			},
			childOpts,
		);

		const managedReferences = args.managedRuleGroups.map((group, i) => ({
			priority: 10 + i * 10,
			resourceArn: `arn:aws:network-firewall:${args.region}:aws-managed:stateful-rulegroup/${group}`,
		}));

		const policy = new aws.networkfirewall.FirewallPolicy(
			name,
			{
				name,
				firewallPolicy: {
					// Stateless engine passes everything to the stateful engine, where
					// the real decisions are made.
					statelessDefaultActions: ["aws:forward_to_sfe"],
					statelessFragmentDefaultActions: ["aws:forward_to_sfe"],
					statefulEngineOptions: {
						ruleOrder: "STRICT_ORDER",
						// Drop a flow if the engine loses track of it mid-stream, rather than letting it through.
						streamExceptionPolicy: "REJECT",
					},
					// Default deny: anything no rule passes is dropped once the TCP
					// handshake completes (so the SNI / Host header can be inspected first).
					statefulDefaultActions: ["aws:drop_established", "aws:alert_established"],
					statefulRuleGroupReferences: [
						...managedReferences,
						{ priority: 10 + managedReferences.length * 10, resourceArn: allowList.arn },
					],
				},
			},
			childOpts,
		);

		this.firewall = new aws.networkfirewall.Firewall(
			name,
			{
				name,
				vpcId: args.vpcId,
				firewallPolicyArn: policy.arn,
				subnetMappings: args.subnets.map(({ subnet }) => ({ subnetId: subnet.id })),
				subnetChangeProtection: true,
				firewallPolicyChangeProtection: true,
				// Set to true for a real environment. Off here so `pulumi destroy` works.
				deleteProtection: false,
			},
			childOpts,
		);

		const alertLogs = args.logs.logGroup(`${name}-alert`, `/learning/network-firewall/alert`);
		const flowLogs = args.logs.logGroup(`${name}-flow`, `/learning/network-firewall/flow`);

		new aws.networkfirewall.LoggingConfiguration(
			name,
			{
				firewallArn: this.firewall.arn,
				loggingConfiguration: {
					logDestinationConfigs: [
						{ logType: "ALERT", logDestinationType: "CloudWatchLogs", logDestination: { logGroup: alertLogs.name } },
						{ logType: "FLOW", logDestinationType: "CloudWatchLogs", logDestination: { logGroup: flowLogs.name } },
					],
				},
			},
			childOpts,
		);

		this.registerOutputs({ firewallArn: this.firewall.arn });
	}

	/** The firewall endpoint in one AZ: the next hop for routes that send traffic through inspection. */
	endpointId(az: string): pulumi.Output<string> {
		return this.firewall.firewallStatuses.apply((statuses) => {
			const state = statuses[0]?.syncStates.find((s) => s.availabilityZone === az);
			const endpoint = state?.attachments[0]?.endpointId;
			if (!endpoint) {
				throw new Error(`Network Firewall has no endpoint in ${az}`);
			}
			return endpoint;
		});
	}
}
