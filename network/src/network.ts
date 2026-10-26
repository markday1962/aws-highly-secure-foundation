import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { addressPlan, Tier } from "./addressPlan";
import { DnsFirewall } from "./dnsFirewall";
import { EgressFirewall } from "./egressFirewall";
import { VpcEndpoints } from "./endpoints";
import { LogEncryption } from "./logging";
import { naclRules } from "./nacls";
import { policyDocument } from "./policy";
import { TierSecurityGroups } from "./securityGroups";

export type NatMode = "single" | "perAz";

export interface NetworkArgs {
	accountId: string;
	region: string;
	/** VPC address range. A /16 fits the address plan (see addressPlan.ts). */
	cidr: string;
	/** One subnet per tier in each of these AZs (max 3). */
	availabilityZones: string[];
	natGateways: NatMode;
	/** Port the app tier listens on behind the load balancer (1024-65535). */
	appPort: number;
	/** Ports the data tier listens on. */
	dataPorts: number[];
	/** Domains workloads may resolve and reach. Each includes its subdomains. */
	allowedDomains: string[];
	networkFirewall: { enabled: boolean; managedRuleGroups: string[] };
	dnsFirewall: { enabled: boolean; managedBlockListIds: string[] };
	/** Interface endpoint services, e.g. "ssm". Empty to skip interface endpoints. */
	interfaceEndpoints: string[];
	logRetentionDays: number;
}

/**
 * A four-tier VPC built for defence in depth (Well-Architected SEC05):
 *
 *   internet ⇄ IGW ⇄ [Network Firewall] ⇄ public (ALB, NAT) → app (workloads) → data (isolated)
 *
 * Every layer filters independently: route tables decide what's reachable at
 * all, network ACLs which tiers may talk, security groups which resources,
 * Network Firewall and DNS Firewall which destinations. Flow logs, firewall
 * logs and DNS query logs record it all, encrypted with a customer-managed key.
 */
export class Network extends pulumi.ComponentResource {
	public readonly vpc: aws.ec2.Vpc;
	public readonly subnets: Record<Tier, aws.ec2.Subnet[]>;
	public readonly securityGroups: TierSecurityGroups;
	public readonly natGateways: aws.ec2.NatGateway[];
	public readonly logKey: aws.kms.Key;

	constructor(name: string, args: NetworkArgs, opts?: pulumi.ComponentResourceOptions) {
		super("learning:network:Network", name, {}, opts);

		const plan = addressPlan(args.cidr, args.availabilityZones.length);
		const nacls = naclRules(plan, args.appPort, args.dataPorts);
		const azs = args.availabilityZones;
		const childOpts = { parent: this };
		const tag = (suffix: string) => ({ Name: `${name}-${suffix}` });

		const logs = new LogEncryption(
			`${name}-logs`,
			{ accountId: args.accountId, region: args.region, retentionDays: args.logRetentionDays },
			childOpts,
		);
		this.logKey = logs.key;

		this.vpc = new aws.ec2.Vpc(
			name,
			{ cidrBlock: plan.vpc, enableDnsSupport: true, enableDnsHostnames: true, tags: tag("vpc") },
			childOpts,
		);

		// ── Subnets: one per tier per AZ. None assign public IPs automatically.
		const makeSubnets = (tier: Tier) =>
			azs.map(
				(az, i) =>
					new aws.ec2.Subnet(
						`${name}-${tier}-${az}`,
						{
							vpcId: this.vpc.id,
							availabilityZone: az,
							cidrBlock: plan.tiers[tier][i],
							mapPublicIpOnLaunch: false,
							tags: { ...tag(`${tier}-${az}`), tier },
						},
						childOpts,
					),
			);
		this.subnets = {
			public: makeSubnets("public"),
			app: makeSubnets("app"),
			data: makeSubnets("data"),
			firewall: makeSubnets("firewall"),
		};

		// ── Ingress: the Internet Gateway.
		const igw = new aws.ec2.InternetGateway(name, { vpcId: this.vpc.id, tags: tag("igw") }, childOpts);

		// ── Inspection: Network Firewall sits between the IGW and the public subnets.
		const firewall = args.networkFirewall.enabled
			? new EgressFirewall(
					`${name}-nfw`,
					{
						vpcId: this.vpc.id,
						region: args.region,
						subnets: azs.map((az, i) => ({ az, subnet: this.subnets.firewall[i] })),
						allowedDomains: args.allowedDomains,
						managedRuleGroups: args.networkFirewall.managedRuleGroups,
						logs,
					},
					childOpts,
				)
			: undefined;

		const routeTable = (id: string) => new aws.ec2.RouteTable(`${name}-${id}`, { vpcId: this.vpc.id, tags: tag(id) }, childOpts);
		const associate = (id: string, subnet: aws.ec2.Subnet, table: aws.ec2.RouteTable) =>
			new aws.ec2.RouteTableAssociation(`${name}-${id}`, { subnetId: subnet.id, routeTableId: table.id }, childOpts);

		// Firewall subnets: the only route out is the IGW.
		const firewallTable = routeTable("firewall");
		new aws.ec2.Route(
			`${name}-firewall-internet`,
			{ routeTableId: firewallTable.id, destinationCidrBlock: "0.0.0.0/0", gatewayId: igw.id },
			childOpts,
		);
		azs.forEach((az, i) => associate(`firewall-${az}`, this.subnets.firewall[i], firewallTable));

		// Public subnets: internet traffic goes through this AZ's firewall endpoint
		// (or straight to the IGW if the firewall is off).
		azs.forEach((az, i) => {
			const table = routeTable(`public-${az}`);
			new aws.ec2.Route(
				`${name}-public-${az}-internet`,
				{
					routeTableId: table.id,
					destinationCidrBlock: "0.0.0.0/0",
					...(firewall ? { vpcEndpointId: firewall.endpointId(az) } : { gatewayId: igw.id }),
				},
				childOpts,
			);
			associate(`public-${az}`, this.subnets.public[i], table);
		});

		// Return traffic arriving at the IGW must also pass the firewall, so the
		// IGW gets its own "edge" route table sending each public subnet's
		// traffic to the same AZ's firewall endpoint (symmetric routing).
		if (firewall) {
			const edgeTable = routeTable("igw-edge");
			azs.forEach((az, i) => {
				new aws.ec2.Route(
					`${name}-igw-edge-${az}`,
					{ routeTableId: edgeTable.id, destinationCidrBlock: plan.tiers.public[i], vpcEndpointId: firewall.endpointId(az) },
					childOpts,
				);
			});
			new aws.ec2.RouteTableAssociation(`${name}-igw-edge`, { gatewayId: igw.id, routeTableId: edgeTable.id }, childOpts);
		}

		// ── Egress: NAT gateways in the public subnets.
		const natAzs = args.natGateways === "perAz" ? azs : [azs[0]];
		this.natGateways = natAzs.map((az) => {
			const eip = new aws.ec2.Eip(`${name}-nat-${az}`, { domain: "vpc", tags: tag(`nat-${az}`) }, childOpts);
			return new aws.ec2.NatGateway(
				`${name}-${az}`,
				{ allocationId: eip.id, subnetId: this.subnets.public[azs.indexOf(az)].id, tags: tag(`nat-${az}`) },
				{ parent: this, dependsOn: [igw] },
			);
		});

		// App subnets: internet traffic via NAT (then firewall). One table per AZ
		// so each can use its own NAT.
		const appTables = azs.map((az, i) => {
			const table = routeTable(`app-${az}`);
			const nat = this.natGateways[args.natGateways === "perAz" ? i : 0];
			new aws.ec2.Route(
				`${name}-app-${az}-egress`,
				{ routeTableId: table.id, destinationCidrBlock: "0.0.0.0/0", natGatewayId: nat.id },
				childOpts,
			);
			associate(`app-${az}`, this.subnets.app[i], table);
			return table;
		});

		// Data subnets: no default route at all. They can reach only the VPC.
		const dataTable = routeTable("data");
		azs.forEach((az, i) => associate(`data-${az}`, this.subnets.data[i], dataTable));

		// ── Network ACLs per tier, and the default ACL stripped of its allow-all rules.
		for (const tier of Object.keys(nacls) as Tier[]) {
			new aws.ec2.NetworkAcl(
				`${name}-${tier}`,
				{
					vpcId: this.vpc.id,
					subnetIds: this.subnets[tier].map((s) => s.id),
					ingress: nacls[tier].ingress,
					egress: nacls[tier].egress,
					tags: tag(`${tier}-nacl`),
				},
				childOpts,
			);
		}
		new aws.ec2.DefaultNetworkAcl(
			name,
			{ defaultNetworkAclId: this.vpc.defaultNetworkAclId, tags: tag("default-nacl-deny-all") },
			// Every subnet has its own ACL; don't fight AWS over the default ACL's associations.
			{ parent: this, ignoreChanges: ["subnetIds"] },
		);

		// The VPC's built-in default security group, with every rule removed (CIS 5.4).
		new aws.ec2.DefaultSecurityGroup(
			name,
			{ vpcId: this.vpc.id, ingress: [], egress: [], tags: tag("default-sg-locked") },
			childOpts,
		);

		// ── Security groups per tier, chained by reference.
		this.securityGroups = new TierSecurityGroups(
			`${name}-sg`,
			{ vpcId: this.vpc.id, appPort: args.appPort, dataPorts: args.dataPorts },
			childOpts,
		);

		// ── Private access to AWS APIs.
		new VpcEndpoints(
			`${name}-vpce`,
			{
				vpcId: this.vpc.id,
				region: args.region,
				accountId: args.accountId,
				gatewayRouteTableIds: appTables.map((t) => t.id),
				interfaceServices: args.interfaceEndpoints,
				interfaceSubnetIds: this.subnets.app.map((s) => s.id),
				securityGroupId: this.securityGroups.endpoints.id,
			},
			childOpts,
		);

		// ── DNS: walled-garden filtering and query logging.
		if (args.dnsFirewall.enabled) {
			new DnsFirewall(
				`${name}-dns`,
				{
					vpcId: this.vpc.id,
					allowedDomains: args.allowedDomains,
					managedBlockListIds: args.dnsFirewall.managedBlockListIds,
					logs,
				},
				childOpts,
			);
		}

		// ── VPC Flow Logs: every accepted and rejected flow, at one-minute granularity.
		this.flowLogs(name, args, logs);

		this.registerOutputs({ vpcId: this.vpc.id });
	}

	private flowLogs(name: string, args: NetworkArgs, logs: LogEncryption) {
		const childOpts = { parent: this };
		const logGroup = logs.logGroup(`${name}-flow`, `/learning/vpc/flow-logs`);

		const role = new aws.iam.Role(
			`${name}-flow-logs`,
			{
				assumeRolePolicy: policyDocument([
					{
						principals: { type: "Service", identifiers: ["vpc-flow-logs.amazonaws.com"] },
						actions: ["sts:AssumeRole"],
						// Only flow logs in this account may use the role (confused-deputy protection).
						conditions: {
							StringEquals: { "aws:SourceAccount": args.accountId },
							ArnLike: { "aws:SourceArn": `arn:aws:ec2:${args.region}:${args.accountId}:vpc-flow-log/*` },
						},
					},
				]),
			},
			childOpts,
		);
		new aws.iam.RolePolicy(
			`${name}-flow-logs`,
			{
				role: role.name,
				policy: policyDocument([
					{
						actions: ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
						resources: [logGroup.arn, pulumi.interpolate`${logGroup.arn}:*`],
					},
				]),
			},
			childOpts,
		);

		new aws.ec2.FlowLog(
			name,
			{
				vpcId: this.vpc.id,
				trafficType: "ALL",
				logDestinationType: "cloud-watch-logs",
				logDestination: logGroup.arn,
				iamRoleArn: role.arn,
				maxAggregationInterval: 60,
				// Version 5 fields add packet-level addresses, direction and path, which
				// show traffic through NAT and the firewall as it really flowed.
				logFormat: [
					"${version}", "${account-id}", "${interface-id}", "${srcaddr}", "${dstaddr}", "${srcport}", "${dstport}",
					"${protocol}", "${packets}", "${bytes}", "${start}", "${end}", "${action}", "${log-status}", "${vpc-id}",
					"${subnet-id}", "${instance-id}", "${tcp-flags}", "${type}", "${pkt-srcaddr}", "${pkt-dstaddr}",
					"${region}", "${az-id}", "${flow-direction}", "${traffic-path}",
				].join(" "),
				tags: { Name: `${name}-flow-log` },
			},
			childOpts,
		);
	}
}
