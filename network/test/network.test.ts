import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import * as pulumi from "@pulumi/pulumi";
import { subnetCidr } from "../src/cidr";
import { addressPlan } from "../src/addressPlan";
import { naclRules } from "../src/nacls";

const created: pulumi.runtime.MockResourceArgs[] = [];
const AZS = ["eu-west-1a", "eu-west-1b", "eu-west-1c"];

// Mocks must be set before the network module is loaded.
pulumi.runtime.setMocks(
	{
		newResource: (args) => {
			created.push(args);
			const state: Record<string, unknown> = { ...args.inputs, arn: `arn:aws:mock:::${args.name}` };
			if (args.type === "aws:networkfirewall/firewall:Firewall") {
				state.firewallStatuses = [
					{ syncStates: AZS.map((az) => ({ availabilityZone: az, attachments: [{ endpointId: `vpce-fw-${az}`, subnetId: "x" }] })) },
				];
			}
			if (args.type === "aws:ec2/vpc:Vpc") state.defaultNetworkAclId = "acl-default";
			return { id: `${args.name}_id`, state };
		},
		call: (args) => args.inputs,
	},
	"highly-secure-foundation-network",
	"test",
	false,
);

type NetworkModule = typeof import("../src/network");
let Network: NetworkModule["Network"];
type NetworkArgs = import("../src/network").NetworkArgs;

function args(overrides: Partial<NetworkArgs> = {}): NetworkArgs {
	return {
		accountId: "123456789012",
		region: "eu-west-1",
		cidr: "10.0.0.0/16",
		availabilityZones: AZS,
		natGateways: "perAz",
		appPort: 8443,
		dataPorts: [5432],
		allowedDomains: ["amazonaws.com"],
		networkFirewall: { enabled: true, managedRuleGroups: ["MalwareDomainsStrictOrder"] },
		dnsFirewall: { enabled: true, managedBlockListIds: [] },
		interfaceEndpoints: ["ssm", "ssmmessages", "sts"],
		logRetentionDays: 365,
		...overrides,
	};
}

function find(type: string, name: string) {
	return created.find((r) => r.type === type && r.name === name);
}

/** Child resources register asynchronously; wait until one with this name reaches the mock. */
async function registered(type: string, name: string): Promise<pulumi.runtime.MockResourceArgs> {
	for (let i = 0; i < 400; i++) {
		const match = find(type, name);
		if (match) return match;
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
	const seen = created.filter((r) => r.type === type).map((r) => r.name);
	throw new Error(`${type} "${name}" was never registered (saw: ${seen.join(", ") || "none"})`);
}

/** Lets pending registrations land, for asserting that something was *not* created. */
async function settle() {
	await new Promise((resolve) => setTimeout(resolve, 100));
}

describe("subnetCidr", () => {
	it("carves subnets like Terraform's cidrsubnet()", () => {
		assert.equal(subnetCidr("10.0.0.0/16", 3, 2), "10.0.64.0/19");
		assert.equal(subnetCidr("10.0.0.0/16", 8, 96), "10.0.96.0/24");
		assert.equal(subnetCidr("10.0.0.0/16", 12, 1585), "10.0.99.16/28");
	});

	it("rejects ranges that don't fit", () => {
		assert.throws(() => subnetCidr("10.0.0.0/16", 4, 16), /doesn't fit/);
		assert.throws(() => subnetCidr("10.0.0.0/30", 4, 0), /cannot add/);
		assert.throws(() => subnetCidr("10.0.0.1/16", 4, 0), /host bits/);
	});
});

describe("addressPlan", () => {
	it("lays out four tiers without overlap", () => {
		const plan = addressPlan("10.0.0.0/16", 3);
		assert.deepEqual(plan.tiers.app, ["10.0.0.0/19", "10.0.32.0/19", "10.0.64.0/19"]);
		assert.deepEqual(plan.tiers.public, ["10.0.96.0/24", "10.0.97.0/24", "10.0.98.0/24"]);
		assert.deepEqual(plan.tiers.firewall, ["10.0.99.0/28", "10.0.99.16/28", "10.0.99.32/28"]);
		assert.deepEqual(plan.tiers.data, ["10.0.100.0/22", "10.0.104.0/22", "10.0.108.0/22"]);

		const range = (cidr: string) => {
			const [ip, bits] = cidr.split("/");
			const start = ip.split(".").reduce((a, o) => a * 256 + Number(o), 0);
			return [start, start + 2 ** (32 - Number(bits)) - 1];
		};
		const all = Object.values(plan.tiers).flat().map(range).sort((a, b) => a[0] - b[0]);
		for (let i = 1; i < all.length; i++) {
			assert.ok(all[i][0] > all[i - 1][1], "subnets overlap");
		}
	});

	it("rejects more than three AZs", () => {
		assert.throws(() => addressPlan("10.0.0.0/16", 4), /1-3 availability zones/);
	});
});

describe("naclRules", () => {
	const plan = addressPlan("10.0.0.0/16", 3);
	const nacls = naclRules(plan, 8443, [5432]);

	it("never lets the internet reach the data tier", () => {
		for (const rule of [...nacls.data.ingress, ...nacls.data.egress]) {
			assert.notEqual(rule.cidrBlock, "0.0.0.0/0");
		}
	});

	it("only lets the app tier reach the data tier, on the data ports", () => {
		const fromApp = nacls.data.ingress.filter((r) => plan.tiers.app.includes(r.cidrBlock));
		assert.equal(fromApp.length, 3);
		assert.ok(fromApp.every((r) => r.protocol === "tcp" && r.fromPort === 5432 && r.toPort === 5432));
	});

	it("only exposes HTTPS and return traffic on the public tier", () => {
		const ports = nacls.public.ingress.map((r) => `${r.fromPort}-${r.toPort}`);
		assert.deepEqual(ports, ["443-443", "1024-65535"]);
	});

	it("rejects an appPort the public tier's rules wouldn't carry", () => {
		assert.throws(() => naclRules(plan, 80, [5432]), /appPort must be between/);
	});

	it("enforces the 20-rule limit", () => {
		assert.throws(() => naclRules(plan, 8443, [5432, 3306, 6379, 27017, 9200, 11211, 1433]), /limit is 20/);
	});
});

describe("Network", () => {
	before(async () => {
		({ Network } = await import("../src/network"));
		new Network("t", args());
	});

	it("routes public subnets through the firewall endpoint in their own AZ", async () => {
		for (const az of AZS) {
			const route = await registered("aws:ec2/route:Route", `t-public-${az}-internet`);
			assert.equal(route.inputs.vpcEndpointId, `vpce-fw-${az}`);
			assert.equal(route.inputs.gatewayId, undefined);
		}
	});

	it("sends return traffic from the IGW back through the same AZ's firewall", async () => {
		const edge = await registered("aws:ec2/routeTableAssociation:RouteTableAssociation", "t-igw-edge");
		assert.equal(edge.inputs.gatewayId, "t_id");
		const back = await registered("aws:ec2/route:Route", "t-igw-edge-eu-west-1b");
		assert.equal(back.inputs.destinationCidrBlock, "10.0.97.0/24");
		assert.equal(back.inputs.vpcEndpointId, "vpce-fw-eu-west-1b");
	});

	it("sends each app subnet's internet traffic to the NAT gateway in its own AZ", async () => {
		for (const az of AZS) {
			const nat = await registered("aws:ec2/natGateway:NatGateway", `t-${az}`);
			assert.equal(nat.inputs.subnetId, `t-public-${az}_id`);
			const route = await registered("aws:ec2/route:Route", `t-app-${az}-egress`);
			assert.equal(route.inputs.natGatewayId, `t-${az}_id`);
		}
	});

	it("shares one NAT gateway across AZs when natGateways is single", async () => {
		new Network("onenat", args({ natGateways: "single" }));
		const route = await registered("aws:ec2/route:Route", "onenat-app-eu-west-1c-egress");
		assert.equal(route.inputs.natGatewayId, "onenat-eu-west-1a_id");
		await settle();
		assert.equal(created.filter((r) => r.type === "aws:ec2/natGateway:NatGateway" && r.name.startsWith("onenat-")).length, 1);
	});

	it("gives the data tier no route out of the VPC", async () => {
		await registered("aws:ec2/routeTable:RouteTable", "t-data");
		await settle();
		const dataRoutes = created.filter((r) => r.type === "aws:ec2/route:Route" && r.inputs.routeTableId === "t-data_id");
		assert.deepEqual(dataRoutes, []);
	});

	it("denies by default in the firewall policy", async () => {
		const policy = await registered("aws:networkfirewall/firewallPolicy:FirewallPolicy", "t-nfw");
		const fp = policy.inputs.firewallPolicy;
		assert.equal(fp.statefulEngineOptions.ruleOrder, "STRICT_ORDER");
		assert.deepEqual(fp.statefulDefaultActions, ["aws:drop_established", "aws:alert_established"]);
		assert.equal(
			fp.statefulRuleGroupReferences[0].resourceArn,
			"arn:aws:network-firewall:eu-west-1:aws-managed:stateful-rulegroup/MalwareDomainsStrictOrder",
		);
	});

	it("allow-lists domains and their subdomains", async () => {
		const group = await registered("aws:networkfirewall/ruleGroup:RuleGroup", "t-nfw-allow-domains");
		assert.deepEqual(group.inputs.ruleGroup.rulesSource.rulesSourceList.targets, ["amazonaws.com", ".amazonaws.com"]);
	});

	it("runs DNS Firewall as a walled garden that fails closed", async () => {
		const allow = await registered("aws:route53/resolverFirewallRule:ResolverFirewallRule", "t-dns-allow");
		const block = await registered("aws:route53/resolverFirewallRule:ResolverFirewallRule", "t-dns-block-rest");
		assert.ok(allow.inputs.priority < block.inputs.priority);
		assert.equal(block.inputs.action, "BLOCK");
		const config = await registered("aws:route53/resolverFirewallConfig:ResolverFirewallConfig", "t-dns");
		assert.equal(config.inputs.firewallFailOpen, "DISABLED");
	});

	it("locks down the default security group and network ACL", async () => {
		const sg = await registered("aws:ec2/defaultSecurityGroup:DefaultSecurityGroup", "t");
		assert.deepEqual(sg.inputs.ingress, []);
		assert.deepEqual(sg.inputs.egress, []);
		const acl = await registered("aws:ec2/defaultNetworkAcl:DefaultNetworkAcl", "t");
		assert.equal(acl.inputs.ingress, undefined);
		assert.equal(acl.inputs.egress, undefined);
	});

	it("logs all traffic, encrypted with a rotating customer-managed key", async () => {
		const flow = await registered("aws:ec2/flowLog:FlowLog", "t");
		assert.equal(flow.inputs.trafficType, "ALL");
		const group = await registered("aws:cloudwatch/logGroup:LogGroup", "t-flow");
		assert.equal(group.inputs.kmsKeyId, "arn:aws:mock:::t-logs");
		const key = await registered("aws:kms/key:Key", "t-logs");
		assert.equal(key.inputs.enableKeyRotation, true);
	});

	it("restricts endpoints to this account's principals where policies are supported", async () => {
		const sts = await registered("aws:ec2/vpcEndpoint:VpcEndpoint", "t-vpce-sts");
		const doc = JSON.parse(sts.inputs.policy);
		assert.deepEqual(doc.Statement[0].Condition, { StringEquals: { "aws:PrincipalAccount": "123456789012" } });
		const ssmmessages = await registered("aws:ec2/vpcEndpoint:VpcEndpoint", "t-vpce-ssmmessages");
		assert.equal(ssmmessages.inputs.policy, undefined);
	});

	it("chains security groups by reference, and gives the data tier no egress", async () => {
		const dataIn = await registered("aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", "t-sg-data-in-app-5432");
		assert.equal(dataIn.inputs.referencedSecurityGroupId, "t-sg-app_id");
		await settle();
		const dataEgress = created.filter(
			(r) => r.type === "aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule" && r.inputs.securityGroupId === "t-sg-data_id",
		);
		assert.deepEqual(dataEgress, []);
	});

	it("routes straight to the IGW when the firewall is off", async () => {
		new Network("nofw", args({ networkFirewall: { enabled: false, managedRuleGroups: [] }, dnsFirewall: { enabled: false, managedBlockListIds: [] } }));
		const route = await registered("aws:ec2/route:Route", "nofw-public-eu-west-1a-internet");
		assert.equal(route.inputs.gatewayId, "nofw_id");
		await settle();
		assert.equal(find("aws:ec2/routeTableAssociation:RouteTableAssociation", "nofw-igw-edge"), undefined);
	});
});
