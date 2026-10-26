import * as pulumi from "@pulumi/pulumi";
import { NatMode, Network } from "./src/network";

const config = new pulumi.Config();
const awsConfig = new pulumi.Config("aws");

// The account this stack is pinned to. The provider refuses to run against
// any other, and policies use it to scope access to this account only.
const [accountId] = awsConfig.requireObject<string[]>("allowedAccountIds");
if (!/^\d{12}$/.test(accountId ?? "")) {
	throw new Error("aws:allowedAccountIds must hold the 12-digit account ID this stack deploys to");
}

const natGateways = config.get("natGateways") ?? "perAz";
if (natGateways !== "single" && natGateways !== "perAz") {
	throw new Error(`natGateways must be "single" or "perAz", got "${natGateways}"`);
}

const network = new Network("learning", {
	accountId,
	region: awsConfig.require("region"),
	cidr: config.get("vpcCidr") ?? "10.0.0.0/16",
	availabilityZones: config.requireObject<string[]>("availabilityZones"),
	natGateways: natGateways as NatMode,
	appPort: config.getNumber("appPort") ?? 8443,
	dataPorts: config.getObject<number[]>("dataPorts") ?? [5432],
	allowedDomains: config.requireObject<string[]>("allowedDomains"),
	networkFirewall: {
		enabled: config.getBoolean("networkFirewall") ?? true,
		managedRuleGroups: config.requireObject<string[]>("networkFirewallManagedRuleGroups"),
	},
	dnsFirewall: {
		enabled: config.getBoolean("dnsFirewall") ?? true,
		managedBlockListIds: config.getObject<string[]>("dnsFirewallManagedListIds") ?? [],
	},
	interfaceEndpoints: config.getObject<string[]>("interfaceEndpoints") ?? [],
	logRetentionDays: config.getNumber("logRetentionDays") ?? 365,
});

export const vpcId = network.vpc.id;
export const publicSubnetIds = network.subnets.public.map((s) => s.id);
export const appSubnetIds = network.subnets.app.map((s) => s.id);
export const dataSubnetIds = network.subnets.data.map((s) => s.id);
export const securityGroupIds = {
	alb: network.securityGroups.alb.id,
	app: network.securityGroups.app.id,
	data: network.securityGroups.data.id,
};
export const natGatewayIds = network.natGateways.map((n) => n.id);
export const logKeyArn = network.logKey.arn;
