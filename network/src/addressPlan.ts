import { subnetCidr } from "./cidr";

export type Tier = "public" | "app" | "data" | "firewall";

export interface AddressPlan {
	vpc: string;
	/** CIDRs per tier, in the same order as the availability zones. */
	tiers: Record<Tier, string[]>;
}

/**
 * Lays out four tiers across up to three AZs. For a /16 VPC (10.0.0.0/16):
 *
 *   app       /19  10.0.0.0, 10.0.32.0, 10.0.64.0     workloads (private, egress via NAT)
 *   public    /24  10.0.96.0, 10.0.97.0, 10.0.98.0    load balancers and NAT gateways
 *   firewall  /28  10.0.99.0, 10.0.99.16, 10.0.99.32  Network Firewall endpoints
 *   data      /22  10.0.100.0, 10.0.104.0, 10.0.108.0 databases (isolated: no internet route)
 *
 * 10.0.112.0 - 10.0.255.255 is left free for future tiers.
 */
export function addressPlan(vpcCidr: string, azCount: number): AddressPlan {
	if (azCount < 1 || azCount > 3) {
		throw new Error(`the address plan supports 1-3 availability zones, got ${azCount}`);
	}

	const azs = [...Array(azCount).keys()];
	return {
		vpc: vpcCidr,
		tiers: {
			app: azs.map((i) => subnetCidr(vpcCidr, 3, i)),
			public: azs.map((i) => subnetCidr(vpcCidr, 8, 96 + i)),
			firewall: azs.map((i) => subnetCidr(vpcCidr, 12, 99 * 16 + i)),
			data: azs.map((i) => subnetCidr(vpcCidr, 6, 25 + i)),
		},
	};
}
