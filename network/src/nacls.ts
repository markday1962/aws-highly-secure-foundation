import { AddressPlan, Tier } from "./addressPlan";

export interface NaclRule {
	ruleNo: number;
	protocol: "tcp" | "-1";
	action: "allow";
	cidrBlock: string;
	fromPort: number;
	toPort: number;
}

export interface TierNacl {
	ingress: NaclRule[];
	egress: NaclRule[];
}

type Ports = { fromPort: number; toPort: number };
type Entry = [cidr: string, protocol: "tcp" | "-1", ports: Ports];

/** AWS's default limit is 20 rules per direction per network ACL. */
const MAX_RULES = 20;
const ANYWHERE = "0.0.0.0/0";
/** Return traffic arrives on the client's ephemeral port. */
const EPHEMERAL: Ports = { fromPort: 1024, toPort: 65535 };

/**
 * Network ACLs: the stateless, subnet-level second layer under security
 * groups. They enforce which *tiers* may talk at all; security groups then
 * decide which *resources* may. Being stateless, every allowed flow needs a
 * matching rule for its return traffic. Anything not listed is denied.
 *
 * Traffic to the VPC's DNS resolver and the instance metadata service isn't
 * subject to network ACLs, so no rules are needed for it.
 */
export function naclRules(plan: AddressPlan, appPort: number, dataPorts: number[]): Record<Tier, TierNacl> {
	const { public: pub, app, data } = plan.tiers;

	// Load balancer → target traffic leaves the public tier under the ephemeral-range rule.
	if (appPort < EPHEMERAL.fromPort || appPort > EPHEMERAL.toPort) {
		throw new Error(`appPort must be between ${EPHEMERAL.fromPort} and ${EPHEMERAL.toPort}, got ${appPort}`);
	}

	const https: Ports = { fromPort: 443, toPort: 443 };
	const port = (p: number): Ports => ({ fromPort: p, toPort: p });
	const tcp = (cidr: string, ports: Ports): Entry => [cidr, "tcp", ports];
	const allTraffic = (cidr: string): Entry => [cidr, "-1", { fromPort: 0, toPort: 0 }];

	const rules = (entries: Entry[]): NaclRule[] =>
		entries.map(([cidrBlock, protocol, ports], i) => ({ ruleNo: 100 + i * 10, protocol, action: "allow", cidrBlock, ...ports }));

	const result: Record<Tier, TierNacl> = {
		// Load balancers (HTTPS in) and NAT gateways (HTTPS out on behalf of the app tier).
		public: {
			ingress: rules([
				tcp(ANYWHERE, https), // clients → load balancer; app tier → NAT
				tcp(ANYWHERE, EPHEMERAL), // responses: internet → NAT, targets → load balancer
			]),
			egress: rules([
				tcp(ANYWHERE, https), // NAT → internet
				tcp(ANYWHERE, EPHEMERAL), // load balancer → clients and targets (appPort ≥ 1024), NAT → app tier
			]),
		},
		app: {
			ingress: rules([
				...pub.map((c) => tcp(c, port(appPort))), // load balancer → app
				...app.map((c) => tcp(c, https)), // app → interface endpoints (which live in the app subnets)
				tcp(ANYWHERE, EPHEMERAL), // responses from the internet, AWS APIs and the data tier
			]),
			egress: rules([
				tcp(ANYWHERE, https), // AWS APIs, endpoints, allow-listed internet
				...data.flatMap((c) => dataPorts.map((p) => tcp(c, port(p)))),
				...pub.map((c) => tcp(c, EPHEMERAL)), // responses to the load balancer
				...app.map((c) => tcp(c, EPHEMERAL)), // endpoint responses
			]),
		},
		// Isolated: reachable only from the app tier, and only on the data ports.
		data: {
			ingress: rules([
				...app.flatMap((c) => dataPorts.map((p) => tcp(c, port(p)))),
				...data.map(allTraffic), // replication within the tier
			]),
			egress: rules([...app.map((c) => tcp(c, EPHEMERAL)), ...data.map(allTraffic)]),
		},
		// Network Firewall must see all traffic to inspect it; AWS advises against filtering its subnets.
		firewall: {
			ingress: rules([allTraffic(ANYWHERE)]),
			egress: rules([allTraffic(ANYWHERE)]),
		},
	};

	for (const [tier, nacl] of Object.entries(result)) {
		for (const direction of ["ingress", "egress"] as const) {
			if (nacl[direction].length > MAX_RULES) {
				throw new Error(`${tier} network ACL needs ${nacl[direction].length} ${direction} rules; the limit is ${MAX_RULES}`);
			}
		}
	}
	return result;
}
