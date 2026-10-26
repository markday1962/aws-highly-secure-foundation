/**
 * Carves a subnet out of a parent IPv4 CIDR, like Terraform's cidrsubnet():
 * subnetCidr("10.0.0.0/16", 8, 2) === "10.0.2.0/24".
 */
export function subnetCidr(parent: string, newBits: number, index: number): string {
	const [address, prefixText] = parent.split("/");
	const prefix = Number(prefixText);
	const newPrefix = prefix + newBits;

	if (!Number.isInteger(prefix) || prefix < 0 || newPrefix > 32) {
		throw new Error(`cannot add ${newBits} bits to ${parent}`);
	}
	if (index < 0 || index >= 2 ** newBits) {
		throw new Error(`index ${index} doesn't fit in ${newBits} bits of ${parent}`);
	}

	const octets = address.split(".").map(Number);
	if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
		throw new Error(`invalid IPv4 address in ${parent}`);
	}

	const base = octets.reduce((acc, o) => acc * 256 + o, 0);
	const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	if ((base & ~mask) >>> 0 !== 0) {
		throw new Error(`${parent} has host bits set`);
	}

	const subnet = base + index * 2 ** (32 - newPrefix);
	const parts = [24, 16, 8, 0].map((shift) => Math.floor(subnet / 2 ** shift) % 256);
	return `${parts.join(".")}/${newPrefix}`;
}
