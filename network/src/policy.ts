import * as pulumi from "@pulumi/pulumi";

export interface Statement {
	sid?: string;
	effect?: "Allow" | "Deny";
	actions: string[];
	/** Omit for trust policies, which take a principal instead. */
	resources?: pulumi.Input<string>[];
	principals?: { type: string; identifiers: pulumi.Input<string>[] };
	conditions?: Record<string, Record<string, pulumi.Input<string | string[]>>>;
}

/** Renders an IAM, KMS or endpoint policy document as JSON, resolving any Outputs in it. */
export function policyDocument(statements: Statement[]): pulumi.Output<string> {
	return pulumi.jsonStringify({
		Version: "2012-10-17",
		Statement: statements.map((s) => ({
			...(s.sid ? { Sid: s.sid } : {}),
			Effect: s.effect ?? "Allow",
			...(s.principals ? { Principal: { [s.principals.type]: s.principals.identifiers } } : {}),
			Action: s.actions,
			...(s.resources ? { Resource: s.resources } : {}),
			...(s.conditions ? { Condition: s.conditions } : {}),
		})),
	});
}
