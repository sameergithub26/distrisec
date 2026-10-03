import { describe, it, expect } from "vitest";
import { tokenize } from "../lexer.js";
import { parse, ParseError } from "../parser.js";

function parseSource(src: string) {
  return parse(tokenize(src));
}

describe("parsing your three original example rules", () => {
  it('"Allow access if role is developer, resource is database, action is read, device is trusted"', () => {
    const policy = parseSource(`
      rule "developer-db-read" {
        effect: allow
        when: role == "developer" AND resource.type == "database" AND action == "read" AND device.trust == "trusted"
      }
    `);

    expect(policy.rules).toHaveLength(1);
    const rule = policy.rules[0]!;
    expect(rule.name).toBe("developer-db-read");
    expect(rule.effect).toBe("allow");

    // The condition should be a left-leaning chain of ANDs, matching how
    // parseAnd() folds repeated "AND x" onto the LEFT side as it goes -
    // this is "left-associative" parsing, the standard choice for chained
    // operators of equal precedence (same as how "1 - 2 - 3" means
    // "(1 - 2) - 3" in arithmetic, not "1 - (2 - 3)").
    expect(rule.condition.kind).toBe("and");
  });

  it('"Deny access when the risk score is above a threshold"', () => {
    const policy = parseSource(`
      rule "high-risk-deny" {
        effect: deny
        when: risk.score > 80
      }
    `);

    const rule = policy.rules[0]!;
    expect(rule.effect).toBe("deny");
    expect(rule.condition).toEqual({
      kind: "comparison",
      left: { kind: "field", segments: ["risk", "score"] },
      operator: ">",
      right: { kind: "number", value: 80 },
    });
  });

  it('"Require additional authentication when the country of access changes"', () => {
    const policy = parseSource(`
      rule "country-change-step-up" {
        effect: step_up
        when: country != previous_country
      }
    `);

    const rule = policy.rules[0]!;
    expect(rule.effect).toBe("step_up");
    expect(rule.condition).toEqual({
      kind: "comparison",
      left: { kind: "field", segments: ["country"] },
      operator: "!=",
      right: { kind: "field", segments: ["previous_country"] },
    });
  });
});

describe("operator precedence", () => {
  it("AND binds tighter than OR: 'a OR b AND c' parses as 'a OR (b AND c)'", () => {
    const policy = parseSource(`
      rule "precedence" {
        effect: allow
        when: action == "read" OR action == "write" AND risk.score < 10
      }
    `);
    const condition = policy.rules[0]!.condition;

    expect(condition.kind).toBe("or");
    if (condition.kind !== "or") throw new Error("unreachable");
    // left side of the OR is the plain "action == read" comparison
    expect(condition.left.kind).toBe("comparison");
    // right side of the OR is the WHOLE "action == write AND risk.score < 10",
    // not just "action == write" - proving AND grabbed both operands first
    expect(condition.right.kind).toBe("and");
  });

  it("NOT binds tighter than AND: 'NOT a AND b' parses as '(NOT a) AND b'", () => {
    const policy = parseSource(`
      rule "not-precedence" {
        effect: deny
        when: NOT device.trust == "trusted" AND action == "write"
	}
    `);
    const condition = policy.rules[0]!.condition;

    expect(condition.kind).toBe("and");
    if (condition.kind !== "and") throw new Error("unreachable");
    expect(condition.left.kind).toBe("not");
  });

  it("parses multiple rules in one policy, in source order", () => {
    const policy = parseSource(`
      rule "first" { effect: allow when: action == "read" }
      rule "second" { effect: deny when: risk.score > 90 }
    `);
    expect(policy.rules.map((r) => r.name)).toEqual(["first", "second"]);
  });
});

describe("parse errors give a useful message", () => {
  it("rejects a rule missing the 'effect:' line", () => {
    expect(() =>
      parseSource(`rule "bad" { when: action == "read" }`),
    ).toThrow(ParseError);
  });

  it("rejects an invalid effect value", () => {
    expect(() =>
      parseSource(`rule "bad" { effect: maybe when: action == "read" }`),
    ).toThrow(ParseError);
  });

  it("rejects an unclosed rule body", () => {
    expect(() =>
      parseSource(`rule "bad" { effect: allow when: action == "read"`),
    ).toThrow(ParseError);
  });

  it("error messages include the offending line number", () => {
    try {
      parseSource(`rule "bad" {\n  effect: nonsense\n}`);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ParseError);
      expect((e as ParseError).line).toBe(2);
    }
  });
});
