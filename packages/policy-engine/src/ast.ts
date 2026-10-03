/**
 * The AST (Abstract Syntax Tree) is the structured, tree-shaped
 * representation of a parsed policy - what's left after the lexer's flat
 * token list has been organized according to the grammar's rules of
 * precedence and nesting. This is the ONLY thing the evaluator (built on
 * Day 9) will ever look at; it never re-reads raw text.
 *
 * Each expression node type below corresponds directly to a line in the
 * grammar in the walkthrough: OrExpr/AndExpr/NotExpr encode operator
 * precedence as NESTING - an OrExpr's children are AndExprs, never raw
 * Comparisons, which is exactly what makes "a OR b AND c" parse as
 * "a OR (b AND c)" rather than being ambiguous.
 */

export type Effect = "allow" | "deny" | "step_up";

export interface FieldPath {
  kind: "field";
  /** e.g. ["resource", "type"] for `resource.type`, or ["role"] for `role`. */
  segments: string[];
}

export interface StringLiteral {
  kind: "string";
  value: string;
}

export interface NumberLiteral {
  kind: "number";
  value: number;
}

export interface BooleanLiteral {
  kind: "boolean";
  value: boolean;
}

export type Operand = FieldPath | StringLiteral | NumberLiteral | BooleanLiteral;

export type ComparisonOperator = "==" | "!=" | ">" | ">=" | "<" | "<=";

export interface Comparison {
  kind: "comparison";
  left: Operand;
  operator: ComparisonOperator;
  right: Operand;
}

/**
 * A "bare" operand used as a condition on its own, e.g. a future rule like
 * `when: device.trusted` with no comparison operator - not used by any
 * example rule yet, but the grammar and AST support it since boolean
 * fields are a natural thing to want to test directly.
 */
export interface BareOperand {
  kind: "bare";
  operand: Operand;
}

export interface NotExpr {
  kind: "not";
  operand: Expression;
}

export interface AndExpr {
  kind: "and";
  left: Expression;
  right: Expression;
}

export interface OrExpr {
  kind: "or";
  left: Expression;
  right: Expression;
}

export type Expression = Comparison | BareOperand | NotExpr | AndExpr | OrExpr;

export interface PolicyRule {
  kind: "rule";
  name: string;
  effect: Effect;
  condition: Expression;
  line: number;
}

export interface Policy {
  kind: "policy";
  rules: PolicyRule[];
}
