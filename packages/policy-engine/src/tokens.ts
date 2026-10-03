/**
 * Every distinct "kind of thing" the lexer can produce. Keeping this as a
 * flat enum (rather than, say, just using the raw matched string) means the
 * parser can switch on `.type` and get exhaustiveness checking from
 * TypeScript - if we add a new effect keyword later and forget to handle
 * it somewhere, the compiler tells us.
 */
export type TokenType =
  | "RULE" // the keyword "rule"
  | "EFFECT_KW" // the keyword "effect"
  | "WHEN_KW" // the keyword "when"
  | "ALLOW" // the keyword "allow"
  | "DENY" // the keyword "deny"
  | "STEP_UP" // the keyword "step_up"
  | "AND"
  | "OR"
  | "NOT"
  | "IDENTIFIER" // e.g. role, resource, type, risk, score
  | "STRING" // e.g. "developer"
  | "NUMBER" // e.g. 80
  | "BOOLEAN" // true / false
  | "DOT" // .
  | "LBRACE" // {
  | "RBRACE" // }
  | "COLON" // :
  | "EQ" // ==
  | "NEQ" // !=
  | "GT" // >
  | "GTE" // >=
  | "LT" // <
  | "LTE" // <=
  | "EOF";

export interface Token {
  type: TokenType;
  value: string;
  /** 1-based line number, used to produce useful parse error messages. */
  line: number;
  /** 1-based column number, same reason. */
  column: number;
}

/**
 * Words that mean something special to the language, as opposed to being
 * available as a field name. Reserving these means `role == "allow"` is
 * fine (the string "allow" is just a string), but you can't name a rule
 * field `effect` - which you wouldn't want to anyway, since it'd be
 * genuinely ambiguous with the `effect:` line of a rule.
 */
export const KEYWORDS: Record<string, TokenType> = {
  rule: "RULE",
  effect: "EFFECT_KW",
  when: "WHEN_KW",
  allow: "ALLOW",
  deny: "DENY",
  step_up: "STEP_UP",
  AND: "AND",
  OR: "OR",
  NOT: "NOT",
  true: "BOOLEAN",
  false: "BOOLEAN",
};
