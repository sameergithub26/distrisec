import type { Token, TokenType } from "./tokens.js";
import type {
  Policy,
  PolicyRule,
  Expression,
  Comparison,
  BareOperand,
  ComparisonOperator,
  Operand,
  FieldPath,
  Effect,
} from "./ast.js";

export class ParseError extends Error {
  constructor(message: string, public line: number, public column: number) {
    super(`${message} (line ${line}, column ${column})`);
    this.name = "ParseError";
  }
}

const COMPARISON_OPERATORS: Partial<Record<TokenType, ComparisonOperator>> = {
  EQ: "==",
  NEQ: "!=",
  GT: ">",
  GTE: ">=",
  LT: "<",
  LTE: "<=",
};

/**
 * This is a "recursive descent" parser: each grammar rule from the EBNF
 * becomes one method, and higher-precedence rules call into lower-precedence
 * ones. parsePolicy calls parseRule calls parseExpression calls parseOr
 * calls parseAnd calls parseUnary calls parseComparison calls parseOperand.
 * The nesting in the CODE mirrors the nesting of CALLS, which mirrors the
 * precedence we want in the final tree - that's the whole trick to how
 * recursive descent naturally encodes "AND binds tighter than OR" etc.
 * without any separate precedence-table logic.
 */
class Parser {
  private pos = 0;

  constructor(private tokens: Token[]) {}

  private peek(offset = 0): Token {
    return this.tokens[Math.min(this.pos + offset, this.tokens.length - 1)]!;
  }

  private advance(): Token {
    const tok = this.tokens[this.pos]!;
    if (this.pos < this.tokens.length - 1) this.pos++;
    return tok;
  }

  private check(type: TokenType): boolean {
    return this.peek().type === type;
  }

  private expect(type: TokenType, context: string): Token {
    if (!this.check(type)) {
      const tok = this.peek();
      throw new ParseError(
        `Expected ${type} ${context}, got ${tok.type}${tok.value ? ` ("${tok.value}")` : ""}`,
        tok.line,
        tok.column,
      );
    }
    return this.advance();
  }

  parsePolicy(): Policy {
    const rules: PolicyRule[] = [];
    while (!this.check("EOF")) {
      rules.push(this.parseRule());
    }
    return { kind: "policy", rules };
  }

  private parseRule(): PolicyRule {
    const ruleTok = this.expect("RULE", "to start a rule definition");
    const nameTok = this.expect("STRING", "as the rule's name, e.g. rule \"my-rule-name\"");
    this.expect("LBRACE", "to open the rule body");

    this.expect("EFFECT_KW", "- every rule needs an 'effect:' line");
    this.expect("COLON", "after 'effect'");
    const effect = this.parseEffect();

    this.expect("WHEN_KW", "- every rule needs a 'when:' line");
    this.expect("COLON", "after 'when'");
    const condition = this.parseExpression();

    this.expect("RBRACE", "to close the rule body");

    return {
      kind: "rule",
      name: nameTok.value,
      effect,
      condition,
      line: ruleTok.line,
    };
  }

  private parseEffect(): Effect {
    const tok = this.peek();
    if (tok.type === "ALLOW") {
      this.advance();
      return "allow";
    }
    if (tok.type === "DENY") {
      this.advance();
      return "deny";
    }
    if (tok.type === "STEP_UP") {
      this.advance();
      return "step_up";
    }
    throw new ParseError(
      `Expected an effect (allow, deny, or step_up), got ${tok.type}`,
      tok.line,
      tok.column,
    );
  }

  // expression := orExpr
  private parseExpression(): Expression {
    return this.parseOr();
  }

  // orExpr := andExpr ("OR" andExpr)*
  private parseOr(): Expression {
    let left = this.parseAnd();
    while (this.check("OR")) {
      this.advance();
      const right = this.parseAnd();
      left = { kind: "or", left, right };
    }
    return left;
  }

  // andExpr := unary ("AND" unary)*
  private parseAnd(): Expression {
    let left = this.parseUnary();
    while (this.check("AND")) {
      this.advance();
      const right = this.parseUnary();
      left = { kind: "and", left, right };
    }
    return left;
  }

  // unary := "NOT" unary | comparison
  private parseUnary(): Expression {
    if (this.check("NOT")) {
      this.advance();
      return { kind: "not", operand: this.parseUnary() };
    }
    return this.parseComparison();
  }

  // comparison := operand (compOp operand)?
  private parseComparison(): Expression {
    const left = this.parseOperand();

    const opType = this.peek().type;
    const operator = COMPARISON_OPERATORS[opType];
    if (!operator) {
      // No comparison operator follows - this is a "bare" condition,
      // e.g. a hypothetical `when: device.trusted` with no `== true`.
      const bare: BareOperand = { kind: "bare", operand: left };
      return bare;
    }

    this.advance(); // consume the operator token
    const right = this.parseOperand();
    const comparison: Comparison = { kind: "comparison", left, operator, right };
    return comparison;
  }

  // operand := fieldPath | STRING | NUMBER | BOOLEAN
  private parseOperand(): Operand {
    const tok = this.peek();

    if (tok.type === "STRING") {
      this.advance();
      return { kind: "string", value: tok.value };
    }
    if (tok.type === "NUMBER") {
      this.advance();
      return { kind: "number", value: Number(tok.value) };
    }
    if (tok.type === "BOOLEAN") {
      this.advance();
      return { kind: "boolean", value: tok.value === "true" };
    }
    if (tok.type === "IDENTIFIER") {
      return this.parseFieldPath();
    }

    throw new ParseError(
      `Expected a value (field, string, number, or boolean), got ${tok.type}`,
      tok.line,
      tok.column,
    );
  }

  // fieldPath := IDENTIFIER ("." IDENTIFIER)*
  private parseFieldPath(): FieldPath {
    const segments: string[] = [this.expect("IDENTIFIER", "as a field name").value];
    while (this.check("DOT")) {
      this.advance();
      segments.push(this.expect("IDENTIFIER", "after '.' in a field path").value);
    }
    return { kind: "field", segments };
  }
}

export function parse(tokens: Token[]): Policy {
  return new Parser(tokens).parsePolicy();
}
