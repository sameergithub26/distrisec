import { KEYWORDS, type Token, type TokenType } from "./tokens.js";

export class LexError extends Error {
  constructor(message: string, public line: number, public column: number) {
    super(`${message} (line ${line}, column ${column})`);
    this.name = "LexError";
  }
}

/**
 * Converts policy DSL source text into a flat array of tokens.
 *
 * This is a hand-written, single-pass scanner: it walks the source
 * character by character exactly once, maintaining line/column position
 * for error messages, and decides what kind of token it's looking at based
 * on the first character it sees (a quote means a string is starting, a
 * digit means a number, a letter means an identifier-or-keyword, etc).
 *
 * We don't use a regex-based or generated lexer here because the grammar
 * is small and stable enough that a hand-written one is easier to read,
 * easier to give precise error locations from, and has zero dependencies.
 */
export function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let pos = 0;
  let line = 1;
  let column = 1;

  function peek(offset = 0): string {
    return source[pos + offset] ?? "";
  }

  function advance(): string {
    const ch = source[pos++]!;
    if (ch === "\n") {
      line++;
      column = 1;
    } else {
      column++;
    }
    return ch;
  }

  function isDigit(ch: string): boolean {
    return ch >= "0" && ch <= "9";
  }

  function isAlpha(ch: string): boolean {
    return /[A-Za-z_]/.test(ch);
  }

  function isAlphaNumeric(ch: string): boolean {
    return isAlpha(ch) || isDigit(ch);
  }

  function push(type: TokenType, value: string, startLine: number, startColumn: number) {
    tokens.push({ type, value, line: startLine, column: startColumn });
  }

  while (pos < source.length) {
    const ch = peek();
    const startLine = line;
    const startColumn = column;

    // Whitespace: skip entirely, it carries no meaning in this grammar.
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") {
      advance();
      continue;
    }

    // Line comments: "# ..." to end of line. Useful for annotating WHY a
    // rule exists, e.g. "# added after the March incident review".
    if (ch === "#") {
      while (pos < source.length && peek() !== "\n") advance();
      continue;
    }

    // String literals: "developer", "database", etc. We don't support
    // escape sequences yet (e.g. \") - deliberately simple for v1, and
    // policy values in practice (role names, resource types) don't need
    // embedded quotes.
    if (ch === '"') {
      advance(); // consume opening quote
      let value = "";
      while (pos < source.length && peek() !== '"') {
        if (peek() === "\n") {
          throw new LexError("Unterminated string literal", startLine, startColumn);
        }
        value += advance();
      }
      if (pos >= source.length) {
        throw new LexError("Unterminated string literal", startLine, startColumn);
      }
      advance(); // consume closing quote
      push("STRING", value, startLine, startColumn);
      continue;
    }

    // Number literals: integers and decimals, e.g. 80, 0.5. No negative
    // numbers at the lexer level - "-80" is handled as NOT needed here
    // since risk scores etc. are always >= 0 in our domain; if we ever
    // need negative numbers, that's a small addition later.
    if (isDigit(ch)) {
      let value = "";
      while (isDigit(peek())) value += advance();
      if (peek() === "." && isDigit(peek(1))) {
        value += advance(); // consume "."
        while (isDigit(peek())) value += advance();
      }
      push("NUMBER", value, startLine, startColumn);
      continue;
    }

    // Identifiers and keywords: both start with a letter/underscore, so we
    // scan the whole word first and THEN decide if it's a reserved keyword
    // (rule, allow, AND, ...) or a plain field-name identifier (role,
    // resource, score, ...).
    if (isAlpha(ch)) {
      let value = "";
      while (isAlphaNumeric(peek())) value += advance();
      const keywordType = KEYWORDS[value];
      push(keywordType ?? "IDENTIFIER", value, startLine, startColumn);
      continue;
    }

    // Two-character operators must be checked before their one-character
    // prefixes (== before =, != before !, >= before >, <= before <), or
    // we'd mis-tokenize "==" as two separate (invalid) "=" tokens.
    if (ch === "=" && peek(1) === "=") {
      advance();
      advance();
      push("EQ", "==", startLine, startColumn);
      continue;
    }
    if (ch === "!" && peek(1) === "=") {
      advance();
      advance();
      push("NEQ", "!=", startLine, startColumn);
      continue;
    }
    if (ch === ">" && peek(1) === "=") {
      advance();
      advance();
      push("GTE", ">=", startLine, startColumn);
      continue;
    }
    if (ch === "<" && peek(1) === "=") {
      advance();
      advance();
      push("LTE", "<=", startLine, startColumn);
      continue;
    }
    if (ch === ">") {
      advance();
      push("GT", ">", startLine, startColumn);
      continue;
    }
    if (ch === "<") {
      advance();
      push("LT", "<", startLine, startColumn);
      continue;
    }
    if (ch === ".") {
      advance();
      push("DOT", ".", startLine, startColumn);
      continue;
    }
    if (ch === "{") {
      advance();
      push("LBRACE", "{", startLine, startColumn);
      continue;
    }
    if (ch === "}") {
      advance();
      push("RBRACE", "}", startLine, startColumn);
      continue;
    }
    if (ch === ":") {
      advance();
      push("COLON", ":", startLine, startColumn);
      continue;
    }

    throw new LexError(`Unexpected character '${ch}'`, startLine, startColumn);
  }

  tokens.push({ type: "EOF", value: "", line, column });
  return tokens;
}
