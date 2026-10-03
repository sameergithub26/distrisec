import { describe, it, expect } from "vitest";
import { tokenize, LexError } from "../lexer.js";

describe("tokenize", () => {
  it("tokenizes a minimal rule", () => {
    const tokens = tokenize(`rule "x" { effect: allow when: action == "read" }`);
    const types = tokens.map((t) => t.type);
    expect(types).toEqual([
      "RULE", "STRING", "LBRACE",
      "EFFECT_KW", "COLON", "ALLOW",
      "WHEN_KW", "COLON", "IDENTIFIER", "EQ", "STRING",
      "RBRACE", "EOF",
    ]);
  });

  it("distinguishes keywords from identifiers with the same spelling pattern", () => {
    // "allow", "deny", "AND" etc. are reserved; "action", "role" etc. are not.
    const tokens = tokenize("allow deny step_up AND OR NOT action role");
    expect(tokens.map((t) => t.type)).toEqual([
      "ALLOW", "DENY", "STEP_UP", "AND", "OR", "NOT", "IDENTIFIER", "IDENTIFIER", "EOF",
    ]);
  });

  it("tokenizes dotted field paths as repeated IDENTIFIER/DOT pairs", () => {
    const tokens = tokenize("resource.type");
    expect(tokens.map((t) => t.type)).toEqual(["IDENTIFIER", "DOT", "IDENTIFIER", "EOF"]);
  });

  it("tokenizes all comparison operators, preferring the two-char form", () => {
    const tokens = tokenize("== != > >= < <=");
    expect(tokens.map((t) => t.type)).toEqual(["EQ", "NEQ", "GT", "GTE", "LT", "LTE", "EOF"]);
  });

  it("tokenizes numbers including decimals", () => {
    const tokens = tokenize("80 0.5");
    expect(tokens[0]).toMatchObject({ type: "NUMBER", value: "80" });
    expect(tokens[1]).toMatchObject({ type: "NUMBER", value: "0.5" });
  });

  it("tokenizes booleans as BOOLEAN, not IDENTIFIER", () => {
    const tokens = tokenize("true false");
    expect(tokens.map((t) => t.type)).toEqual(["BOOLEAN", "BOOLEAN", "EOF"]);
  });

  it("skips whitespace and comments", () => {
    const tokens = tokenize(`
      # this whole line is a comment
      allow   # trailing comment too
    `);
    expect(tokens.map((t) => t.type)).toEqual(["ALLOW", "EOF"]);
  });

  it("reports the correct line number for error messages", () => {
    const tokens = tokenize('rule\n"x"');
    const stringTok = tokens.find((t) => t.type === "STRING")!;
    expect(stringTok.line).toBe(2);
  });

  it("throws LexError on an unterminated string", () => {
    expect(() => tokenize('"never closed')).toThrow(LexError);
  });

  it("throws LexError on a genuinely unknown character", () => {
    expect(() => tokenize("role @ action")).toThrow(LexError);
  });
});
