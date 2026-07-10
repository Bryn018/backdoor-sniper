/**
 * Lightweight pure-TypeScript Python tokenizer.
 *
 * This is NOT a full Python parser. It is a fast, single-pass state machine
 * that splits Python source into a stream of tokens sufficient for
 * statement-level analysis used by the AST-aware detection rules.
 *
 * Token types:
 *   - NAME        identifiers and keywords (e.g. `eval`, `import`, `MyClass`)
 *   - NUMBER      integer / float / hex / bin / oct / complex literals
 *   - STRING      string literals (single, double, triple, raw, byte, f-string)
 *                 The token VALUE is the unquoted inner text (best-effort).
 *                 Prefixes (rb, f, b, u) and quotes are stripped.
 *   - OP          operators and delimiters: ( ) [ ] { } , : ; = + - * / % etc.
 *   - NEWLINE     logical newline (one per logical line)
 *   - INDENT      increase in indentation level (only at start of logical line)
 *   - DEDENT      decrease in indentation level (only at start of logical line)
 *   - COMMENT     # comment (value includes the # but not the newline)
 *   - NL          physical newline that does NOT end a logical line
 *                 (inside brackets or after a backslash continuation)
 *
 * Handles:
 *   - Line continuations via trailing backslash
 *   - Implicit line continuation inside ( ) [ ] { }
 *   - f-strings, raw strings, byte strings, triple-quoted strings
 *   - Nested quotes inside triple-quoted strings
 *   - String prefix combinations (rb'', bR'', f'', Fr'', u'', U'')
 *
 * Does NOT need to:
 *   - Produce a CST / AST
 *   - Validate syntax
 *   - Resolve indentation errors
 *
 * Performance: O(n) single pass over source. For a 10,000 line file the
 * tokenizer runs in single-digit milliseconds.
 */

export type TokenType =
  | "NAME"
  | "NUMBER"
  | "STRING"
  | "OP"
  | "NEWLINE"
  | "INDENT"
  | "DEDENT"
  | "COMMENT"
  | "NL";

export interface Token {
  type: TokenType;
  /** Raw source text of the token (for STRING this includes quotes/prefix). */
  value: string;
  /** 1-based line number where the token starts. */
  line: number;
  /** 0-based column offset where the token starts. */
  col: number;
  /** For STRING tokens, the inner decoded text (quotes + prefix stripped). */
  text?: string;
  /** For STRING tokens, the lowercase prefix (e.g. "rb", "f", ""). */
  prefix?: string;
}

const OPEN_BRACKETS = new Set(["(", "[", "{"]);
const CLOSE_BRACKETS = new Set([")", "]", "}"]);

const STRING_PREFIXES = new Set([
  "r", "b", "u", "f",
  "rb", "br", "rf", "fr",
  "ru", "ur", "bu", "ub",
  "R", "B", "U", "F",
  "rB", "Rb", "bR", "BR",
  "rF", "Rf", "fR", "FR",
]);

const THREE_OPS = new Set(["**=", "//=", ">>=", "<<=", "..."]);
const TWO_OPS = new Set([
  "**", "//", ">>", "<<", "<=", ">=", "==", "!=", "+=", "-=",
  "*=", "/=", "%=", "&=", "|=", "^=", "->", ":=", "@=",
]);

/**
 * Tokenize Python source into an array of tokens.
 *
 * The function is intentionally defensive: malformed input never throws —
 * it just produces the best-effort token stream up to that point.
 */
export function tokenizePython(source: string): Token[] {
  const tokens: Token[] = [];
  // Normalize CRLF / CR to LF.
  const src = source.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

  // Indentation stack used for INDENT / DEDENT tokens.
  const indents: number[] = [0];
  // Bracket depth: incremented on ( [ { , decremented on ) ] }.
  let bracketDepth = 0;
  // True if we are at the start of a logical line (need to emit INDENT/DEDENT).
  let atLineStart = true;
  // True if a backslash line-continuation is pending (next newline is NL not NEWLINE).
  let lineContinuation = false;

  let i = 0;
  const n = src.length;
  let line = 1;
  let col = 0;

  // Position tracking helper: advance over one character updating line/col.
  const advance = (ch: string) => {
    if (ch === "\n") {
      line++;
      col = 0;
    } else {
      col++;
    }
  };

  // Process leading indentation of a logical line.
  const handleIndentation = () => {
    // Inside brackets, indentation is not significant — just consume whitespace.
    if (bracketDepth > 0) {
      while (i < n && (src[i] === " " || src[i] === "\t" || src[i] === "\f")) {
        advance(src[i]);
        i++;
      }
      return;
    }
    // Count leading whitespace (spaces / tabs — treat tab as 8 cols like Python).
    let indent = 0;
    let j = i;
    while (j < n) {
      const c = src[j];
      if (c === " ") {
        indent++;
        j++;
      } else if (c === "\t") {
        indent += 8 - (indent % 8);
        j++;
      } else if (c === "\f") {
        // form feed resets column to 0
        indent = 0;
        j++;
      } else {
        break;
      }
    }
    // Blank lines / comment-only lines do NOT emit INDENT/DEDENT.
    if (j >= n || src[j] === "\n" || src[j] === "#") {
      // consume the whitespace and continue (no indentation token)
      while (i < j) {
        advance(src[i]);
        i++;
      }
      return;
    }
    // Move i to j, updating line/col.
    while (i < j) {
      advance(src[i]);
      i++;
    }
    const top = indents[indents.length - 1];
    if (indent > top) {
      indents.push(indent);
      tokens.push({ type: "INDENT", value: "", line, col: 0 });
    } else if (indent < top) {
      while (indents.length > 1 && indents[indents.length - 1] > indent) {
        indents.pop();
        tokens.push({ type: "DEDENT", value: "", line, col: 0 });
      }
    }
  };

  // Emit a newline token (NEWLINE for logical line end, NL otherwise).
  const emitNewline = (kind: "NEWLINE" | "NL") => {
    tokens.push({ type: kind, value: "\n", line, col });
  };

  while (i < n) {
    if (atLineStart) {
      handleIndentation();
      atLineStart = false;
      if (i >= n) break;
      // After handleIndentation, i now points to the first non-whitespace char.
      // If it was a blank/comment-only line, we already consumed the whitespace
      // and the loop will pick up the comment or newline below.
    }

    const c = src[i];

    // -----------------------------------------------------------------
    // Newlines
    // -----------------------------------------------------------------
    if (c === "\n") {
      // If inside brackets or line-continuation pending, this is NL not NEWLINE.
      if (bracketDepth > 0 || lineContinuation) {
        emitNewline("NL");
        lineContinuation = false;
      } else {
        emitNewline("NEWLINE");
      }
      advance(c);
      i++;
      atLineStart = true;
      continue;
    }

    // -----------------------------------------------------------------
    // Line continuation: backslash followed by newline.
    // -----------------------------------------------------------------
    if (c === "\\" && i + 1 < n && src[i + 1] === "\n") {
      lineContinuation = true;
      advance(c);
      i++;
      advance(src[i]);
      i++; // consume the \n
      atLineStart = false; // we're still on the same logical line
      // Don't set atLineStart=true because there's no indentation to handle
      // — but we do need to skip whitespace on the next physical line.
      while (i < n && (src[i] === " " || src[i] === "\t")) {
        advance(src[i]);
        i++;
      }
      continue;
    }

    // -----------------------------------------------------------------
    // Comments
    // -----------------------------------------------------------------
    if (c === "#") {
      const start = i;
      const startCol = col;
      while (i < n && src[i] !== "\n") {
        advance(src[i]);
        i++;
      }
      tokens.push({
        type: "COMMENT",
        value: src.slice(start, i),
        line,
        col: startCol,
      });
      continue; // next iteration will hit the newline
    }

    // -----------------------------------------------------------------
    // Whitespace (not at line start) — skip.
    // -----------------------------------------------------------------
    if (c === " " || c === "\t" || c === "\f") {
      advance(c);
      i++;
      continue;
    }

    // -----------------------------------------------------------------
    // Strings (with optional prefix: r, b, u, f, and combinations)
    // -----------------------------------------------------------------
    // Detect a string prefix: a sequence of 1-2 alpha chars from {r,b,u,f,R,B,U,F}
    // immediately followed by a quote.
    if (isStringStart(src, i)) {
      const tok = readString(src, i, line, col, advance);
      // Update position to end of string.
      const consumed = tok.value.length;
      for (let k = 0; k < consumed; k++) advance(src[i + k]);
      i += consumed;
      // Track bracket depth (strings don't affect it — they're literals).
      tokens.push(tok);
      continue;
    }

    // -----------------------------------------------------------------
    // Numbers (int, float, hex, bin, oct, complex, underscores)
    // -----------------------------------------------------------------
    if (isDigit(c) || (c === "." && i + 1 < n && isDigit(src[i + 1]))) {
      const tok = readNumber(src, i, line, col);
      const consumed = tok.value.length;
      for (let k = 0; k < consumed; k++) advance(src[i + k]);
      i += consumed;
      tokens.push(tok);
      continue;
    }

    // -----------------------------------------------------------------
    // Names / keywords
    // -----------------------------------------------------------------
    if (isNameStart(c)) {
      const start = i;
      const startCol = col;
      while (i < n && isNamePart(src[i])) {
        advance(src[i]);
        i++;
      }
      tokens.push({
        type: "NAME",
        value: src.slice(start, i),
        line,
        col: startCol,
      });
      continue;
    }

    // -----------------------------------------------------------------
    // Operators and delimiters (1, 2, or 3 chars)
    // -----------------------------------------------------------------
    const three = src.slice(i, i + 3);
    if (THREE_OPS.has(three)) {
      tokens.push({ type: "OP", value: three, line, col });
      advance(three[0]); advance(three[1]); advance(three[2]);
      i += 3;
      continue;
    }
    const two = src.slice(i, i + 2);
    if (TWO_OPS.has(two)) {
      tokens.push({ type: "OP", value: two, line, col });
      advance(two[0]); advance(two[1]);
      i += 2;
      continue;
    }
    // Single-char op.
    tokens.push({ type: "OP", value: c, line, col });
    advance(c);
    i++;
    if (OPEN_BRACKETS.has(c)) bracketDepth++;
    else if (CLOSE_BRACKETS.has(c)) bracketDepth = Math.max(0, bracketDepth - 1);
  }

  // Flush any pending logical newline at EOF.
  if (tokens.length === 0 || (tokens[tokens.length - 1].type !== "NEWLINE" && tokens[tokens.length - 1].type !== "NL")) {
    // Only emit if the last meaningful token wasn't already a newline.
    const last = tokens[tokens.length - 1];
    if (!last || (last.type !== "NEWLINE" && last.type !== "NL" && last.type !== "DEDENT")) {
      tokens.push({ type: "NEWLINE", value: "\n", line, col });
    }
  }
  // Emit final DEDENTs to balance the indentation stack.
  while (indents.length > 1) {
    indents.pop();
    tokens.push({ type: "DEDENT", value: "", line, col: 0 });
  }

  return tokens;
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

function isDigit(c: string): boolean {
  return c >= "0" && c <= "9";
}
function isNameStart(c: string): boolean {
  return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || c === "_";
}
function isNamePart(c: string): boolean {
  return isNameStart(c) || isDigit(c);
}
function isHexDigit(c: string): boolean {
  return isDigit(c) || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
}

/**
 * Determine if position i starts a string literal (with optional prefix).
 * Looks ahead 1-2 alpha chars then checks for a quote (single, double, or triple).
 */
function isStringStart(src: string, i: number): boolean {
  // Try 2-char prefix first.
  if (i + 2 < src.length) {
    const p2 = src.slice(i, i + 2);
    if (STRING_PREFIXES.has(p2)) {
      const q = src[i + 2];
      if (q === '"' || q === "'") return true;
    }
  }
  // 1-char prefix.
  const p1 = src[i];
  if (STRING_PREFIXES.has(p1)) {
    const q = src[i + 1];
    if (q === '"' || q === "'") return true;
  }
  // No prefix.
  if (p1 === '"' || p1 === "'") return true;
  return false;
}

interface StringReadResult {
  value: string; // raw text including prefix + quotes
  text: string; // inner text (quotes stripped, prefix stripped)
  prefix: string; // lowercase prefix
}

/**
 * Read a string literal starting at position i. Returns the raw text consumed
 * plus the decoded inner text (best-effort: no escape processing for now,
 * because the detection rules care about the literal characters as written).
 */
function readString(
  src: string,
  start: number,
  startLine: number,
  startCol: number,
  _advance: (c: string) => void
): Token {
  // Extract optional prefix (1-2 chars).
  let prefix = "";
  let i = start;
  if (
    src.length > i + 2 &&
    STRING_PREFIXES.has(src.slice(i, i + 2)) &&
    (src[i + 2] === '"' || src[i + 2] === "'")
  ) {
    prefix = src.slice(i, i + 2).toLowerCase();
    i += 2;
  } else if (
    STRING_PREFIXES.has(src[i]) &&
    (src[i + 1] === '"' || src[i + 1] === "'")
  ) {
    prefix = src[i].toLowerCase();
    i += 1;
  }

  // Determine quote style: triple or single.
  const ch = src[i];
  const triple = src.slice(i, i + 3) === ch + ch + ch;
  const quote = triple ? ch + ch + ch : ch;
  const quoteLen = triple ? 3 : 1;
  i += quoteLen;

  const textStart = i;
  if (triple) {
    // Scan until matching triple quote (or EOF).
    while (i < src.length) {
      if (src.slice(i, i + 3) === quote) break;
      if (src[i] === "\\" && i + 1 < src.length) {
        i += 2;
        continue;
      }
      i++;
    }
  } else {
    // Single-line string. Scan until matching quote, newline, or EOF.
    while (i < src.length && src[i] !== "\n") {
      if (src[i] === "\\") {
        i += 2;
        continue;
      }
      if (src[i] === ch) break;
      i++;
    }
  }

  let innerEnd = i;
  let rawEnd: number;
  let text: string;
  if (i < src.length && src.slice(i, i + quoteLen) === quote) {
    rawEnd = i + quoteLen;
    text = src.slice(textStart, innerEnd);
  } else {
    // Unterminated string — take what we have.
    rawEnd = i;
    text = src.slice(textStart, innerEnd);
  }

  const value = src.slice(start, rawEnd);
  return {
    type: "STRING",
    value,
    line: startLine,
    col: startCol,
    text,
    prefix,
  } as Token;
}

/**
 * Read a numeric literal starting at position i.
 * Handles: 0x/0o/0b prefixes, underscores, decimals, floats, exponents,
 * and trailing j/J for complex literals.
 */
function readNumber(src: string, start: number, startLine: number, startCol: number): Token {
  let i = start;
  const n = src.length;

  // Hex / Oct / Bin.
  if (src[i] === "0" && i + 1 < n && (src[i + 1] === "x" || src[i + 1] === "X")) {
    i += 2;
    while (i < n && (isHexDigit(src[i]) || src[i] === "_")) i++;
    // Handle malformed — if no hex digits followed, just stop.
    return {
      type: "NUMBER",
      value: src.slice(start, i),
      line: startLine,
      col: startCol,
    };
  }
  if (src[i] === "0" && i + 1 < n && (src[i + 1] === "o" || src[i + 1] === "O")) {
    i += 2;
    while (i < n && ((src[i] >= "0" && src[i] <= "7") || src[i] === "_")) i++;
    return {
      type: "NUMBER",
      value: src.slice(start, i),
      line: startLine,
      col: startCol,
    };
  }
  if (src[i] === "0" && i + 1 < n && (src[i + 1] === "b" || src[i + 1] === "B")) {
    i += 2;
    while (i < n && (src[i] === "0" || src[i] === "1" || src[i] === "_")) i++;
    return {
      type: "NUMBER",
      value: src.slice(start, i),
      line: startLine,
      col: startCol,
    };
  }

  // Decimal / float.
  // Integer part.
  while (i < n && (isDigit(src[i]) || src[i] === "_")) i++;
  // Fractional part.
  if (i < n && src[i] === ".") {
    i++;
    while (i < n && (isDigit(src[i]) || src[i] === "_")) i++;
  }
  // Exponent.
  if (i < n && (src[i] === "e" || src[i] === "E")) {
    i++;
    if (i < n && (src[i] === "+" || src[i] === "-")) i++;
    while (i < n && (isDigit(src[i]) || src[i] === "_")) i++;
  }
  // Complex suffix.
  if (i < n && (src[i] === "j" || src[i] === "J")) i++;

  return {
    type: "NUMBER",
    value: src.slice(start, i),
    line: startLine,
    col: startCol,
  };
}
