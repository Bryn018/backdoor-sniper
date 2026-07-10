/**
 * Statement-level Python analyzer.
 *
 * Takes the token stream from `tokenizePython` and builds lightweight
 * "logical statements" with extracted calls, assignments, imports,
 * decorators, and string literals. Also performs simple data-flow
 * tracking: variables assigned string/call results → later passed to
 * dangerous sinks (eval / exec / os.system / subprocess.*).
 *
 * This is NOT a full Python AST. It is intentionally lightweight and
 * fast — designed to catch obfuscated malicious patterns that regex
 * alone cannot see (indirect calls, split payloads, data-flow to sinks,
 * decorator abuse, lambda wrappers, etc.).
 */

import { tokenizePython, type Token } from "./python-tokenizer";

// -------------------------------------------------------------------------
// Public types
// -------------------------------------------------------------------------

export interface StringLiteralInfo {
  text: string;
  prefix: string;
  line: number;
  col: number;
}

export interface ArgInfo {
  /** The argument expression as source text (joined token values). */
  text: string;
  /** If the argument is a single NAME token, the variable name. */
  varName: string | null;
  /** All string literal inner-texts found in this argument. */
  strings: string[];
  /** Nested calls inside this argument. */
  calls: CallInfo[];
  /** True if the argument is a single string literal. */
  isStringLiteral: boolean;
  /** True if the argument is a single NAME (variable reference). */
  isVariable: boolean;
  /** True if the argument contains an f-string with interpolation. */
  isFString: boolean;
  /** True if the argument is a `+`-concatenation involving strings. */
  isConcatenation: boolean;
  /** All NAME tokens referenced in this argument (variable refs). */
  varRefs: string[];
}

export interface CallInfo {
  /** Normalized callee text, e.g. "eval", "os.system", "__import__(...).exec". */
  callee: string;
  /** Parts of the callee chain, e.g. ["os", "system"] or ["__import__", "(...)", "exec"]. */
  calleeParts: string[];
  /** Last simple-name segment of the callee, e.g. "system" for "os.system". */
  calleeName: string;
  /** Parsed arguments. */
  args: ArgInfo[];
  /** Line where the call's opening paren appears. */
  line: number;
  /** Column of the callee start. */
  col: number;
  /** True if the callee involves a subscript (dict/list lookup call). */
  hasSubscript: boolean;
  /** True if the callee involves a dict/list/set literal. */
  hasLiteralCallee: boolean;
}

export interface AssignmentInfo {
  /** Full target text, e.g. "v", "self.cmd", "a, b". */
  target: string;
  /** Simple variable name if the target is a single NAME. */
  targetVar: string | null;
  /** RHS expression as source text. */
  valueText: string;
  /** String literal inner-texts in the RHS. */
  valueStrings: string[];
  /** Calls in the RHS. */
  valueCalls: CallInfo[];
  /** Variable names referenced in the RHS. */
  valueVarRefs: string[];
  /** True if RHS is a single string literal. */
  isString: boolean;
  /** True if RHS is a string concatenation (string + string [+ ...]). */
  isStringConcat: boolean;
  /** True if RHS contains an f-string. */
  isFString: boolean;
  /** True if RHS is a list literal [...]. */
  isList: boolean;
  /** Line number of the assignment. */
  line: number;
}

export interface LogicalStatement {
  /** 1-based line where the statement starts. */
  startLine: number;
  /** 1-based line where the statement ends. */
  endLine: number;
  /** Indentation depth (0 = top level). */
  indent: number;
  /** Tokens of the statement (excluding NL, COMMENT, INDENT, DEDENT). */
  tokens: Token[];
  /** Original source text (lines joined). */
  text: string;
  /** Leading keyword: "if", "for", "def", "class", "import", "from", "@", etc. */
  keyword: string | null;
  /** True if the statement introduces a body (if/for/while/def/class/try/...). */
  isCompound: boolean;
  /** Calls extracted from this statement. */
  calls: CallInfo[];
  /** Assignments extracted from this statement. */
  assignments: AssignmentInfo[];
  /** String literals in this statement. */
  stringLiterals: StringLiteralInfo[];
  /** Decorator names if this is a decorator statement. */
  decoratorNames: string[];
  /** Enclosing compound statement (null at top level). */
  parent: LogicalStatement | null;
  /** Body statements (for compound statements). */
  body: LogicalStatement[];
}

export interface DataFlowEdge {
  /** The variable that was assigned. */
  varName: string;
  /** The dangerous sink called with the variable, e.g. "eval". */
  sink: string;
  /** Line where the sink call occurs. */
  sinkLine: number;
  /** Line where the variable was defined. */
  defLine: number;
  /** Snippet of the sink call. */
  snippet: string;
  /** Confidence 0..1. */
  confidence: number;
  /** The assignment info for the variable. */
  assignment: AssignmentInfo;
}

export interface CallEdge {
  caller: string;
  callee: string;
  line: number;
}

export interface DecoratorInfo {
  name: string;
  line: number;
  /** The def/class body that follows this decorator. */
  body: LogicalStatement[];
  /** The def/class statement itself. */
  target: LogicalStatement | null;
}

export interface ImportInfo {
  module: string;
  names: string[];
  line: number;
}

export interface AnalysisResult {
  statements: LogicalStatement[];
  callGraph: CallEdge[];
  stringAssignments: { varName: string; value: string; line: number }[];
  dataFlow: DataFlowEdge[];
  decorators: DecoratorInfo[];
  imports: ImportInfo[];
  tokens: Token[];
}

// -------------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------------

const COMPOUND_KEYWORDS = new Set([
  "if", "elif", "else", "for", "while", "try", "except", "finally",
  "with", "def", "class",
]);

const PYTHON_KEYWORDS = new Set([
  "if", "elif", "else", "for", "while", "try", "except", "finally",
  "with", "def", "class", "import", "from", "return", "yield", "raise",
  "break", "continue", "pass", "global", "nonlocal", "del", "assert",
  "lambda", "async", "await", "in", "is", "not", "and", "or", "None",
  "True", "False",
]);

/** Dangerous sink callees for data-flow tracking. */
export const DANGEROUS_SINKS = new Set([
  "eval", "exec", "compile",
  "os.system", "os.popen", "os.exec", "os.execv", "os.execvp", "os.execve",
  "os.execl", "os.execlp", "os.spawnl", "os.spawnv",
  "subprocess.run", "subprocess.call", "subprocess.Popen",
  "subprocess.check_output", "subprocess.check_call",
  "subprocess.getoutput", "subprocess.getstatusoutput",
  "commands.getoutput", "commands.getstatusoutput",
  "pty.spawn",
]);

/** Sinks that execute Python code (vs shell commands). */
export const CODE_SINKS = new Set(["eval", "exec", "compile"]);

/** Sinks that execute shell commands. */
export const SHELL_SINKS = new Set([
  "os.system", "os.popen", "subprocess.run", "subprocess.call",
  "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
  "subprocess.getoutput", "subprocess.getstatusoutput",
  "commands.getoutput", "commands.getstatusoutput", "pty.spawn",
]);

// -------------------------------------------------------------------------
// Bracket matching helpers
// -------------------------------------------------------------------------

function findMatching(
  tokens: Token[],
  openIdx: number,
  open: string,
  close: string
): number {
  let depth = 0;
  for (let i = openIdx; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type !== "OP") continue;
    if (t.value === open) depth++;
    else if (t.value === close) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function findMatchingBackward(
  tokens: Token[],
  closeIdx: number,
  open: string,
  close: string
): number {
  let depth = 0;
  for (let i = closeIdx; i >= 0; i--) {
    const t = tokens[i];
    if (t.type !== "OP") continue;
    if (t.value === close) depth++;
    else if (t.value === open) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// -------------------------------------------------------------------------
// Call extraction
// -------------------------------------------------------------------------

/**
 * Walk backwards from the token immediately before a `(` to extract the
 * callee expression. Handles attribute chains (a.b.c), subscript (d["x"]),
 * and chained calls (foo().bar()).
 */
function extractCallee(
  tokens: Token[],
  endIdx: number
): { callee: string; parts: string[]; line: number; col: number; hasSubscript: boolean; hasLiteral: boolean } | null {
  if (endIdx < 0) return null;
  const parts: string[] = [];
  let line = 0;
  let col = 0;
  let hasSubscript = false;
  let hasLiteral = false;
  let j = endIdx;
  let expectDot = false;

  while (j >= 0) {
    const tok = tokens[j];
    if (!expectDot) {
      if (tok.type === "NAME") {
        parts.unshift(tok.value);
        if (line === 0) {
          line = tok.line;
          col = tok.col;
        }
        expectDot = true;
        j--;
      } else if (tok.type === "OP" && (tok.value === "]" || tok.value === ")" || tok.value === "}")) {
        const open = tok.value === "]" ? "[" : tok.value === ")" ? "(" : "{";
        const openIdx = findMatchingBackward(tokens, j, open, tok.value);
        if (openIdx < 0) break;
        const bracketText = tokens.slice(openIdx, j + 1).map((t) => t.value).join("");
        if (tok.value === "]") hasSubscript = true;
        if (tok.value === "}") hasLiteral = true;
        // Replace bracket content with (...) for normalized callee
        parts.unshift(tok.value === ")" ? "(...)" : bracketText);
        if (line === 0 && openIdx > 0 && tokens[openIdx - 1]?.type === "NAME") {
          line = tokens[openIdx - 1].line;
          col = tokens[openIdx - 1].col;
        }
        j = openIdx - 1;
        expectDot = false; // after a bracket, expect a NAME (the function/object)
      } else {
        break;
      }
    } else {
      if (tok.type === "OP" && tok.value === ".") {
        j--;
        expectDot = false;
      } else {
        break;
      }
    }
  }

  if (parts.length === 0) return null;
  const callee = parts.join(".");
  return { callee, parts, line, col, hasSubscript, hasLiteral };
}

/** Split a token list by top-level commas into argument token lists. */
function splitArgs(tokens: Token[]): Token[][] {
  const args: Token[][] = [];
  let depth = 0;
  let current: Token[] = [];
  for (const t of tokens) {
    if (t.type === "OP") {
      if (t.value === "(" || t.value === "[" || t.value === "{") depth++;
      else if (t.value === ")" || t.value === "]" || t.value === "}") depth--;
      else if (t.value === "," && depth === 0) {
        if (current.length > 0) args.push(current);
        current = [];
        continue;
      }
    }
    current.push(t);
  }
  if (current.length > 0) args.push(current);
  return args;
}

/** Parse an argument's token list into structured info (with nested call extraction). */
function parseArg(tokens: Token[], depth: number): ArgInfo {
  const text = tokens.map((t) => t.value).join("");
  const strings: string[] = [];
  const varRefs: string[] = [];
  let varName: string | null = null;
  let isStringLiteral = false;
  let isFString = false;
  let isConcatenation = false;

  // Single NAME → variable reference.
  if (tokens.length === 1 && tokens[0].type === "NAME") {
    varName = tokens[0].value;
  }
  // Single STRING → string literal.
  if (tokens.length === 1 && tokens[0].type === "STRING") {
    isStringLiteral = true;
  }

  let hasString = false;
  let hasPlus = false;
  for (const t of tokens) {
    if (t.type === "STRING") {
      hasString = true;
      strings.push(t.text ?? "");
      if ((t.prefix ?? "").includes("f")) isFString = true;
    }
    if (t.type === "NAME" && PYTHON_KEYWORDS.has(t.value) === false) {
      varRefs.push(t.value);
    }
    if (t.type === "OP" && t.value === "+") hasPlus = true;
  }

  // Detect string concatenation: STRING + STRING [+ ...] possibly with NAMEs.
  if (hasString && hasPlus) {
    let concatOk = true;
    for (const t of tokens) {
      if (t.type === "STRING") continue;
      if (t.type === "OP" && (t.value === "+" || t.value === "(" || t.value === ")")) continue;
      if (t.type === "NAME") continue;
      concatOk = false;
      break;
    }
    if (concatOk) isConcatenation = true;
  }

  // Nested calls — guarded by depth to prevent pathological recursion.
  const calls = depth < 8 ? extractCalls(tokens, depth + 1) : [];

  return {
    text,
    varName,
    strings,
    calls,
    isStringLiteral,
    isVariable: varName !== null,
    isFString,
    isConcatenation,
    varRefs,
  };
}

/** Extract all calls from a token list. Recursively parses arguments. */
function extractCalls(tokens: Token[], depth = 0): CallInfo[] {
  const calls: CallInfo[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type !== "OP" || t.value !== "(") continue;
    if (i === 0) continue;
    const calleeInfo = extractCallee(tokens, i - 1);
    if (!calleeInfo) continue;
    const closeIdx = findMatching(tokens, i, "(", ")");
    if (closeIdx < 0) continue;
    const argToks = tokens.slice(i + 1, closeIdx);
    // Skip keyword arguments by filtering out NAME= prefixes (best-effort).
    const args = splitArgs(argToks).map((a) => parseArg(a, depth));
    // Determine calleeName (last NAME part).
    let calleeName = "";
    for (let k = calleeInfo.parts.length - 1; k >= 0; k--) {
      const p = calleeInfo.parts[k];
      if (p && /^[A-Za-z_]\w*$/.test(p)) {
        calleeName = p;
        break;
      }
    }
    calls.push({
      callee: calleeInfo.callee,
      calleeParts: calleeInfo.parts,
      calleeName,
      args,
      line: calleeInfo.line || t.line,
      col: calleeInfo.col,
      hasSubscript: calleeInfo.hasSubscript,
      hasLiteralCallee: calleeInfo.hasLiteral,
    });
  }
  return calls;
}

// -------------------------------------------------------------------------
// Assignment extraction
// -------------------------------------------------------------------------

/** Assignment operators (excluding ==, !=, <=, >=). */
const ASSIGN_OPS = new Set(["=", "+=", "-=", "*=", "/=", "%=", "//=", "**=", "&=", "|=", "^=", ">>=", "<<=", "@=", ":="]);

/**
 * Extract assignments from a statement's token list.
 * Looks for `target = value` or `target op= value` at bracket depth 0.
 */
function extractAssignments(tokens: Token[], calls: CallInfo[]): AssignmentInfo[] {
  const out: AssignmentInfo[] = [];
  // Find the first assignment operator at depth 0.
  let depth = 0;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type === "OP") {
      if (t.value === "(" || t.value === "[" || t.value === "{") depth++;
      else if (t.value === ")" || t.value === "]" || t.value === "}") depth--;
      else if (depth === 0 && ASSIGN_OPS.has(t.value)) {
        // Check it's not == by verifying the previous char — but our tokenizer
        // already separates == and =, so this is safe.
        const targetToks = tokens.slice(0, i);
        const valueToks = tokens.slice(i + 1);
        const target = targetToks.map((tk) => tk.value).join("").trim();
        const valueText = valueToks.map((tk) => tk.value).join("").trim();
        // Target variable name (if single NAME).
        let targetVar: string | null = null;
        if (targetToks.length === 1 && targetToks[0].type === "NAME") {
          targetVar = targetToks[0].value;
        }
        // Analyze RHS.
        const valueStrings: string[] = [];
        const valueVarRefs: string[] = [];
        let isString = false;
        let isStringConcat = false;
        let isFString = false;
        let isList = false;
        if (valueToks.length === 1 && valueToks[0].type === "STRING") {
          isString = true;
        }
        let hasString = false;
        let hasPlus = false;
        for (const tk of valueToks) {
          if (tk.type === "STRING") {
            hasString = true;
            valueStrings.push(tk.text ?? "");
            if ((tk.prefix ?? "").includes("f")) isFString = true;
          }
          if (tk.type === "NAME" && !PYTHON_KEYWORDS.has(tk.value)) {
            valueVarRefs.push(tk.value);
          }
          if (tk.type === "OP" && tk.value === "+") hasPlus = true;
        }
        if (hasString && hasPlus) {
          let concatOk = true;
          for (const tk of valueToks) {
            if (tk.type === "STRING") continue;
            if (tk.type === "OP" && (tk.value === "+" || tk.value === "(" || tk.value === ")")) continue;
            if (tk.type === "NAME") continue;
            concatOk = false;
            break;
          }
          if (concatOk) isStringConcat = true;
        }
        // Check for list literal.
        if (valueToks.length >= 2 && valueToks[0]?.type === "OP" && valueToks[0]?.value === "[") {
          isList = true;
        }
        // Calls in the RHS — reuse the already-extracted calls that fall within the RHS range.
        const valueStartCol = valueToks[0]?.col ?? 0;
        const valueCalls = calls.filter((c) => c.col >= valueStartCol);
        out.push({
          target,
          targetVar,
          valueText,
          valueStrings,
          valueCalls,
          valueVarRefs,
          isString,
          isStringConcat,
          isFString,
          isList,
          line: tokens[0]?.line ?? 1,
        });
        break; // only handle the first assignment in a statement
      }
    }
  }
  return out;
}

// -------------------------------------------------------------------------
// Import extraction
// -------------------------------------------------------------------------

function extractImport(tokens: Token[], line: number): ImportInfo | null {
  if (tokens.length < 2) return null;
  const first = tokens[0];
  if (first.type !== "NAME") return null;
  if (first.value === "import") {
    // import a, b.c as d
    const rest = tokens.slice(1);
    const names: string[] = [];
    let moduleName = "";
    const text = rest.map((t) => t.value).join("");
    // Split by comma at depth 0.
    let depth = 0;
    let current = "";
    for (const t of rest) {
      if (t.type === "OP") {
        if (t.value === "(" || t.value === "[") depth++;
        else if (t.value === ")" || t.value === "]") depth--;
        else if (t.value === "," && depth === 0) {
          if (current) names.push(current);
          current = "";
          continue;
        }
      }
      current += t.value;
    }
    if (current) names.push(current);
    moduleName = (names[0] ?? "").split(/\s+as\s+/)[0].split(".")[0];
    const cleanNames = names.map((n) => n.split(/\s+as\s+/)[0].trim());
    return { module: moduleName, names: cleanNames, line };
  }
  if (first.value === "from") {
    // from a.b import c, d
    let moduleName = "";
    const rest = tokens.slice(1);
    // Find "import" keyword.
    let importIdx = -1;
    for (let i = 0; i < rest.length; i++) {
      if (rest[i].type === "NAME" && rest[i].value === "import") {
        importIdx = i;
        break;
      }
    }
    if (importIdx < 0) return null;
    moduleName = rest.slice(0, importIdx).map((t) => t.value).join("").trim();
    const nameToks = rest.slice(importIdx + 1);
    const text = nameToks.map((t) => t.value).join("");
    const names: string[] = [];
    let depth = 0;
    let current = "";
    for (const t of nameToks) {
      if (t.type === "OP") {
        if (t.value === "(" || t.value === "[") depth++;
        else if (t.value === ")" || t.value === "]") depth--;
        else if (t.value === "*" && depth === 0) {
          names.push("*");
          continue;
        }
        else if (t.value === "," && depth === 0) {
          if (current) names.push(current);
          current = "";
          continue;
        }
      }
      current += t.value;
    }
    if (current) names.push(current);
    const cleanNames = names.map((n) => n.split(/\s+as\s+/)[0].trim()).filter(Boolean);
    return { module: moduleName, names: cleanNames, line };
  }
  return null;
}

// -------------------------------------------------------------------------
// Statement grouping
// -------------------------------------------------------------------------

const DECORATOR_KEYWORD = "@";

function groupStatements(tokens: Token[], lines: string[]): LogicalStatement[] {
  const stmts: LogicalStatement[] = [];
  let i = 0;
  const n = tokens.length;
  let currentIndent = 0;

  while (i < n) {
    const t = tokens[i];
    if (t.type === "INDENT") {
      currentIndent++;
      i++;
      continue;
    }
    if (t.type === "DEDENT") {
      currentIndent = Math.max(0, currentIndent - 1);
      i++;
      continue;
    }
    if (t.type === "NEWLINE" || t.type === "NL" || t.type === "COMMENT") {
      i++;
      continue;
    }

    // Collect tokens until NEWLINE.
    const start = i;
    const startLine = t.line;
    let endLine = startLine;
    while (i < n && tokens[i].type !== "NEWLINE") {
      if (tokens[i].type !== "NL" && tokens[i].type !== "COMMENT") {
        endLine = tokens[i].line;
      }
      i++;
    }
    const stmtTokens = tokens
      .slice(start, i)
      .filter((tk) => tk.type !== "NL" && tk.type !== "COMMENT");

    if (stmtTokens.length === 0) continue;

    // Determine keyword.
    let keyword: string | null = null;
    let decoratorNames: string[] = [];
    if (stmtTokens[0].type === "OP" && stmtTokens[0].value === "@") {
      keyword = DECORATOR_KEYWORD;
      // Extract decorator name: @name or @name(args)
      const nameToks = stmtTokens.slice(1);
      const name = nameToks.map((t) => t.value).join("").trim();
      decoratorNames.push(name);
    } else if (stmtTokens[0].type === "NAME" && PYTHON_KEYWORDS.has(stmtTokens[0].value)) {
      keyword = stmtTokens[0].value;
    }

    const isCompound = keyword !== null && COMPOUND_KEYWORDS.has(keyword);

    // Reconstruct text from source lines.
    const text = lines.slice(startLine - 1, endLine).join("\n").trim();

    const stmt: LogicalStatement = {
      startLine,
      endLine,
      indent: currentIndent,
      tokens: stmtTokens,
      text,
      keyword,
      isCompound,
      calls: [],
      assignments: [],
      stringLiterals: [],
      decoratorNames,
      parent: null,
      body: [],
    };

    // Extract structured info.
    stmt.calls = extractCalls(stmtTokens);
    stmt.assignments = extractAssignments(stmtTokens, stmt.calls);
    stmt.stringLiterals = stmtTokens
      .filter((tk) => tk.type === "STRING")
      .map((tk) => ({
        text: tk.text ?? "",
        prefix: tk.prefix ?? "",
        line: tk.line,
        col: tk.col,
      }));

    stmts.push(stmt);
  }

  return stmts;
}

// -------------------------------------------------------------------------
// Block tree construction
// -------------------------------------------------------------------------

function buildBlockTree(stmts: LogicalStatement[]): void {
  const stack: LogicalStatement[] = [];
  for (const stmt of stmts) {
    while (stack.length > 0 && stack[stack.length - 1].indent >= stmt.indent) {
      stack.pop();
    }
    if (stack.length > 0) {
      stmt.parent = stack[stack.length - 1];
      stack[stack.length - 1].body.push(stmt);
    }
    if (stmt.isCompound) {
      stack.push(stmt);
    }
  }
}

// -------------------------------------------------------------------------
// Decorator linking
// -------------------------------------------------------------------------

function linkDecorators(stmts: LogicalStatement[]): DecoratorInfo[] {
  const decorators: DecoratorInfo[] = [];
  for (let i = 0; i < stmts.length; i++) {
    const stmt = stmts[i];
    if (stmt.keyword !== DECORATOR_KEYWORD) continue;
    // Find the next non-decorator statement at the same indent.
    let target: LogicalStatement | null = null;
    for (let j = i + 1; j < stmts.length; j++) {
      if (stmts[j].indent < stmt.indent) break;
      if (stmts[j].indent === stmt.indent && stmts[j].keyword !== DECORATOR_KEYWORD) {
        target = stmts[j];
        break;
      }
    }
    const body = target ? target.body : [];
    for (const name of stmt.decoratorNames) {
      decorators.push({
        name,
        line: stmt.startLine,
        body,
        target,
      });
    }
  }
  return decorators;
}

// -------------------------------------------------------------------------
// Data flow tracking
// -------------------------------------------------------------------------

/**
 * Build data-flow edges: variables assigned a value → later passed to a
 * dangerous sink. Returns edges for each (var, sink) pair.
 */
function buildDataFlow(stmts: LogicalStatement[]): DataFlowEdge[] {
  // Map varName → latest assignment info (per scope — but we use a flat map
  // for simplicity; Python scoping is complex and this is heuristic).
  const varMap = new Map<string, AssignmentInfo>();
  const edges: DataFlowEdge[] = [];

  for (const stmt of stmts) {
    // Register assignments first (so a call on the same line can reference them
    // — though in practice the assignment is usually on a prior line).
    for (const assign of stmt.assignments) {
      if (assign.targetVar) {
        varMap.set(assign.targetVar, assign);
      }
    }
    // Check calls for dangerous sinks.
    for (const call of stmt.calls) {
      const sink = call.callee;
      const isDangerous =
        DANGEROUS_SINKS.has(sink) ||
        CODE_SINKS.has(sink) ||
        SHELL_SINKS.has(sink) ||
        call.calleeName === "eval" ||
        call.calleeName === "exec" ||
        call.calleeName === "compile" ||
        call.calleeName === "system" ||
        call.calleeName === "popen";
      if (!isDangerous) continue;
      for (const arg of call.args) {
        if (arg.varName) {
          const assign = varMap.get(arg.varName);
          if (assign) {
            edges.push({
              varName: arg.varName,
              sink,
              sinkLine: call.line,
              defLine: assign.line,
              snippet: stmt.text,
              confidence: 0.75,
              assignment: assign,
            });
          }
        }
      }
    }
  }

  return edges;
}

// -------------------------------------------------------------------------
// Call graph
// -------------------------------------------------------------------------

function buildCallGraph(stmts: LogicalStatement[]): CallEdge[] {
  const edges: CallEdge[] = [];
  // The "caller" is the enclosing function def (if any).
  for (const stmt of stmts) {
    // Find enclosing def.
    let caller = "<module>";
    let p: LogicalStatement | null = stmt.parent;
    while (p) {
      if (p.keyword === "def" && p.tokens.length >= 2 && p.tokens[1].type === "NAME") {
        caller = p.tokens[1].value;
        break;
      }
      p = p.parent;
    }
    for (const call of stmt.calls) {
      edges.push({ caller, callee: call.callee, line: call.line });
    }
  }
  return edges;
}

// -------------------------------------------------------------------------
// Main entry point
// -------------------------------------------------------------------------

/**
 * Analyze Python source code and return structured statement-level info.
 *
 * This function is the core of the AST-aware detection layer. It is called
 * once per scan (cached by the rules via a WeakMap) and provides all the
 * structured data the AST rules need.
 *
 * Defensive: never throws — returns an empty result on error.
 */
export function analyzePython(source: string): AnalysisResult {
  try {
    const lines = source.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
    const t0 = Date.now();
    const tokens = tokenizePython(source);
    const t1 = Date.now();
    const statements = groupStatements(tokens, lines);
    const t2 = Date.now();
    buildBlockTree(statements);
    const t3 = Date.now();
    const decorators = linkDecorators(statements);
    const imports: ImportInfo[] = [];
    for (const stmt of statements) {
      if (stmt.keyword === "import" || stmt.keyword === "from") {
        const imp = extractImport(stmt.tokens, stmt.startLine);
        if (imp) imports.push(imp);
      }
    }
    const dataFlow = buildDataFlow(statements);
    const t4 = Date.now();
    const callGraph = buildCallGraph(statements);

    // Collect string assignments for the public API.
    const stringAssignments: { varName: string; value: string; line: number }[] = [];
    for (const stmt of statements) {
      for (const a of stmt.assignments) {
        if (a.targetVar && (a.isString || a.isStringConcat || a.isFString)) {
          stringAssignments.push({
            varName: a.targetVar,
            value: a.valueStrings.join(" + ") || a.valueText,
            line: a.line,
          });
        }
      }
    }

    return {
      statements,
      callGraph,
      stringAssignments,
      dataFlow,
      decorators,
      imports,
      tokens,
      _timing: { tokenize: t1 - t0, group: t2 - t1, block: t3 - t2, dataflow: t4 - t3 },
    } as AnalysisResult;
  } catch {
    return {
      statements: [],
      callGraph: [],
      stringAssignments: [],
      dataFlow: [],
      decorators: [],
      imports: [],
      tokens: [],
    };
  }
}
