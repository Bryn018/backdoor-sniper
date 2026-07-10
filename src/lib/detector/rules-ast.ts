/**
 * AST-aware detection rules.
 *
 * These 33 rules use the statement-level analyzer (`analyzePython`) to
 * catch malicious Python patterns that regex alone cannot see:
 *   - Indirect execution (getattr, __import__, attribute chains, dict lookups)
 *   - Data flow to dangerous sinks (string var → eval/exec/system)
 *   - Multi-stage payloads (fetch→exec, decode→eval, decompress→exec)
 *   - Decorator / metaclass abuse
 *   - Lambda / functional obfuscation
 *   - Conditional / triggered payloads
 *   - String / encoding tricks (chr arrays, bytes.fromhex, compile)
 *
 * Each rule follows the existing `DetectionRule` interface and uses
 * `ctx.source` (analyzed internally via a cached WeakMap) to find
 * sophisticated patterns.
 *
 * CRITICAL PERFORMANCE: All rules share a single `analyzePython` result
 * per scan via a module-level WeakMap keyed on the ScanContext. Running
 * 33 rules does NOT re-analyze the source 33 times.
 */

import type { DetectionRule, RawMatch, ScanContext } from "./types";
import {
  analyzePython,
  type AnalysisResult,
  type CallInfo,
  type DataFlowEdge,
  type LogicalStatement,
  type ArgInfo,
  CODE_SINKS,
  SHELL_SINKS,
} from "./python-ast";

// -------------------------------------------------------------------------
// Analysis cache — keyed on ScanContext (one analysis per scan).
// -------------------------------------------------------------------------

const analysisCache = new WeakMap<ScanContext, AnalysisResult>();

function getAnalysis(ctx: ScanContext): AnalysisResult {
  let a = analysisCache.get(ctx);
  if (!a) {
    a = analyzePython(ctx.source);
    analysisCache.set(ctx, a);
  }
  return a;
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/** Build a RawMatch from a line number + ctx. */
function matchAt(ctx: ScanContext, line: number, confidence: number, extra?: string): RawMatch {
  const raw = ctx.lines[line - 1] ?? "";
  const snippet = raw.trim().slice(0, 200);
  return { line, snippet, confidence, extra };
}

/** Check if a call's callee matches any of the given names (full or last-segment). */
function callIs(call: CallInfo, names: Set<string>): boolean {
  if (names.has(call.callee)) return true;
  if (names.has(call.calleeName)) return true;
  return false;
}

/** Recursively collect all calls in a statement's body tree. */
function collectBodyCalls(stmt: LogicalStatement): CallInfo[] {
  const calls: CallInfo[] = [];
  const visit = (s: LogicalStatement) => {
    calls.push(...s.calls);
    for (const child of s.body) visit(child);
  };
  for (const child of stmt.body) visit(child);
  return calls;
}

/** Check if a statement's body contains a call to any of the given names. */
function bodyHasCall(stmt: LogicalStatement, names: Set<string>): boolean {
  return collectBodyCalls(stmt).some((c) => callIs(c, names));
}

/** Find a function definition by name in the statement list. */
function findDef(statements: LogicalStatement[], funcName: string): LogicalStatement | null {
  for (const s of statements) {
    if (
      s.keyword === "def" &&
      s.tokens.length >= 2 &&
      s.tokens[1].type === "NAME" &&
      s.tokens[1].value === funcName
    ) {
      return s;
    }
  }
  return null;
}

/** Check if a data-flow edge's sink is a code-execution sink. */
function edgeIsCodeSink(edge: DataFlowEdge): boolean {
  const s = edge.sink.toLowerCase();
  if (s === "eval" || s === "exec" || s === "compile") return true;
  if (s.endsWith(".eval") || s.endsWith(".exec") || s.endsWith(".compile")) return true;
  // callee like "getattr(...).eval"
  if (s.includes(".eval") || s.includes(".exec") || s.includes(".compile")) return true;
  return false;
}

/** Check if a data-flow edge's sink is a shell-execution sink. */
function edgeIsShellSink(edge: DataFlowEdge): boolean {
  const s = edge.sink.toLowerCase();
  if (s === "system" || s === "popen") return true;
  if (s.startsWith("os.system") || s.startsWith("os.popen")) return true;
  if (s.startsWith("subprocess.")) return true;
  if (s.startsWith("commands.")) return true;
  if (s.startsWith("os.exec") || s.startsWith("os.spawn")) return true;
  if (s === "pty.spawn") return true;
  return false;
}

/** Check if an argument references a dangerous function name. */
function argReferencesDanger(arg: ArgInfo, names: Set<string>): boolean {
  if (arg.varName && names.has(arg.varName)) return true;
  for (const ref of arg.varRefs) {
    if (names.has(ref)) return true;
  }
  if (arg.calls.some((c) => callIs(c, names))) return true;
  return false;
}

/** Known dangerous function names (bare). */
const DANGER_NAMES = new Set([
  "eval", "exec", "compile", "system", "popen",
  "__import__", "getattr", "globals", "locals",
]);

/** Check if a string value looks like a dangerous sink name. */
const DANGER_STRING_VALUES = new Set([
  "eval", "exec", "compile", "__import__", "__builtins__",
  "system", "popen",
]);

// =========================================================================
// Indirect execution (regex can't see these)
// =========================================================================

// PY-AST-001: Indirect eval via getattr(__builtins__, "...")
const ast001: DetectionRule = {
  id: "PY-AST-001",
  title: "Indirect builtin lookup via getattr(__builtins__, \"...\")",
  severity: "critical",
  category: "code-execution",
  description:
    "getattr(__builtins__, \"eval\") retrieves the eval function dynamically by name, defeating regex signatures that look for direct eval() calls. This is a common obfuscation in Python web shells and droppers — the string \"eval\" is passed as data, not as a call, so string-based scanners miss it.",
  remediation:
    "Remove the indirect lookup. If you genuinely need dynamic dispatch, use a whitelisted dictionary of safe callables. Never resolve builtin names from string data.",
  references: ["CWE-95", "CWE-913", "OWASP A03:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const s of a.statements) {
        for (const c of s.calls) {
          if (c.calleeName !== "getattr" && c.callee !== "getattr") continue;
          if (c.args.length < 2) continue;
          const a0 = c.args[0];
          const a1 = c.args[1];
          const targetIsBuiltin =
            a0.varName === "__builtins__" ||
            a0.varName === "builtins" ||
            a0.text.includes("__builtins__") ||
            a0.text.includes("builtins");
          if (!targetIsBuiltin) continue;
          const sinkName = a1.strings[0] ?? a1.text.replace(/['"]/g, "");
          if (DANGER_STRING_VALUES.has(sinkName.toLowerCase())) {
            out.push(matchAt(ctx, c.line, 0.92, `getattr(__builtins__, "${sinkName}")`));
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-002: Indirect exec via __import__("builtins").exec
const ast002: DetectionRule = {
  id: "PY-AST-002",
  title: "Indirect execution via __import__(...).exec / .eval chain",
  severity: "critical",
  category: "code-execution",
  description:
    "__import__(\"builtins\").exec(...) dynamically imports the builtins module and calls exec through it, bypassing direct-call detection. This attribute-chain obfuscation is used in real-world droppers to hide the exec/eval call behind an import indirection.",
  remediation:
    "Remove the __import__ chain. If dynamic module loading is required, validate the module name against a strict whitelist and never chain into exec/eval/compile.",
  references: ["CWE-95", "CWE-913", "OWASP A03:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const s of a.statements) {
        for (const c of s.calls) {
          // Look for calls whose callee chain includes __import__ and a code sink.
          const hasImport = c.calleeParts.some(
            (p) => p === "__import__" || p.includes("__import__")
          );
          const hasCodeSink =
            c.calleeName === "eval" ||
            c.calleeName === "exec" ||
            c.calleeName === "compile" ||
            CODE_SINKS.has(c.callee);
          if (hasImport && hasCodeSink) {
            out.push(matchAt(ctx, c.line, 0.9, c.callee));
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-003: Attribute chain obfuscation (a.b.c.d where intermediate is __builtins__/os/sys)
const ast003: DetectionRule = {
  id: "PY-AST-003",
  title: "Deep attribute chain to dangerous builtin (obfuscation)",
  severity: "high",
  category: "obfuscation",
  description:
    "A long attribute chain (3+ segments) reaching into __builtins__, os, or sys is a common obfuscation technique. Attackers write things like __builtins__.__dict__['eval'] or sys.modules['os'].system to evade simple pattern matching. The deeper the chain, the more likely it is deliberately hiding the true call target.",
  remediation:
    "Flatten the attribute chain to a direct, reviewable call. If the indirection is intentional (e.g. plugin loading), document why and restrict the reachable names with a whitelist.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const chainRoots = new Set(["__builtins__", "builtins", "os", "sys", "importlib"]);
      for (const s of a.statements) {
        for (const c of s.calls) {
          if (c.calleeParts.length < 3) continue;
          // Check if the root of the chain is a suspicious module.
          const root = c.calleeParts[0];
          if (!chainRoots.has(root)) continue;
          // And the final callee is a dangerous name.
          if (!DANGER_NAMES.has(c.calleeName) && !CODE_SINKS.has(c.callee) && !SHELL_SINKS.has(c.callee)) {
            // Also check if any part is a danger name.
            if (!c.calleeParts.some((p) => DANGER_NAMES.has(p))) continue;
          }
          out.push(matchAt(ctx, c.line, 0.78, c.callee));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-004: Variable indirection (v = eval; v(...))
const ast004: DetectionRule = {
  id: "PY-AST-004",
  title: "Variable indirection — dangerous function assigned to a variable then called",
  severity: "critical",
  category: "code-execution",
  description:
    "Assigning a dangerous function (eval, exec, os.system) to a variable and then calling it through the variable is a classic obfuscation. The assignment `v = eval` looks harmless to a regex scanner, but `v(payload)` is just as dangerous as `eval(payload)`. This pattern is used in obfuscated droppers to split the call from the function name.",
  remediation:
    "Call the function directly by its real name. If you need a callable reference for dispatch, use a whitelisted dictionary with documented safe entries.",
  references: ["CWE-95", "CWE-913", "OWASP A03:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      // Build a map: varName -> dangerous function it was assigned.
      const varToFunc = new Map<string, string>();
      const allDangerous = new Set<string>([
        ...CODE_SINKS, ...SHELL_SINKS,
        "eval", "exec", "compile", "system", "popen",
      ]);
      for (const s of a.statements) {
        for (const assign of s.assignments) {
          if (!assign.targetVar) continue;
          const val = assign.valueText.trim();
          if (allDangerous.has(val)) {
            varToFunc.set(assign.targetVar, val);
          }
        }
      }
      // Now find calls to those variables.
      for (const s of a.statements) {
        for (const c of s.calls) {
          const func = varToFunc.get(c.callee);
          if (func) {
            out.push(matchAt(ctx, c.line, 0.88, `${c.callee} = ${func}`));
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-005: Dict/list lookup for callable ({"e": eval}["e"](...))
const ast005: DetectionRule = {
  id: "PY-AST-005",
  title: "Callable retrieved from dict/list literal then invoked",
  severity: "critical",
  category: "code-execution",
  description:
    "Constructing a dictionary that maps string keys to dangerous functions (e.g. {\"e\": eval}) and then invoking via subscript (d[\"e\"](...)) is an obfuscation technique that hides the function name behind a data lookup. Regex scanners looking for `eval(` will not match `d[\"e\"](`. This is used in real-world backdoors to build dispatch tables that hide the real call targets.",
  remediation:
    "Replace the dict-lookup dispatch with direct function calls. If a dispatch table is required, use only safe, whitelisted callables and document each entry.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const s of a.statements) {
        for (const c of s.calls) {
          // The callee involves a dict/list literal and/or subscript.
          if (!c.hasLiteralCallee && !c.hasSubscript) continue;
          // Check if any argument or the statement context references danger.
          // Also check the callee text for a dict literal containing danger names.
          const calleeText = c.callee;
          const hasDangerInCallee = DANGER_NAMES.has(c.calleeName) ||
            calleeText.includes("eval") || calleeText.includes("exec") ||
            calleeText.includes("system");
          // If the callee is a dict literal subscript, check the surrounding statement
          // for an assignment of a dict containing danger names.
          let dictHasDanger = false;
          if (c.hasLiteralCallee) {
            for (const s2 of a.statements) {
              for (const assign of s2.assignments) {
                if (assign.valueText.includes("{") && assign.valueText.includes("eval") ||
                    (assign.valueText.includes("{") && assign.valueText.includes("exec")) ||
                    (assign.valueText.includes("{") && assign.valueText.includes("system"))) {
                  if (c.callee.includes(assign.targetVar ?? "\0")) {
                    dictHasDanger = true;
                  }
                }
              }
            }
          }
          if (hasDangerInCallee || dictHasDanger) {
            out.push(matchAt(ctx, c.line, 0.82, c.callee));
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// =========================================================================
// Data flow to dangerous sinks
// =========================================================================

// PY-AST-006: String variable assigned then passed to eval
const ast006: DetectionRule = {
  id: "PY-AST-006",
  title: "String variable assigned then passed to eval()",
  severity: "critical",
  category: "code-execution",
  description:
    "A string literal is assigned to a variable and that variable is later passed to eval(). This splits the payload from the call across multiple lines, which evades single-line regex scanners that only look for eval(\"...\"). The string may itself contain encoded or obfuscated code.",
  remediation:
    "Do not pass dynamically-built strings to eval. If you are evaluating trusted expressions, use ast.literal_eval(). Remove eval entirely if the input is not fully trusted.",
  references: ["CWE-95", "OWASP A03:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const edge of a.dataFlow) {
        if (!edgeIsCodeSink(edge)) continue;
        if (edge.sink !== "eval" && !edge.sink.endsWith(".eval") && !edge.sink.includes(".eval")) continue;
        if (edge.assignment.isString) {
          out.push(matchAt(ctx, edge.sinkLine, 0.9, `${edge.varName} = "${edge.assignment.valueStrings[0]?.slice(0, 40)}..."`));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-007: String variable assigned then passed to exec
const ast007: DetectionRule = {
  id: "PY-AST-007",
  title: "String variable assigned then passed to exec()",
  severity: "critical",
  category: "code-execution",
  description:
    "A string literal is assigned to a variable and that variable is later passed to exec(). This is the most common pattern in Python droppers: the payload string is built (or decoded) on one line and executed on the next. Splitting the assignment from the call evades line-based regex detection.",
  remediation:
    "Remove exec(). If loading trusted code, import it as a module. Never pass attacker-controlled or dynamically-built strings to exec.",
  references: ["CWE-95", "OWASP A03:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const edge of a.dataFlow) {
        if (!edgeIsCodeSink(edge)) continue;
        if (edge.sink !== "exec" && !edge.sink.endsWith(".exec") && !edge.sink.includes(".exec")) continue;
        if (edge.assignment.isString) {
          out.push(matchAt(ctx, edge.sinkLine, 0.9, `${edge.varName} = "${edge.assignment.valueStrings[0]?.slice(0, 40)}..."`));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-008: String variable assigned then passed to os.system / subprocess
const ast008: DetectionRule = {
  id: "PY-AST-008",
  title: "String variable assigned then passed to shell execution sink",
  severity: "critical",
  category: "command-execution",
  description:
    "A string literal is assigned to a variable and that variable is later passed to os.system, subprocess.run, or similar. This splits the command string from the shell call, evading regex. The string may contain a reverse shell, download-and-execute, or destructive command.",
  remediation:
    "Use subprocess.run with a list of arguments (shell=False) and validate each argument. Never pass user-controlled strings to os.system or shell=True.",
  references: ["CWE-78", "OWASP A03:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const edge of a.dataFlow) {
        if (!edgeIsShellSink(edge)) continue;
        if (edge.assignment.isString) {
          out.push(matchAt(ctx, edge.sinkLine, 0.88, `${edge.varName} = "${edge.assignment.valueStrings[0]?.slice(0, 40)}..."`));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-009: String concatenation building dangerous call
const ast009: DetectionRule = {
  id: "PY-AST-009",
  title: "String concatenation building a command/code payload",
  severity: "high",
  category: "obfuscation",
  description:
    "A dangerous string is built by concatenating multiple string fragments (e.g. cmd = \"rm\" + \" -rf \" + \"/\") and then passed to a shell or code execution sink. This fragmentation evades signature matching on the complete string — each fragment looks harmless individually.",
  remediation:
    "Build commands as structured argument lists (subprocess.run([\"rm\", \"-rf\", path])) instead of string concatenation. Validate and sanitize each component.",
  references: ["CWE-78", "CWE-913", "OWASP A03:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const edge of a.dataFlow) {
        if (edge.assignment.isStringConcat) {
          out.push(matchAt(ctx, edge.sinkLine, 0.8, `${edge.varName} = concat → ${edge.sink}`));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-010: f-string injection into shell command
const ast010: DetectionRule = {
  id: "PY-AST-010",
  title: "f-string interpolation injected into shell command",
  severity: "high",
  category: "command-execution",
  description:
    "An f-string with variable interpolation is passed directly to a shell execution sink (e.g. subprocess.run(f\"echo {user_input}\")). If the interpolated value is attacker-controlled, this is a shell injection vulnerability — the attacker can break out of the intended command and execute arbitrary shell code.",
  remediation:
    "Never use f-strings or string formatting to build shell commands. Pass arguments as a list: subprocess.run([\"echo\", user_input]). Use shell=False always.",
  references: ["CWE-78", "CWE-94", "OWASP A03:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const s of a.statements) {
        for (const c of s.calls) {
          const isShell =
            SHELL_SINKS.has(c.callee) ||
            c.calleeName === "system" || c.calleeName === "popen" ||
            c.callee.startsWith("subprocess.") || c.callee.startsWith("os.system") || c.callee.startsWith("os.popen");
          if (!isShell) continue;
          for (const arg of c.args) {
            if (arg.isFString && arg.text.includes("{")) {
              out.push(matchAt(ctx, c.line, 0.85, `f-string → ${c.callee}`));
              break;
            }
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-011: List of strings joined and passed to shell
const ast011: DetectionRule = {
  id: "PY-AST-011",
  title: "List of strings joined and passed to shell execution",
  severity: "high",
  category: "command-execution",
  description:
    "A list of string fragments is assembled, joined into a single string (e.g. \" \".join(parts)), and then passed to a shell sink. This is a two-step obfuscation: the command is split across list elements (evading string signatures) and reassembled at runtime before execution.",
  remediation:
    "Pass the list directly to subprocess.run(parts, shell=False) instead of joining into a string. Avoid shell=True entirely.",
  references: ["CWE-78", "CWE-913", "OWASP A03:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const edge of a.dataFlow) {
        if (!edgeIsShellSink(edge) && !edgeIsCodeSink(edge)) continue;
        // Check if the assignment's RHS involves a .join() call.
        const hasJoin = edge.assignment.valueCalls.some(
          (c) => c.calleeName === "join" || c.callee.endsWith(".join")
        );
        if (hasJoin) {
          out.push(matchAt(ctx, edge.sinkLine, 0.78, `join() → ${edge.sink}`));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-012: Base64-decoded variable passed to exec
const ast012: DetectionRule = {
  id: "PY-AST-012",
  title: "Base64-decoded payload passed to exec/eval",
  severity: "critical",
  category: "obfuscation",
  description:
    "A base64-encoded blob is decoded (via base64.b64decode) and the result is passed to exec or eval. This is the most common Python dropper pattern: the malicious code is hidden as a base64 string, decoded at runtime, and executed — the plaintext payload never appears in the source file.",
  remediation:
    "Remove the base64 decode + exec pattern entirely. If the payload is legitimate (e.g. a packed resource), unpack it at build time and ship the real code. Never exec runtime-decoded data.",
  references: ["CWE-95", "CWE-912", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const edge of a.dataFlow) {
        if (!edgeIsCodeSink(edge)) continue;
        const hasB64 = edge.assignment.valueCalls.some(
          (c) =>
            c.calleeName === "b64decode" ||
            c.callee === "base64.b64decode" ||
            c.callee === "b64decode" ||
            c.callee.includes("b64decode") ||
            c.callee.includes("decodestring")
        );
        if (hasB64) {
          out.push(matchAt(ctx, edge.sinkLine, 0.92, `b64decode → ${edge.sink}`));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// =========================================================================
// Multi-stage payloads
// =========================================================================

// PY-AST-013: Fetch-then-exec pattern (urlopen → read → exec)
const ast013: DetectionRule = {
  id: "PY-AST-013",
  title: "Fetch-then-exec pattern (network download → exec/eval)",
  severity: "critical",
  category: "code-execution",
  description:
    "Code is fetched from a remote URL (urlopen, requests.get, urllib) and the response body is passed to exec or eval. This is the classic fileless dropper: the malicious payload lives on an attacker-controlled server and is never written to disk on the victim. Even when the fetch and exec are on separate lines, the data flow connects them.",
  remediation:
    "Never download and execute remote code. If you need to fetch a resource, validate its integrity (signature, hash) and process it as data, not as executable code.",
  references: ["CWE-95", "CWE-912", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const fetchNames = new Set([
        "urlopen", "requests.get", "requests.post",
        "urllib.request.urlopen", "urllib.urlopen",
        "httpx.get", "httpx.post",
      ]);
      for (const edge of a.dataFlow) {
        if (!edgeIsCodeSink(edge)) continue;
        const hasFetch = edge.assignment.valueCalls.some((c) => {
          if (fetchNames.has(c.callee)) return true;
          if (c.calleeName === "urlopen" || c.calleeName === "get" || c.calleeName === "post") {
            // Check if the call chain involves a known HTTP module.
            return c.calleeParts.some((p) =>
              ["requests", "urllib", "httpx", "urlopen"].includes(p)
            );
          }
          return false;
        });
        const hasRead = edge.assignment.valueCalls.some(
          (c) => c.calleeName === "read" || c.callee.endsWith(".read")
        );
        if (hasFetch || (hasRead && edge.assignment.valueText.includes("http"))) {
          out.push(matchAt(ctx, edge.sinkLine, 0.88, `fetch → ${edge.sink}`));
        }
      }
      // Also check direct inline: exec(urlopen(url).read())
      for (const s of a.statements) {
        for (const c of s.calls) {
          if (!callIs(c, CODE_SINKS) && c.calleeName !== "eval" && c.calleeName !== "exec") continue;
          const argCalls = c.args.flatMap((arg) => arg.calls);
          const hasFetch = argCalls.some((ac) =>
            fetchNames.has(ac.callee) || ac.calleeName === "urlopen" ||
            ac.calleeParts.some((p) => ["requests", "urllib", "httpx"].includes(p))
          );
          const hasRead = argCalls.some((ac) => ac.calleeName === "read");
          if (hasFetch && hasRead) {
            out.push(matchAt(ctx, c.line, 0.9, `inline fetch → ${c.calleeName}`));
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-014: File-read-then-exec pattern
const ast014: DetectionRule = {
  id: "PY-AST-014",
  title: "File-read-then-exec pattern (open → read → exec/eval)",
  severity: "critical",
  category: "code-execution",
  description:
    "Code is read from a file (open(...).read()) and passed to exec or eval. This is used by droppers that write a payload to a temp file, then read and execute it — splitting the write and exec across separate operations to evade detection.",
  remediation:
    "Do not exec file contents. If loading trusted code, import it as a module. If the file is data, parse it with a safe parser, not exec.",
  references: ["CWE-95", "CWE-912", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const edge of a.dataFlow) {
        if (!edgeIsCodeSink(edge)) continue;
        const hasOpen = edge.assignment.valueCalls.some(
          (c) => c.calleeName === "open" || c.callee === "open" || c.callee.endsWith(".open")
        );
        const hasRead = edge.assignment.valueCalls.some(
          (c) => c.calleeName === "read" || c.callee.endsWith(".read")
        );
        if (hasOpen && hasRead) {
          out.push(matchAt(ctx, edge.sinkLine, 0.88, `file read → ${edge.sink}`));
        }
      }
      // Also check inline: exec(open(...).read())
      for (const s of a.statements) {
        for (const c of s.calls) {
          if (c.calleeName !== "eval" && c.calleeName !== "exec" && !CODE_SINKS.has(c.callee)) continue;
          const argCalls = c.args.flatMap((arg) => arg.calls);
          const hasOpen = argCalls.some((ac) => ac.calleeName === "open");
          const hasRead = argCalls.some((ac) => ac.calleeName === "read");
          if (hasOpen && hasRead) {
            out.push(matchAt(ctx, c.line, 0.9, `inline file read → ${c.calleeName}`));
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-015: Decode-then-eval pattern (bytes.decode() → eval)
const ast015: DetectionRule = {
  id: "PY-AST-015",
  title: "Decode-then-eval pattern (bytes.decode → eval/exec)",
  severity: "critical",
  category: "obfuscation",
  description:
    "A bytes object is decoded (.decode()) and the resulting string is passed to eval or exec. This is used to hide payloads as byte literals (which look like b'...' in the source) and decode them at runtime before execution — the plaintext code never appears as a string literal in the file.",
  remediation:
    "Remove the decode + exec pattern. If the bytes are legitimate data, process them with a safe parser. Never exec decoded runtime data.",
  references: ["CWE-95", "CWE-912", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const edge of a.dataFlow) {
        if (!edgeIsCodeSink(edge)) continue;
        const hasDecode = edge.assignment.valueCalls.some(
          (c) => c.calleeName === "decode" || c.callee.endsWith(".decode")
        );
        if (hasDecode) {
          out.push(matchAt(ctx, edge.sinkLine, 0.85, `decode → ${edge.sink}`));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-016: Decompress-then-exec pattern (zlib/gzip → marshal → exec)
const ast016: DetectionRule = {
  id: "PY-AST-016",
  title: "Decompress-then-exec pattern (zlib/gzip → marshal → exec)",
  severity: "critical",
  category: "obfuscation",
  description:
    "A compressed blob (zlib, gzip) is decompressed and the result is loaded via marshal.loads and exec'd. This triple-stage pipeline (compress → marshal → exec) is the signature of a polymorphic Python dropper: the malicious bytecode is compressed, serialized as a code object, and only reassembled in memory at runtime.",
  remediation:
    "Remove the decompress + marshal + exec pipeline. This pattern has no legitimate use in application code. If you are loading compressed bytecode caches, verify the source integrity with a signature.",
  references: ["CWE-95", "CWE-502", "CWE-912", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const decompressNames = new Set(["decompress", "zlib.decompress", "gzip.decompress"]);
      const marshalNames = new Set(["marshal.loads", "marshal.load", "loads"]);
      // Check data flow: var = marshal.loads(zlib.decompress(...)) → exec(var)
      for (const edge of a.dataFlow) {
        if (!edgeIsCodeSink(edge)) continue;
        const hasMarshal = edge.assignment.valueCalls.some((c) =>
          marshalNames.has(c.callee) || c.calleeName === "loads" ||
          c.callee.includes("marshal")
        );
        const hasDecompress = edge.assignment.valueCalls.some((c) =>
          decompressNames.has(c.callee) || c.calleeName === "decompress"
        );
        if (hasMarshal || (hasDecompress && edgeIsCodeSink(edge))) {
          out.push(matchAt(ctx, edge.sinkLine, 0.9, `decompress → marshal → ${edge.sink}`));
        }
      }
      // Also check: statements that contain both decompress and marshal and exec.
      for (const s of a.statements) {
        const allCalls = [...s.calls, ...s.calls.flatMap((c) => c.args.flatMap((a) => a.calls))];
        const hasDecompress = allCalls.some((c) =>
          decompressNames.has(c.callee) || c.calleeName === "decompress"
        );
        const hasMarshal = allCalls.some((c) =>
          marshalNames.has(c.callee) || c.callee.includes("marshal")
        );
        const hasExec = allCalls.some((c) =>
          c.calleeName === "exec" || c.calleeName === "eval" || CODE_SINKS.has(c.callee)
        );
        if (hasDecompress && hasMarshal && hasExec) {
          out.push(matchAt(ctx, s.startLine, 0.92, "decompress + marshal + exec"));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-017: Two-step command build (parts = [...] → " ".join(parts) → system)
const ast017: DetectionRule = {
  id: "PY-AST-017",
  title: "Two-step command build (list → join → shell execution)",
  severity: "high",
  category: "command-execution",
  description:
    "A list of command fragments is assigned to a variable, joined into a string, and the result is passed to a shell execution sink. This three-stage pipeline (list → join → system) is an obfuscation technique that splits the command construction across multiple lines, making it harder to see the complete command in any single line.",
  remediation:
    "Pass the list directly to subprocess.run(parts, shell=False). Avoid joining command fragments into a shell string.",
  references: ["CWE-78", "CWE-913", "OWASP A03:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      // Build a map: varName -> assignment (for list vars).
      const listVars = new Map<string, LogicalStatement>();
      for (const s of a.statements) {
        for (const assign of s.assignments) {
          if (assign.targetVar && assign.isList) {
            listVars.set(assign.targetVar, s);
          }
        }
      }
      // Find data flow edges where the assignment involves .join of a list var.
      for (const edge of a.dataFlow) {
        if (!edgeIsShellSink(edge)) continue;
        const joinCall = edge.assignment.valueCalls.find(
          (c) => c.calleeName === "join" || c.callee.endsWith(".join")
        );
        if (!joinCall) continue;
        // Check if the join's argument is a variable that was a list.
        const joinArgVar = joinCall.args.find((arg) => arg.isVariable)?.varName;
        if (joinArgVar && listVars.has(joinArgVar)) {
          out.push(matchAt(ctx, edge.sinkLine, 0.85, `list → join → ${edge.sink}`));
        } else {
          // Even without the list var, join → shell is suspicious.
          out.push(matchAt(ctx, edge.sinkLine, 0.72, `join → ${edge.sink}`));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// =========================================================================
// Decorator / metaclass abuse
// =========================================================================

// PY-AST-018: Decorator wrapping eval/exec/system call
const ast018: DetectionRule = {
  id: "PY-AST-018",
  title: "Decorator wrapping a function that executes eval/exec/system",
  severity: "high",
  category: "suspicious-pattern",
  description:
    "A decorator is applied to a function whose body calls eval, exec, or os.system. While decorators are a normal Python feature, combining them with code execution sinks is suspicious — it can be used to wrap a payload in a seemingly benign interface (e.g. @app.route, @property, @cached) so the execution is triggered only when the decorated function is called.",
  remediation:
    "Review the decorated function. Remove the eval/exec/system call. If the decorator is meant to intercept calls, log or validate arguments instead of executing arbitrary code.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const dangerSet = new Set([...CODE_SINKS, ...SHELL_SINKS, "eval", "exec", "system", "popen"]);
      for (const dec of a.decorators) {
        if (!dec.target) continue;
        if (bodyHasCall(dec.target, dangerSet)) {
          out.push(matchAt(ctx, dec.line, 0.75, `@${dec.name}`));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-019: Metaclass __init_subclass__ with exec
const ast019: DetectionRule = {
  id: "PY-AST-019",
  title: "__init_subclass__ method containing exec/eval",
  severity: "critical",
  category: "code-execution",
  description:
    "The __init_subclass__ hook runs automatically when a class is subclassed. Putting exec or eval inside it means the payload executes silently whenever any subclass is defined — a stealthy persistence mechanism that triggers without an explicit call. This is used in advanced backdoors to run code at import time without any visible function call.",
  remediation:
    "Remove eval/exec from __init_subclass__. If you need subclass registration, store metadata only — do not execute code.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const codeSet = new Set([...CODE_SINKS, "eval", "exec", "compile"]);
      for (const s of a.statements) {
        if (s.keyword !== "def") continue;
        if (s.tokens.length >= 2 && s.tokens[1].type === "NAME" && s.tokens[1].value === "__init_subclass__") {
          if (bodyHasCall(s, codeSet)) {
            out.push(matchAt(ctx, s.startLine, 0.88, "__init_subclass__ + exec"));
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-020: Class property/getter that executes code
const ast020: DetectionRule = {
  id: "PY-AST-020",
  title: "@property method that executes eval/exec/system",
  severity: "high",
  category: "code-execution",
  description:
    "A @property-decorated method contains a call to eval, exec, or os.system. Properties are accessed as attributes (obj.name), so the code execution is hidden behind what looks like a simple attribute access. This is an obfuscation technique — the malicious call is triggered by reading an attribute, not by calling a function.",
  remediation:
    "Remove the code execution from the property. Properties should compute and return values, not execute arbitrary code.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const dangerSet = new Set([...CODE_SINKS, ...SHELL_SINKS, "eval", "exec", "system", "popen"]);
      for (const dec of a.decorators) {
        if (dec.name !== "property" && !dec.name.startsWith("property")) continue;
        if (!dec.target) continue;
        if (bodyHasCall(dec.target, dangerSet)) {
          out.push(matchAt(ctx, dec.line, 0.82, "@property + code exec"));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// =========================================================================
// Lambda / functional obfuscation
// =========================================================================

// PY-AST-021: Lambda one-liner wrapping eval/exec
const ast021: DetectionRule = {
  id: "PY-AST-021",
  title: "Lambda wrapping eval/exec/system",
  severity: "high",
  category: "obfuscation",
  description:
    "A lambda expression wraps a call to eval, exec, or os.system. Lambdas are anonymous and often appear inline, making them easy to overlook in code review. Wrapping a dangerous call in a lambda is an obfuscation technique — the lambda can be passed around as a value, stored in a data structure, or called later, hiding the true call site.",
  remediation:
    "Replace the lambda with a named function that clearly documents its behavior. Remove the eval/exec/system call.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const dangerSet = new Set([...CODE_SINKS, ...SHELL_SINKS, "eval", "exec", "system", "popen"]);
      for (const s of a.statements) {
        // Check if the statement contains a lambda keyword.
        const hasLambda = s.tokens.some(
          (t) => t.type === "NAME" && t.value === "lambda"
        );
        if (!hasLambda) continue;
        if (s.calls.some((c) => callIs(c, dangerSet))) {
          out.push(matchAt(ctx, s.startLine, 0.8, "lambda + danger call"));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-022: map/filter with eval as the function
const ast022: DetectionRule = {
  id: "PY-AST-022",
  title: "map/filter invoked with eval/exec as the callable",
  severity: "critical",
  category: "code-execution",
  description:
    "map(eval, data) or filter(exec, data) applies a code-execution primitive to every element of an iterable. This is a functional obfuscation that turns a single eval call into a bulk execution — each element of the iterable is passed to eval/exec, potentially executing many payloads from a list of encoded strings.",
  remediation:
    "Replace map(eval, ...) with an explicit loop that processes data safely. Never use eval or exec as the function argument to map/filter/reduce.",
  references: ["CWE-95", "CWE-913", "OWASP A03:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const higherOrder = new Set(["map", "filter", "reduce", "starmap", "apply"]);
      const codeSet = new Set([...CODE_SINKS, "eval", "exec", "compile"]);
      for (const s of a.statements) {
        for (const c of s.calls) {
          if (!callIs(c, higherOrder)) continue;
          // Check if any argument is a reference to eval/exec/compile.
          for (const arg of c.args) {
            if (argReferencesDanger(arg, codeSet)) {
              out.push(matchAt(ctx, c.line, 0.9, `${c.calleeName}(${arg.text}, ...)`));
              break;
            }
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-023: Lambda assigned then immediately called (IIFE pattern)
const ast023: DetectionRule = {
  id: "PY-AST-023",
  title: "Immediately-invoked lambda expression (IIFE)",
  severity: "medium",
  category: "suspicious-pattern",
  description:
    "A lambda is defined and immediately called in the same expression: (lambda x: ...)(arg). This JavaScript-style IIFE pattern in Python is unusual and often used to create a one-off scope for obfuscated code — the lambda body can contain arbitrary logic (including eval/exec) that is executed immediately without being bound to a name.",
  remediation:
    "Replace the IIFE with a direct expression or a named function. If the lambda is used for its closure semantics, document why.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const s of a.statements) {
        for (const c of s.calls) {
          // The callee contains a bracket that includes "lambda".
          if (c.calleeParts.some((p) => p.includes("lambda"))) {
            out.push(matchAt(ctx, c.line, 0.7, "IIFE lambda"));
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-024: Functional composition building dangerous call
const ast024: DetectionRule = {
  id: "PY-AST-024",
  title: "Functional composition (reduce/partial/compose) referencing eval/exec",
  severity: "high",
  category: "obfuscation",
  description:
    "A functional composition utility (functools.reduce, functools.partial, compose) is used with eval/exec as part of the pipeline. This builds a callable at runtime that, when invoked, triggers code execution — the indirection through functional combinators makes it very hard to see the danger in a static review.",
  remediation:
    "Avoid passing eval/exec to functional combinators. If you need a reusable callable, define a named function with clear intent.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const composeNames = new Set([
        "reduce", "functools.reduce", "partial", "functools.partial",
        "compose", "pipe", "chain",
      ]);
      const codeSet = new Set([...CODE_SINKS, "eval", "exec", "compile"]);
      for (const s of a.statements) {
        for (const c of s.calls) {
          if (!callIs(c, composeNames)) continue;
          for (const arg of c.args) {
            if (argReferencesDanger(arg, codeSet)) {
              out.push(matchAt(ctx, c.line, 0.78, `${c.calleeName} + ${arg.text}`));
              break;
            }
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// =========================================================================
// Conditional / triggered payloads
// =========================================================================

// PY-AST-025: if-condition that triggers eval/exec (env-triggered payload)
const ast025: DetectionRule = {
  id: "PY-AST-025",
  title: "Conditional block (if) that triggers eval/exec/system",
  severity: "high",
  category: "suspicious-pattern",
  description:
    "An if-statement's body contains a call to eval, exec, or os.system. This is the signature of an environment-triggered backdoor: the payload only fires when a specific condition is met (e.g. a magic environment variable is set, a specific date, a debug flag). The conditional gate is designed to keep the backdoor dormant during normal testing and only activate in the target environment.",
  remediation:
    "Review the condition and the payload. Remove the eval/exec/system call. If the condition is a feature flag, use it to toggle safe behavior, not to execute arbitrary code.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const dangerSet = new Set([...CODE_SINKS, ...SHELL_SINKS, "eval", "exec", "system", "popen"]);
      for (const s of a.statements) {
        if (s.keyword !== "if" && s.keyword !== "elif") continue;
        if (bodyHasCall(s, dangerSet)) {
          // Only flag if the condition looks env/time-triggered.
          const condText = s.text;
          const looksTriggered =
            /os\.environ|getenv|environ\.get|strftime|datetime|time\.|date\(|argc|argv|random\.|getpass|hostname|platform\.|sys\.argv/.test(condText) ||
            condText.includes("__") || condText.includes("DEBUG") || condText.includes("SECRET");
          const conf = looksTriggered ? 0.82 : 0.65;
          out.push(matchAt(ctx, s.startLine, conf, "if-block + code exec"));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-026: try/except where except block executes payload
const ast026: DetectionRule = {
  id: "PY-AST-026",
  title: "except block that executes eval/exec/system",
  severity: "high",
  category: "suspicious-pattern",
  description:
    "An except block contains a call to eval, exec, or os.system. This is a stealth technique: the payload is hidden in an error handler and only fires when the try block raises an exception. Attackers use this to trigger backdoors via deliberate errors, or to activate fallback payloads when the primary mechanism fails.",
  remediation:
    "Review the except block. Remove the eval/exec/system call. Error handlers should log and recover, not execute arbitrary code.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const dangerSet = new Set([...CODE_SINKS, ...SHELL_SINKS, "eval", "exec", "system", "popen"]);
      for (const s of a.statements) {
        if (s.keyword !== "except") continue;
        if (bodyHasCall(s, dangerSet)) {
          out.push(matchAt(ctx, s.startLine, 0.8, "except-block + code exec"));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-027: __init__ or __enter__ that runs payload
const ast027: DetectionRule = {
  id: "PY-AST-027",
  title: "__init__ / __enter__ method that runs eval/exec/system",
  severity: "high",
  category: "persistence",
  description:
    "A class constructor (__init__) or context manager entry (__enter__) contains a call to eval, exec, or os.system. This means the payload executes automatically when an object is created or a with-block is entered — a stealthy way to trigger backdoor code without an explicit function call. The malicious behavior is hidden behind normal object-oriented patterns.",
  remediation:
    "Remove the eval/exec/system call from the constructor. Constructors should initialize state, not execute arbitrary code.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const dangerSet = new Set([...CODE_SINKS, ...SHELL_SINKS, "eval", "exec", "system", "popen"]);
      for (const s of a.statements) {
        if (s.keyword !== "def") continue;
        if (s.tokens.length < 2 || s.tokens[1].type !== "NAME") continue;
        const name = s.tokens[1].value;
        if (name === "__init__" || name === "__enter__" || name === "__new__" || name === "__post_init__") {
          if (bodyHasCall(s, dangerSet)) {
            out.push(matchAt(ctx, s.startLine, 0.8, `${name} + code exec`));
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-028: Signal handler registration with malicious callback
const ast028: DetectionRule = {
  id: "PY-AST-028",
  title: "Signal handler registered with a callback that executes code",
  severity: "high",
  category: "persistence",
  description:
    "signal.signal() registers a callback that will be invoked when a specific signal is received. If the callback function's body contains eval/exec/os.system, the payload is triggered by an external signal (SIGTERM, SIGUSR1, etc.) — a stealthy persistence mechanism that lies dormant until the attacker sends the trigger signal to the process.",
  remediation:
    "Review the signal handler callback. Remove eval/exec/system from it. Signal handlers should be minimal — set a flag and return, do not execute arbitrary code.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      const dangerSet = new Set([...CODE_SINKS, ...SHELL_SINKS, "eval", "exec", "system", "popen"]);
      for (const s of a.statements) {
        for (const c of s.calls) {
          if (c.callee !== "signal.signal" && !(c.calleeName === "signal" && c.calleeParts.length >= 2)) continue;
          // signal.signal(signum, handler) — handler is the second arg.
          if (c.args.length < 2) continue;
          const handlerArg = c.args[1];
          if (!handlerArg.varName) continue;
          // Find the function definition for the handler.
          const funcDef = findDef(a.statements, handlerArg.varName);
          if (funcDef && bodyHasCall(funcDef, dangerSet)) {
            out.push(matchAt(ctx, c.line, 0.82, `signal.signal(…, ${handlerArg.varName})`));
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// =========================================================================
// String / encoding tricks regex misses
// =========================================================================

// PY-AST-029: chr() array built into string then exec'd
const ast029: DetectionRule = {
  id: "PY-AST-029",
  title: "chr() array assembled into a string then exec'd",
  severity: "critical",
  category: "obfuscation",
  description:
    "A string is built from chr() calls (e.g. \"\".join([chr(105), chr(109), ...]) or chr(65)+chr(66)+...) and the result is passed to exec or eval. This is a classic obfuscation: each character of the payload is encoded as its ASCII code, so the plaintext never appears in the source — regex scanners looking for the payload string find nothing.",
  remediation:
    "Remove the chr-assembly + exec pattern. If the string is legitimate, write it as a plain string literal. Never exec chr-assembled code.",
  references: ["CWE-95", "CWE-912", "CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const edge of a.dataFlow) {
        if (!edgeIsCodeSink(edge)) continue;
        const hasChr = edge.assignment.valueCalls.some(
          (c) => c.calleeName === "chr" || c.callee === "chr"
        );
        const hasJoin = edge.assignment.valueCalls.some(
          (c) => c.calleeName === "join" || c.callee.endsWith(".join")
        );
        // Also check: the value text mentions chr() multiple times.
        const chrCount = (edge.assignment.valueText.match(/chr\s*\(/g) ?? []).length;
        if (hasChr || (hasJoin && chrCount >= 2) || chrCount >= 3) {
          out.push(matchAt(ctx, edge.sinkLine, 0.9, `chr() → ${edge.sink}`));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-030: bytes.fromhex() decoded then exec'd
const ast030: DetectionRule = {
  id: "PY-AST-030",
  title: "bytes.fromhex() payload decoded then exec'd",
  severity: "critical",
  category: "obfuscation",
  description:
    "A hex-encoded byte string is converted via bytes.fromhex() and the result is passed to exec or eval. Hex encoding hides the payload from string-based scanners — the source contains only hex digits (0-9a-f), which look like innocent numeric data. This is used in real-world droppers to embed compiled bytecode or source code as a hex blob.",
  remediation:
    "Remove the fromhex + exec pattern. If the bytes are legitimate data, process them with a safe parser. Never exec hex-decoded runtime data.",
  references: ["CWE-95", "CWE-912", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const edge of a.dataFlow) {
        if (!edgeIsCodeSink(edge)) continue;
        const hasFromhex = edge.assignment.valueCalls.some(
          (c) =>
            c.calleeName === "fromhex" ||
            c.callee === "bytes.fromhex" ||
            c.callee.endsWith(".fromhex") ||
            c.callee.includes("fromhex")
        );
        if (hasFromhex) {
          out.push(matchAt(ctx, edge.sinkLine, 0.9, `fromhex → ${edge.sink}`));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-031: code object construction (compile + exec)
const ast031: DetectionRule = {
  id: "PY-AST-031",
  title: "compile() result passed to exec/eval (code object pipeline)",
  severity: "critical",
  category: "code-execution",
  description:
    "A string is compiled to a code object via compile() and the result is passed to exec or eval. This two-step pattern (compile then exec) is used to separate the compilation from the execution — the code object can be stored, transmitted, or transformed before execution, making the data flow harder to trace. It is a hallmark of dynamic code-loading backdoors.",
  remediation:
    "Remove the compile + exec pattern. If you need to execute trusted dynamic code, import it as a module. Never exec compile() output from untrusted sources.",
  references: ["CWE-95", "CWE-913", "OWASP A03:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const edge of a.dataFlow) {
        if (!edgeIsCodeSink(edge)) continue;
        const hasCompile = edge.assignment.valueCalls.some(
          (c) => c.calleeName === "compile" || c.callee === "compile"
        );
        if (hasCompile) {
          out.push(matchAt(ctx, edge.sinkLine, 0.88, `compile → ${edge.sink}`));
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-032: importlib.import_module with dynamic name
const ast032: DetectionRule = {
  id: "PY-AST-032",
  title: "importlib.import_module with a dynamic/variable module name",
  severity: "medium",
  category: "suspicious-pattern",
  description:
    "importlib.import_module is called with a variable (not a string literal) as the module name. Dynamic imports with runtime-computed names are used in backdoors to load modules from attacker-controlled strings — the module name may be decoded from obfuscated data, fetched from a C2 server, or constructed from environment variables. This evades static import analysis.",
  remediation:
    "Use static import statements for known modules. If dynamic loading is required, validate the module name against a strict whitelist before importing.",
  references: ["CWE-913", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const s of a.statements) {
        for (const c of s.calls) {
          if (
            c.callee !== "importlib.import_module" &&
            c.calleeName !== "import_module"
          ) continue;
          if (c.args.length < 1) continue;
          const arg = c.args[0];
          // Flag if the arg is a variable (not a string literal).
          if (arg.isVariable && !arg.isStringLiteral) {
            out.push(matchAt(ctx, c.line, 0.7, `import_module(${arg.text})`));
          } else if (arg.isFString || arg.isConcatenation) {
            out.push(matchAt(ctx, c.line, 0.75, `import_module(dynamic: ${arg.text})`));
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// PY-AST-033: globals()/locals() manipulation to invoke builtins
const ast033: DetectionRule = {
  id: "PY-AST-033",
  title: "globals()/locals() lookup to invoke a builtin by name",
  severity: "critical",
  category: "code-execution",
  description:
    "globals()['eval'] or globals().get('exec') retrieves a builtin function by name from the global namespace, then invokes it. This is an indirect execution technique that defeats regex — the string 'eval' is a dictionary key, not a function call. It is used in obfuscated backdoors to dynamically resolve and call dangerous functions without writing their names as call expressions.",
  remediation:
    "Remove the globals()/locals() lookup. Call functions directly by name. If you need dynamic dispatch, use a whitelisted dictionary of safe callables.",
  references: ["CWE-913", "CWE-95", "OWASP A08:2021"],
  match: (ctx) => {
    const out: RawMatch[] = [];
    try {
      const a = getAnalysis(ctx);
      for (const s of a.statements) {
        for (const c of s.calls) {
          // Check if the callee chain involves globals() or locals().
          const involvesGlobals =
            c.calleeParts.some((p) => p === "globals" || p === "locals") ||
            c.callee.includes("globals") || c.callee.includes("locals");
          if (!involvesGlobals) continue;
          // Check if the call has a subscript (globals()["eval"]).
          if (!c.hasSubscript && !c.hasLiteralCallee) {
            // Also check if globals().get("eval")(...) — the .get call.
            const hasGet = c.calleeParts.includes("get");
            if (!hasGet) continue;
          }
          // Check if any arg or the callee text references a danger name.
          const argText = c.args.map((arg) => arg.text).join(" ");
          const calleeText = c.callee;
          const referencesDanger =
            argText.includes("eval") || argText.includes("exec") ||
            argText.includes("compile") || argText.includes("__import__") ||
            calleeText.includes("eval") || calleeText.includes("exec");
          if (referencesDanger) {
            out.push(matchAt(ctx, c.line, 0.88, c.callee));
          } else {
            // Even without an explicit danger name, globals()[var](...) is suspicious.
            out.push(matchAt(ctx, c.line, 0.65, c.callee));
          }
        }
      }
    } catch {
      /* defensive */
    }
    return out;
  },
};

// =========================================================================
// Export
// =========================================================================

export const RULES_AST: DetectionRule[] = [
  ast001,
  ast002,
  ast003,
  ast004,
  ast005,
  ast006,
  ast007,
  ast008,
  ast009,
  ast010,
  ast011,
  ast012,
  ast013,
  ast014,
  ast015,
  ast016,
  ast017,
  ast018,
  ast019,
  ast020,
  ast021,
  ast022,
  ast023,
  ast024,
  ast025,
  ast026,
  ast027,
  ast028,
  ast029,
  ast030,
  ast031,
  ast032,
  ast033,
];

export const AST_RULE_COUNT = RULES_AST.length;
