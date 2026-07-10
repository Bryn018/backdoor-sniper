/**
 * Lightweight Python syntax highlighter.
 *
 * Tokenizes a Python source string into HTML-safe spans with color classes
 * that map to the project's emerald-accent dark theme. Intentionally regex
 * based (no full parser) — sufficient for code-review visualization.
 *
 * The output is a string of HTML with <span> tags. Callers must render it
 * via dangerouslySetInnerHTML inside a <code> element.
 */

export type TokenType =
  | "comment"
  | "string"
  | "keyword"
  | "builtin"
  | "number"
  | "decorator"
  | "operator"
  | "function"
  | "self"
  | "plain";

const KEYWORDS = new Set([
  "False", "None", "True", "and", "as", "assert", "async", "await",
  "break", "class", "continue", "def", "del", "elif", "else", "except",
  "finally", "for", "from", "global", "if", "import", "in", "is",
  "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
  "while", "with", "yield", "match", "case",
]);

const BUILTINS = new Set([
  "abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes",
  "callable", "chr", "classmethod", "compile", "complex", "delattr",
  "dict", "dir", "divmod", "enumerate", "eval", "exec", "filter",
  "float", "format", "frozenset", "getattr", "globals", "hasattr",
  "hash", "help", "hex", "id", "input", "int", "isinstance", "issubclass",
  "iter", "len", "list", "locals", "map", "max", "memoryview", "min",
  "next", "object", "oct", "open", "ord", "pow", "print", "property",
  "range", "repr", "reversed", "round", "set", "setattr", "slice",
  "sorted", "staticmethod", "str", "sum", "super", "tuple", "type",
  "vars", "zip", "__import__",
]);

const CONSTANT_LIKE = new Set([
  "self", "cls", "__name__", "__file__", "__doc__", "__init__",
  "__main__", "__package__", "__class__", "__dict__", "NotImplemented",
  "Ellipsis", "__build_class__",
]);

/** Escape HTML special chars. */
function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/**
 * Tokenize a single line of Python code (no triple-string awareness across
 * lines — best-effort, designed for visualization, not for compilation).
 */
export function highlightPythonLine(line: string): string {
  if (!line) return "";

  // Quick path: comment-only or empty
  const trimmed = line.trimStart();
  if (!trimmed) return escapeHtml(line);
  if (trimmed.startsWith("#")) {
    return `<span class="tok-comment">${escapeHtml(line)}</span>`;
  }

  let out = "";
  let i = 0;
  const len = line.length;

  while (i < len) {
    const c = line[i];
    const next = line[i + 1] ?? "";

    // Line comment (#...) — only if not inside a string (we handle strings below)
    if (c === "#") {
      out += `<span class="tok-comment">${escapeHtml(line.slice(i))}</span>`;
      break;
    }

    // Strings: ', ", ''' or """ (single-line only — multi-line strings fall back to plain)
    if (c === '"' || c === "'") {
      // Triple-quoted?
      const triple = line.slice(i, i + 3);
      if (triple === '"""' || triple === "'''") {
        // find closing triple on same line
        const closeIdx = line.indexOf(triple, i + 3);
        if (closeIdx === -1) {
          // unterminated on this line — paint rest as string
          out += `<span class="tok-string">${escapeHtml(line.slice(i))}</span>`;
          break;
        }
        const end = closeIdx + 3;
        out += `<span class="tok-string">${escapeHtml(line.slice(i, end))}</span>`;
        i = end;
        continue;
      }

      // Single-quoted string — find matching unescaped close
      let j = i + 1;
      while (j < len) {
        if (line[j] === "\\") {
          j += 2;
          continue;
        }
        if (line[j] === c) {
          j++;
          break;
        }
        j++;
      }
      out += `<span class="tok-string">${escapeHtml(line.slice(i, j))}</span>`;
      i = j;
      continue;
    }

    // f-strings / r-strings / b-strings: f"...", r'...', b"..."
    if ((c === "f" || c === "r" || c === "b" || c === "F" || c === "R" || c === "B") &&
        (next === '"' || next === "'")) {
      const quote = next;
      let j = i + 2;
      while (j < len) {
        if (line[j] === "\\") {
          j += 2;
          continue;
        }
        if (line[j] === quote) {
          j++;
          break;
        }
        j++;
      }
      out += `<span class="tok-string">${escapeHtml(line.slice(i, j))}</span>`;
      i = j;
      continue;
    }

    // Numbers (int, float, hex, bin, oct, complex)
    if (/[0-9]/.test(c) || (c === "." && /[0-9]/.test(next))) {
      let j = i;
      while (j < len && /[0-9a-fA-FxXoObB._eEjJ+\-]/.test(line[j])) {
        // careful: don't eat trailing +/- that is an operator
        if ((line[j] === "+" || line[j] === "-") && j > i && !/[eE]/.test(line[j - 1])) {
          break;
        }
        j++;
      }
      out += `<span class="tok-number">${escapeHtml(line.slice(i, j))}</span>`;
      i = j;
      continue;
    }

    // Decorator: @name
    if (c === "@") {
      let j = i + 1;
      while (j < len && /[A-Za-z0-9_.]/.test(line[j])) j++;
      out += `<span class="tok-decorator">${escapeHtml(line.slice(i, j))}</span>`;
      i = j;
      continue;
    }

    // Identifier / keyword / builtin / function call
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < len && /[A-Za-z0-9_]/.test(line[j])) j++;
      const word = line.slice(i, j);

      // Look ahead for `(` → function call
      let k = j;
      while (k < len && line[k] === " ") k++;
      const isCall = line[k] === "(";

      if (KEYWORDS.has(word)) {
        out += `<span class="tok-keyword">${escapeHtml(word)}</span>`;
      } else if (CONSTANT_LIKE.has(word)) {
        out += `<span class="tok-self">${escapeHtml(word)}</span>`;
      } else if (BUILTINS.has(word)) {
        out += `<span class="tok-builtin">${escapeHtml(word)}</span>`;
      } else if (isCall) {
        out += `<span class="tok-function">${escapeHtml(word)}</span>`;
      } else {
        out += escapeHtml(word);
      }
      i = j;
      continue;
    }

    // Operators
    if (/[+\-*/%=<>!&|^~]/.test(c)) {
      let j = i;
      while (j < len && /[+\-*/%=<>!&|^~]/.test(line[j])) j++;
      out += `<span class="tok-operator">${escapeHtml(line.slice(i, j))}</span>`;
      i = j;
      continue;
    }

    // Default: pass through escaped char
    out += escapeHtml(c);
    i++;
  }

  return out;
}

/**
 * Highlight an entire Python source string (multi-line).
 * Returns HTML with <span> tags. Newlines are preserved.
 */
export function highlightPython(source: string): string {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  return lines.map(highlightPythonLine).join("\n");
}
