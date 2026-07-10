"use client";

import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Plus,
  X,
  Search,
  Trash2,
  Edit2,
  Save,
  Beaker,
  AlertCircle,
  CheckCircle2,
  Wand2,
  FileCode2,
  Download,
  Upload,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SEVERITY_BADGE, CATEGORY_LABEL } from "@/lib/severity";
import type { Severity, Category } from "@/lib/detector/types";
import type { CustomRuleSpec } from "@/lib/detector/scanner";
import { toast } from "sonner";

export interface CustomRule extends CustomRuleSpec {
  /** Local-only fields */
  enabled: boolean;
  createdAt: number;
}

interface CustomRuleEditorProps {
  open: boolean;
  onClose: () => void;
  rules: CustomRule[];
  onChange: (rules: CustomRule[]) => void;
  /** Code currently in the editor — used to test the rule live. */
  testCode: string;
}

const STORAGE_KEY = "backdoorsniper.customRules.v1";

/** Load custom rules from localStorage (client-side only). */
export function loadCustomRules(): CustomRule[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (r) => r && typeof r.id === "string" && typeof r.pattern === "string"
    );
  } catch {
    return [];
  }
}

/** Persist custom rules to localStorage. */
export function saveCustomRules(rules: CustomRule[]) {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(rules));
  } catch {
    /* ignore quota errors */
  }
}

const SAMPLE_TEMPLATES: Array<{
  label: string;
  spec: CustomRuleSpec;
}> = [
  {
    label: "Detect `requests` calls",
    spec: {
      id: "USER-REQ-001",
      title: "Outbound HTTP request via requests",
      severity: "low",
      category: "network",
      pattern: "requests\\.(get|post|put|delete|patch|head)\\s*\\(",
      description: "Flags any outbound HTTP call made via the requests library.",
      remediation:
        "Verify the destination URL is allowlisted. Avoid fetching arbitrary user-supplied URLs.",
      references: "CWE-918",
    },
  },
  {
    label: "Detect `print` of secrets",
    spec: {
      id: "USER-PRINT-001",
      title: "Print statement referencing a secret-named variable",
      severity: "medium",
      category: "credential-theft",
      pattern: "print\\s*\\(.*\\b(token|password|secret|api_?key)\\b",
      description:
        "Prints of variables whose name suggests a secret — may leak credentials to stdout/logs.",
      remediation: "Never print credentials. Use redaction or remove the print statement.",
      references: "CWE-532",
    },
  },
  {
    label: "Detect `subprocess.run` with shell=True",
    spec: {
      id: "USER-SHELL-001",
      title: "subprocess call with shell=True",
      severity: "high",
      category: "command-execution",
      pattern: "subprocess\\.(run|call|Popen|check_output|check_call).*shell\\s*=\\s*True",
      description:
        "shell=True allows command injection if any part of the command is user-controlled.",
      remediation: "Pass args as a list with shell=False (default).",
      references: "CWE-78",
    },
  },
];

export function CustomRuleEditor({
  open,
  onClose,
  rules,
  onChange,
  testCode,
}: CustomRuleEditorProps) {
  const [editing, setEditing] = useState<CustomRule | null>(null);
  const [search, setSearch] = useState("");
  const importInputRef = useRef<HTMLInputElement>(null);

  // Live-test the regex against the current editor code (computed inline
  // rather than via setState-in-effect — gives us a memoized result that
  // updates synchronously as the user types).
  const testResult = useMemo(() => {
    if (!editing) return { matches: [] as number[], error: null as string | null };
    const pattern = editing.pattern;
    if (!pattern.trim()) return { matches: [], error: null };
    try {
      const regex = new RegExp(pattern, "i");
      const lines = testCode.replace(/\r\n/g, "\n").split("\n");
      const matches: number[] = [];
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i].trim())) matches.push(i + 1);
        regex.lastIndex = 0;
      }
      return { matches: matches.slice(0, 50), error: null };
    } catch (e) {
      return {
        matches: [] as number[],
        error: e instanceof Error ? e.message : String(e),
      };
    }
  }, [editing, testCode]);

  const testMatches = testResult.matches;
  const regexError = testResult.error;

  // ESC to close
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  const startNew = useCallback(() => {
    setEditing({
      id: `USER-${Date.now().toString(36).toUpperCase().slice(-6)}`,
      title: "",
      severity: "medium",
      category: "suspicious-pattern",
      pattern: "",
      description: "",
      remediation: "",
      references: "",
      enabled: true,
      createdAt: Date.now(),
    });
  }, []);

  const startEdit = useCallback((rule: CustomRule) => {
    setEditing({ ...rule });
  }, []);

  const cancelEdit = useCallback(() => {
    setEditing(null);
  }, []);

  const saveEdit = useCallback(() => {
    if (!editing) return;
    if (!editing.id.trim() || !editing.title.trim() || !editing.pattern.trim()) {
      toast.error("Rule id, title, and pattern are required");
      return;
    }
    if (!/^[\w-]+$/.test(editing.id)) {
      toast.error("Rule id must be alphanumeric/underscore/hyphen");
      return;
    }
    // Validate regex
    try {
      // Assigning to a variable to satisfy linters; the regex is intentionally
      // constructed only to validate that the pattern compiles.
      const _validateRegex = new RegExp(editing.pattern, "i");
      void _validateRegex;
    } catch (e) {
      toast.error(
        `Invalid regex: ${e instanceof Error ? e.message : String(e)}`
      );
      return;
    }
    const idx = rules.findIndex((r) => r.id === editing.id);
    const next: CustomRule[] =
      idx === -1
        ? [...rules, editing]
        : rules.map((r, i) => (i === idx ? editing : r));
    onChange(next);
    saveCustomRules(next);
    toast.success(
      idx === -1 ? "Custom rule created" : "Custom rule updated",
      { description: `${editing.id} · ${editing.title}` }
    );
    cancelEdit();
  }, [editing, rules, onChange, cancelEdit]);

  const deleteRule = useCallback(
    (id: string) => {
      const next = rules.filter((r) => r.id !== id);
      onChange(next);
      saveCustomRules(next);
      toast.success("Custom rule deleted", { description: id });
    },
    [rules, onChange]
  );

  const toggleEnabled = useCallback(
    (id: string) => {
      const next = rules.map((r) =>
        r.id === id ? { ...r, enabled: !r.enabled } : r
      );
      onChange(next);
      saveCustomRules(next);
    },
    [rules, onChange]
  );

  const loadTemplate = useCallback(
    (spec: CustomRuleSpec) => {
      // Ensure unique id by appending timestamp suffix
      const suffix = Date.now().toString(36).toUpperCase().slice(-4);
      setEditing({
        ...spec,
        id: `${spec.id}-${suffix}`,
        enabled: true,
        createdAt: Date.now(),
      });
    },
    []
  );

  /** Export all custom rules as a downloadable JSON file. */
  const exportRulesJson = useCallback(() => {
    if (rules.length === 0) {
      toast.info("No custom rules to export");
      return;
    }
    const payload = {
      format: "backdoorsniper-custom-rules",
      version: 1,
      exportedAt: new Date().toISOString(),
      rules: rules.map(({ enabled, createdAt, ...spec }) => ({
        ...spec,
        enabled,
      })),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `backdoorsniper-rules-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Exported ${rules.length} custom rule${rules.length === 1 ? "" : "s"}`);
  }, [rules]);

  /** Import custom rules from a JSON file selected by the user. */
  const importRulesJson = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const parsed = JSON.parse(String(reader.result));
          const incoming: unknown = Array.isArray(parsed)
            ? parsed
            : (parsed?.rules ?? []);
          if (!Array.isArray(incoming)) {
            throw new Error("Expected an array of rules or { rules: [...] }");
          }
          // Validate + dedupe against existing rule ids
          const existingIds = new Set(rules.map((r) => r.id));
          const imported: CustomRule[] = [];
          let skipped = 0;
          for (const raw of incoming) {
            const r = raw as Partial<CustomRuleSpec>;
            if (!r || typeof r.id !== "string" || typeof r.pattern !== "string") {
              skipped++;
              continue;
            }
            // If id collides, append a suffix
            let id = r.id;
            let n = 1;
            while (existingIds.has(id)) {
              id = `${r.id}-${n++}`;
            }
            existingIds.add(id);
            imported.push({
              id,
              title: typeof r.title === "string" ? r.title : "Imported rule",
              severity: r.severity ?? "medium",
              category: r.category ?? "suspicious-pattern",
              pattern: r.pattern,
              description: r.description ?? "",
              remediation: r.remediation ?? "",
              references: r.references ?? "",
              enabled: r.enabled !== false,
              createdAt: Date.now(),
            });
          }
          if (imported.length === 0) {
            toast.error("No valid rules found in file");
            return;
          }
          const next = [...rules, ...imported];
          onChange(next);
          saveCustomRules(next);
          toast.success(`Imported ${imported.length} rule${imported.length === 1 ? "" : "s"}`, {
            description:
              skipped > 0
                ? `${skipped} skipped (invalid)`
                : `${next.length} total rules now`,
          });
        } catch (err) {
          toast.error("Failed to parse JSON file", {
            description: err instanceof Error ? err.message : "Unknown error",
          });
        } finally {
          // Reset input so the same file can be re-selected
          if (importInputRef.current) importInputRef.current.value = "";
        }
      };
      reader.readAsText(file);
    },
    [rules, onChange]
  );

  const filteredRules = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return rules;
    return rules.filter(
      (r) =>
        r.id.toLowerCase().includes(q) ||
        r.title.toLowerCase().includes(q) ||
        r.pattern.toLowerCase().includes(q)
    );
  }, [rules, search]);

  if (!open) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm"
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.96, y: 8 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.96, y: 8 }}
          transition={{ type: "spring", stiffness: 320, damping: 30 }}
          className="glass relative flex h-[90vh] w-[95vw] max-w-5xl flex-col overflow-hidden rounded-xl border border-border bg-card shadow-2xl"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border bg-muted/30 px-5 py-3">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500/20 to-emerald-700/10 border border-emerald-500/30">
                <Wand2 className="h-4 w-4 text-emerald-500" />
              </div>
              <div>
                <h3 className="text-sm font-semibold">Custom Rule Editor</h3>
                <p className="text-[10px] text-muted-foreground">
                  Write your own regex-based detection rules ·{" "}
                  <span className="text-emerald-600 dark:text-emerald-400">
                    {rules.filter((r) => r.enabled).length}
                  </span>{" "}
                  active
                </p>
              </div>
            </div>
            <div className="flex items-center gap-1.5">
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 text-xs"
                onClick={exportRulesJson}
                disabled={rules.length === 0}
                title="Export all custom rules as a JSON file"
              >
                <Download className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Export</span>
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 text-xs"
                onClick={() => importInputRef.current?.click()}
                title="Import custom rules from a JSON file"
              >
                <Upload className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Import</span>
              </Button>
              <input
                ref={importInputRef}
                type="file"
                accept=".json,application/json"
                className="hidden"
                onChange={importRulesJson}
              />
              <Button variant="ghost" size="icon" className="h-8 w-8" onClick={onClose}>
                <X className="h-4 w-4" />
              </Button>
            </div>
          </div>

          {/* Body — split view: list on left, editor on right */}
          <div className="flex min-h-0 flex-1 flex-col md:flex-row">
            {/* List */}
            <div className="flex min-h-0 flex-1 flex-col border-b border-border md:border-b-0 md:border-r">
              <div className="flex items-center gap-2 border-b border-border bg-muted/10 px-3 py-2">
                <div className="relative min-w-0 flex-1">
                  <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    placeholder="Search custom rules…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="h-8 pl-8 text-xs"
                  />
                </div>
                <Button
                  size="sm"
                  className="h-8 gap-1.5 bg-emerald-600 text-xs hover:bg-emerald-700"
                  onClick={startNew}
                >
                  <Plus className="h-3.5 w-3.5" />
                  New
                </Button>
              </div>

              <ScrollArea className="thin-scrollbar flex-1">
                <div className="space-y-2 p-3">
                  {filteredRules.length === 0 ? (
                    <div className="flex flex-col items-center justify-center gap-3 py-12 text-center">
                      <Wand2 className="h-10 w-10 text-muted-foreground/30" />
                      <p className="text-sm text-muted-foreground">
                        {rules.length === 0
                          ? "No custom rules yet — create one or load a template below"
                          : "No rules match your search"}
                      </p>
                      {rules.length === 0 && (
                        <div className="flex flex-wrap justify-center gap-2 pt-2">
                          {SAMPLE_TEMPLATES.map((t) => (
                            <button
                              key={t.label}
                              onClick={() => loadTemplate(t.spec)}
                              className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/5 px-2.5 py-1 text-[11px] text-emerald-700 transition-colors hover:bg-emerald-500/15 dark:text-emerald-400"
                            >
                              <FileCode2 className="h-3 w-3" />
                              {t.label}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : (
                    filteredRules.map((r) => {
                      const s = SEVERITY_BADGE[r.severity as Severity];
                      return (
                        <motion.div
                          key={r.id}
                          layout
                          initial={{ opacity: 0, y: 4 }}
                          animate={{ opacity: 1, y: 0 }}
                          className={`group overflow-hidden rounded-lg border bg-card/50 ${s.leftBorder} ${
                            !r.enabled ? "opacity-50" : ""
                          }`}
                        >
                          <div className="flex items-start gap-2 p-2.5">
                            <button
                              onClick={() => toggleEnabled(r.id)}
                              className={`mt-0.5 flex h-4 w-7 shrink-0 items-center rounded-full p-0.5 transition-colors ${
                                r.enabled
                                  ? "bg-emerald-500"
                                  : "bg-muted-foreground/30"
                              }`}
                              title={r.enabled ? "Disable rule" : "Enable rule"}
                            >
                              <span
                                className={`block h-3 w-3 rounded-full bg-white shadow transition-transform ${
                                  r.enabled ? "translate-x-3" : "translate-x-0"
                                }`}
                              />
                            </button>
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span
                                  className={`inline-flex items-center rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${s.badge}`}
                                >
                                  {r.severity.slice(0, 4)}
                                </span>
                                <span className="font-mono text-[10px] text-muted-foreground">
                                  {r.id}
                                </span>
                                <span className="truncate text-xs font-medium">
                                  {r.title}
                                </span>
                              </div>
                              <code className="mt-1 block truncate font-mono text-[10px] text-muted-foreground">
                                /{r.pattern}/i
                              </code>
                              <div className="mt-0.5 text-[10px] text-muted-foreground/70">
                                {CATEGORY_LABEL[r.category as Category] ?? r.category}
                              </div>
                            </div>
                            <div className="flex shrink-0 items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-7 w-7"
                                onClick={() => startEdit(r)}
                                title="Edit"
                              >
                                <Edit2 className="h-3 w-3" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-7 w-7 text-red-500 hover:text-red-600"
                                onClick={() => deleteRule(r.id)}
                                title="Delete"
                              >
                                <Trash2 className="h-3 w-3" />
                              </Button>
                            </div>
                          </div>
                        </motion.div>
                      );
                    })
                  )}
                </div>
              </ScrollArea>
            </div>

            {/* Editor pane */}
            <div className="flex min-h-0 flex-1 flex-col bg-background">
              {editing ? (
                <ScrollArea className="thin-scrollbar flex-1">
                  <div className="space-y-4 p-4">
                    <div className="flex items-center gap-2">
                      <Beaker className="h-4 w-4 text-emerald-500" />
                      <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                        {rules.some((r) => r.id === editing.id)
                          ? "Edit rule"
                          : "New rule"}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                      <div className="space-y-1.5">
                        <Label className="text-xs">Rule ID</Label>
                        <Input
                          value={editing.id}
                          onChange={(e) =>
                            setEditing({ ...editing, id: e.target.value })
                          }
                          placeholder="USER-NEW-001"
                          className="h-8 font-mono text-xs"
                        />
                      </div>
                      <div className="space-y-1.5">
                        <Label className="text-xs">Severity</Label>
                        <Select
                          value={editing.severity}
                          onValueChange={(v) =>
                            setEditing({ ...editing, severity: v })
                          }
                        >
                          <SelectTrigger className="h-8 text-xs">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {(
                              [
                                "critical",
                                "high",
                                "medium",
                                "low",
                                "info",
                              ] as Severity[]
                            ).map((s) => (
                              <SelectItem key={s} value={s} className="text-xs">
                                {s}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                    </div>

                    <div className="space-y-1.5">
                      <Label className="text-xs">Title</Label>
                      <Input
                        value={editing.title}
                        onChange={(e) =>
                          setEditing({ ...editing, title: e.target.value })
                        }
                        placeholder="Short, human-readable rule title"
                        className="h-8 text-xs"
                      />
                    </div>

                    <div className="space-y-1.5">
                      <Label className="text-xs">
                        Regex pattern{" "}
                        <span className="text-muted-foreground/60">
                          (matched against each line, case-insensitive)
                        </span>
                      </Label>
                      <Input
                        value={editing.pattern}
                        onChange={(e) =>
                          setEditing({ ...editing, pattern: e.target.value })
                        }
                        placeholder="e.g. subprocess\.(run|call).*shell\s*=\s*True"
                        className={`h-8 font-mono text-xs ${
                          regexError
                            ? "border-red-500/60 bg-red-500/5"
                            : testMatches.length > 0
                              ? "border-emerald-500/60 bg-emerald-500/5"
                              : ""
                        }`}
                      />
                      {regexError ? (
                        <div className="flex items-center gap-1.5 text-[11px] text-red-500">
                          <AlertCircle className="h-3 w-3" />
                          {regexError}
                        </div>
                      ) : testMatches.length > 0 ? (
                        <div className="flex items-center gap-1.5 text-[11px] text-emerald-600 dark:text-emerald-400">
                          <CheckCircle2 className="h-3 w-3" />
                          Matches {testMatches.length} line
                          {testMatches.length === 1 ? "" : "s"} in the editor
                          {testMatches.length > 0 && (
                            <span className="text-muted-foreground">
                              {" "}
                              (L{testMatches.slice(0, 5).join(", ")}
                              {testMatches.length > 5 ? "…" : ""})
                            </span>
                          )}
                        </div>
                      ) : editing.pattern ? (
                        <div className="text-[11px] text-muted-foreground">
                          No matches in the current editor contents
                        </div>
                      ) : null}
                    </div>

                    <div className="space-y-1.5">
                      <Label className="text-xs">Category</Label>
                      <Select
                        value={editing.category}
                        onValueChange={(v) =>
                          setEditing({ ...editing, category: v })
                        }
                      >
                        <SelectTrigger className="h-8 text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {(Object.keys(CATEGORY_LABEL) as Category[]).map((c) => (
                            <SelectItem key={c} value={c} className="text-xs">
                              {CATEGORY_LABEL[c]}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-1.5">
                      <Label className="text-xs">
                        Description{" "}
                        <span className="text-muted-foreground/60">(optional)</span>
                      </Label>
                      <Textarea
                        value={editing.description ?? ""}
                        onChange={(e) =>
                          setEditing({ ...editing, description: e.target.value })
                        }
                        placeholder="Why is this pattern dangerous?"
                        className="min-h-[60px] text-xs"
                      />
                    </div>

                    <div className="space-y-1.5">
                      <Label className="text-xs">
                        Remediation{" "}
                        <span className="text-muted-foreground/60">(optional)</span>
                      </Label>
                      <Textarea
                        value={editing.remediation ?? ""}
                        onChange={(e) =>
                          setEditing({ ...editing, remediation: e.target.value })
                        }
                        placeholder="How to fix / what to replace it with"
                        className="min-h-[60px] text-xs"
                      />
                    </div>

                    <div className="space-y-1.5">
                      <Label className="text-xs">
                        CWE / References{" "}
                        <span className="text-muted-foreground/60">
                          (comma-separated, optional)
                        </span>
                      </Label>
                      <Input
                        value={editing.references ?? ""}
                        onChange={(e) =>
                          setEditing({ ...editing, references: e.target.value })
                        }
                        placeholder="CWE-78, CWE-918"
                        className="h-8 font-mono text-xs"
                      />
                    </div>

                    <div className="flex items-center justify-end gap-2 border-t border-border pt-3">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-8 text-xs"
                        onClick={cancelEdit}
                      >
                        Cancel
                      </Button>
                      <Button
                        size="sm"
                        className="h-8 gap-1.5 bg-emerald-600 text-xs hover:bg-emerald-700"
                        onClick={saveEdit}
                      >
                        <Save className="h-3.5 w-3.5" />
                        Save rule
                      </Button>
                    </div>
                  </div>
                </ScrollArea>
              ) : (
                <div className="flex flex-1 flex-col items-center justify-center gap-4 p-8 text-center">
                  <div className="relative">
                    <Wand2 className="h-12 w-12 text-muted-foreground/30" />
                    <div className="absolute inset-0 -z-10 animate-ping rounded-full bg-emerald-500/10" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">No rule selected</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      Click <Edit2 className="mx-0.5 inline h-3 w-3" /> on a rule to
                      edit, or
                      <button
                        onClick={startNew}
                        className="mx-1 inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400 hover:underline"
                      >
                        <Plus className="h-3 w-3" /> create a new one
                      </button>
                    </p>
                  </div>
                  {rules.length === 0 && (
                    <div className="mt-2 w-full max-w-sm rounded-lg border border-border bg-muted/30 p-3 text-left">
                      <p className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                        Quick start templates
                      </p>
                      <div className="space-y-1.5">
                        {SAMPLE_TEMPLATES.map((t) => (
                          <button
                            key={t.label}
                            onClick={() => loadTemplate(t.spec)}
                            className="flex w-full items-center gap-2 rounded-md border border-border bg-background px-2.5 py-1.5 text-left text-xs transition-colors hover:bg-muted/40"
                          >
                            <FileCode2 className="h-3.5 w-3.5 shrink-0 text-emerald-500" />
                            <span className="flex-1 truncate">{t.label}</span>
                            <Plus className="h-3 w-3 shrink-0 text-muted-foreground" />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Footer */}
          <div className="border-t border-border bg-muted/20 px-4 py-2 text-[10px] text-muted-foreground">
            <div className="flex items-center justify-between">
              <span>
                Custom rules are stored in your browser (localStorage) and run
                alongside built-in rules.
              </span>
              <Badge variant="outline" className="font-mono text-[10px]">
                {rules.length} custom rule{rules.length === 1 ? "" : "s"}
              </Badge>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
