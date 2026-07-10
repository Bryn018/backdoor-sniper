"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bookmark,
  BookmarkPlus,
  Trash2,
  FileCode2,
  Clock,
  Search,
  X,
  Upload,
  Check,
  Loader2,
  AlertCircle,
} from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { formatDistanceToNow } from "date-fns";
import { toast } from "sonner";

/** A user-saved code snippet persisted in localStorage. */
export interface Snippet {
  id: string;
  name: string;
  code: string;
  createdAt: string;
  lastUsedAt: string;
}

const STORAGE_KEY = "backdoorsniper.snippets.v1";

/** Load all saved snippets from localStorage. Safe to call during SSR (returns []). */
export function loadSnippets(): Snippet[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (s): s is Snippet =>
        s &&
        typeof s.id === "string" &&
        typeof s.name === "string" &&
        typeof s.code === "string" &&
        typeof s.createdAt === "string" &&
        typeof s.lastUsedAt === "string"
    );
  } catch {
    return [];
  }
}

export function saveSnippets(snippets: Snippet[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(snippets));
  } catch {
    /* quota exceeded — ignore */
  }
}

interface SnippetLibraryProps {
  /** Current code in the editor — used for "save current" + "test snippet". */
  code: string;
  /** Called when a snippet is loaded into the editor. */
  onLoad: (code: string, name: string) => void;
  /** Controlled open state. */
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function SnippetLibrary({
  code,
  onLoad,
  open,
  onOpenChange,
}: SnippetLibraryProps) {
  const [snippets, setSnippets] = useState<Snippet[]>(() => loadSnippets());
  const [search, setSearch] = useState("");
  const [saveName, setSaveName] = useState("");
  const [saving, setSaving] = useState(false);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  // When the sheet opens, refresh from localStorage (in case it was modified
  // elsewhere) and auto-suggest a name. This is a legitimate sync with an
  // external store, so we disable the set-state-in-effect rule here.
  useEffect(() => {
    if (!open) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSnippets(loadSnippets());
    // Auto-suggest a name based on first non-comment line of code
    const firstLine = code
      .split("\n")
      .map((l) => l.trim())
      .find((l) => l && !l.startsWith("#"));
    const suggested = firstLine
      ? firstLine.slice(0, 40).replace(/[^a-zA-Z0-9_\-\s]/g, "").trim() ||
        "untitled"
      : `snippet-${new Date().toISOString().slice(0, 10)}`;
    setSaveName(suggested);
  }, [open, code]);

  const persist = useCallback((next: Snippet[]) => {
    setSnippets(next);
    saveSnippets(next);
  }, []);

  const saveCurrent = () => {
    if (!code.trim()) {
      toast.error("Editor is empty — nothing to save");
      return;
    }
    if (!saveName.trim()) {
      toast.error("Please enter a snippet name");
      return;
    }
    setSaving(true);
    const now = new Date().toISOString();
    const snippet: Snippet = {
      id: `snip-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      name: saveName.trim().slice(0, 60),
      code,
      createdAt: now,
      lastUsedAt: now,
    };
    persist([snippet, ...snippets]);
    toast.success(`Saved snippet "${snippet.name}"`, {
      description: `${code.split("\n").length} lines · ${code.length} chars`,
    });
    setSaveName("");
    setSaving(false);
  };

  const load = (snippet: Snippet) => {
    const updated = snippets.map((s) =>
      s.id === snippet.id ? { ...s, lastUsedAt: new Date().toISOString() } : s
    );
    persist(updated);
    onLoad(snippet.code, snippet.name);
    onOpenChange(false);
    toast.success(`Loaded snippet "${snippet.name}"`, {
      description: `${snippet.code.split("\n").length} lines inserted into editor`,
    });
  };

  const remove = (id: string) => {
    const target = snippets.find((s) => s.id === id);
    persist(snippets.filter((s) => s.id !== id));
    setConfirmDeleteId(null);
    if (target) {
      toast.info(`Deleted snippet "${target.name}"`);
    }
  };

  const filtered = snippets.filter((s) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      s.name.toLowerCase().includes(q) ||
      s.code.toLowerCase().includes(q)
    );
  });

  // Sort: most recently used first
  const sorted = [...filtered].sort(
    (a, b) =>
      new Date(b.lastUsedAt).getTime() - new Date(a.lastUsedAt).getTime()
  );

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-md p-0 flex flex-col">
        <SheetHeader className="border-b border-border px-4 py-3">
          <SheetTitle className="flex items-center gap-2 text-sm">
            <Bookmark className="h-4 w-4 text-emerald-500" />
            Snippet Library
            <span className="ml-1 rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
              {snippets.length}
            </span>
          </SheetTitle>
        </SheetHeader>

        {/* Save current editor content as snippet */}
        <div className="border-b border-border bg-muted/30 p-3">
          <label className="mb-1.5 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
            Save current editor content
          </label>
          <div className="flex items-center gap-1.5">
            <input
              type="text"
              value={saveName}
              onChange={(e) => setSaveName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !saving) saveCurrent();
              }}
              placeholder="Snippet name…"
              maxLength={60}
              className="h-8 flex-1 rounded-md border border-border bg-background px-2.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-emerald-500/40"
            />
            <Button
              size="sm"
              className="h-8 gap-1.5 bg-emerald-600 text-xs hover:bg-emerald-700"
              onClick={saveCurrent}
              disabled={saving || !code.trim()}
              title="Save current code as a snippet (Ctrl+S in editor would also work)"
            >
              {saving ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <BookmarkPlus className="h-3.5 w-3.5" />
              )}
              Save
            </Button>
          </div>
          {!code.trim() && (
            <p className="mt-1.5 flex items-center gap-1 text-[10px] text-amber-600 dark:text-amber-400">
              <AlertCircle className="h-3 w-3" />
              Editor is empty — paste code first to enable saving.
            </p>
          )}
        </div>

        {/* Search */}
        {snippets.length > 0 && (
          <div className="border-b border-border px-3 py-2">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search snippets…"
                className="h-7 w-full rounded-md border border-border bg-transparent pl-7 pr-7 text-[11px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-emerald-500/40"
              />
              {search && (
                <button
                  onClick={() => setSearch("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
          </div>
        )}

        {/* Snippets list */}
        <div className="min-h-0 flex-1 overflow-y-auto custom-scrollbar">
          {snippets.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 p-6 text-center">
              <Bookmark className="h-10 w-10 text-muted-foreground/40" />
              <p className="text-sm font-medium text-foreground">
                No saved snippets yet
              </p>
              <p className="max-w-xs text-xs text-muted-foreground">
                Save frequently scanned Python code snippets here for quick
                re-loading. Snippets persist across page reloads (stored in
                your browser).
              </p>
            </div>
          ) : sorted.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 p-6 text-center">
              <Search className="h-8 w-8 text-muted-foreground/40" />
              <p className="text-sm text-muted-foreground">
                No snippets match &ldquo;{search}&rdquo;
              </p>
            </div>
          ) : (
            <div className="space-y-1.5 p-2">
              {sorted.map((snippet, idx) => {
                const lineCount = snippet.code.split("\n").length;
                const charCount = snippet.code.length;
                const isConfirming = confirmDeleteId === snippet.id;
                return (
                  <motion.div
                    key={snippet.id}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: Math.min(idx * 0.02, 0.15) }}
                    className={`group relative rounded-lg border border-border/60 bg-card p-2.5 transition-all hover:border-emerald-500/40 hover:bg-emerald-500/5 ${
                      hoveredId === snippet.id ? "ring-1 ring-emerald-500/30" : ""
                    }`}
                    onMouseEnter={() => setHoveredId(snippet.id)}
                    onMouseLeave={() => {
                      setHoveredId(null);
                      if (confirmDeleteId === snippet.id) setConfirmDeleteId(null);
                    }}
                  >
                    <div className="flex items-center gap-2">
                      <Bookmark className="h-3.5 w-3.5 shrink-0 text-emerald-500" />
                      <span className="min-w-0 flex-1 truncate text-xs font-medium text-foreground">
                        {snippet.name}
                      </span>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6 shrink-0 opacity-0 transition-opacity group-hover:opacity-100"
                        onClick={() => load(snippet)}
                        title="Load snippet into editor"
                      >
                        <Upload className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
                      </Button>
                      {isConfirming ? (
                        <>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-6 w-6 shrink-0"
                            onClick={() => remove(snippet.id)}
                            title="Confirm delete"
                          >
                            <Check className="h-3 w-3 text-red-500" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-6 w-6 shrink-0"
                            onClick={() => setConfirmDeleteId(null)}
                            title="Cancel delete"
                          >
                            <X className="h-3 w-3 text-muted-foreground" />
                          </Button>
                        </>
                      ) : (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6 shrink-0 opacity-0 transition-opacity group-hover:opacity-100"
                          onClick={() => setConfirmDeleteId(snippet.id)}
                          title="Delete snippet"
                        >
                          <Trash2 className="h-3 w-3 text-muted-foreground hover:text-red-500" />
                        </Button>
                      )}
                    </div>
                    <div className="mt-1.5 flex items-center justify-between pl-6 font-mono text-[10px] text-muted-foreground">
                      <div className="flex items-center gap-2">
                        <span className="inline-flex items-center gap-0.5">
                          <FileCode2 className="h-2.5 w-2.5" />
                          {lineCount}L
                        </span>
                        <span>{charCount.toLocaleString()} chars</span>
                      </div>
                      <span className="inline-flex items-center gap-0.5">
                        <Clock className="h-2.5 w-2.5" />
                        {formatDistanceToNow(new Date(snippet.lastUsedAt))} ago
                      </span>
                    </div>

                    {/* Code preview on hover */}
                    <AnimatePresence>
                      {hoveredId === snippet.id && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: "auto", opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.15 }}
                          className="overflow-hidden"
                        >
                          <pre className="mt-2 max-h-32 overflow-y-auto rounded-md border border-border/40 bg-muted/30 p-2 font-mono text-[10px] leading-relaxed text-muted-foreground thin-scrollbar">
                            {snippet.code.slice(0, 400)}
                            {snippet.code.length > 400 ? "…" : ""}
                          </pre>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer info */}
        <div className="border-t border-border bg-muted/30 px-4 py-2 text-[10px] text-muted-foreground">
          <div className="flex items-center justify-between">
            <span>
              {snippets.length} snippet{snippets.length === 1 ? "" : "s"} ·
              stored locally
            </span>
            {snippets.length > 0 && (
              <button
                onClick={() => {
                  if (
                    window.confirm(
                      `Delete all ${snippets.length} snippets? This cannot be undone.`
                    )
                  ) {
                    persist([]);
                    toast.info("All snippets cleared");
                  }
                }}
                className="text-red-500 hover:text-red-600 transition-colors"
              >
                Clear all
              </button>
            )}
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
