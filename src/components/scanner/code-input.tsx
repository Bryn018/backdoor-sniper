"use client";

import { useRef, useEffect, useCallback, useState, useMemo } from "react";
import {
  Upload,
  Trash2,
  FileCode2,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Beaker,
  Files,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SAMPLES, type SampleThreat } from "@/lib/samples/threats";
import { highlightPython } from "@/lib/python-highlight";
import type { Finding, Severity } from "@/lib/detector/types";

interface CodeInputProps {
  code: string;
  onChange: (code: string) => void;
  onScan: () => void;
  scanning: boolean;
  activeLine: number | null;
  findings?: Finding[];
  onBatchFiles?: (files: { name: string; content: string }[]) => void;
}

/** Map each line number to the worst severity detected on that line. */
function useFindingLineMap(findings: Finding[] | undefined) {
  return useMemo(() => {
    const m = new Map<number, Severity>();
    if (!findings) return m;
    const rank: Record<Severity, number> = {
      critical: 0, high: 1, medium: 2, low: 3, info: 4,
    };
    for (const f of findings) {
      const prev = m.get(f.line);
      if (!prev || rank[f.severity] < rank[prev]) m.set(f.line, f.severity);
    }
    return m;
  }, [findings]);
}

export function CodeInput({
  code,
  onChange,
  onScan,
  scanning,
  activeLine,
  findings,
  onBatchFiles,
}: CodeInputProps) {
  const taRef = useRef<HTMLTextAreaElement>(null);
  const preRef = useRef<HTMLPreElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const [fileName, setFileName] = useState<string>("");
  const [multiSelect, setMultiSelect] = useState(false);

  const lines = code.split("\n");
  const lineCount = lines.length;
  const findingLineMap = useFindingLineMap(findings);

  // Highlighted HTML (memoized)
  const highlightedHtml = useMemo(() => highlightPython(code), [code]);

  // Sync gutter + pre scroll with textarea
  const handleScroll = useCallback(() => {
    if (taRef.current) {
      const top = taRef.current.scrollTop;
      const left = taRef.current.scrollLeft;
      if (gutterRef.current) gutterRef.current.scrollTop = top;
      if (preRef.current) {
        preRef.current.scrollTop = top;
        preRef.current.scrollLeft = left;
      }
    }
  }, []);

  // Scroll active line into view
  useEffect(() => {
    if (activeLine == null || !taRef.current) return;
    const lineHeight = 20;
    taRef.current.scrollTop = Math.max(0, (activeLine - 4) * lineHeight);
    handleScroll();
  }, [activeLine, handleScroll]);

  const handleFile = async (file: File) => {
    if (file.size > 500_000) {
      alert(`File too large (max 500 KB): ${file.name}`);
      return;
    }
    const text = await file.text();
    onChange(text);
    setFileName(file.name);
  };

  const handleFiles = async (files: FileList) => {
    if (!onBatchFiles) {
      // single-file mode — just take the first
      if (files[0]) await handleFile(files[0]);
      return;
    }
    const all: { name: string; content: string }[] = [];
    for (const f of Array.from(files)) {
      if (f.size > 500_000) continue;
      const text = await f.text();
      all.push({ name: f.name, content: text });
    }
    if (all.length === 1) {
      onChange(all[0].content);
      setFileName(all[0].name);
    } else if (all.length > 1) {
      onBatchFiles(all);
    }
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files?.length) {
      handleFiles(e.dataTransfer.files);
    }
  };

  const loadSample = (id: string) => {
    const s: SampleThreat | undefined = SAMPLES.find((x) => x.id === id);
    if (s) {
      onChange(s.code);
      setFileName(`sample: ${s.name}`);
    }
  };

  const charCount = code.length;

  // Tab key inserts 4 spaces instead of changing focus
  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Tab") {
      e.preventDefault();
      const ta = e.currentTarget;
      const start = ta.selectionStart;
      const end = ta.selectionEnd;
      const next = code.slice(0, start) + "    " + code.slice(end);
      onChange(next);
      requestAnimationFrame(() => {
        ta.selectionStart = ta.selectionEnd = start + 4;
      });
    }
  };

  // Build gutter line entries with finding markers
  const gutterLines = useMemo(() => {
    return lines.map((_, i) => {
      const n = i + 1;
      const sev = findingLineMap.get(n);
      const isActive = activeLine === n;
      return { n, sev, isActive };
    });
  }, [lines, findingLineMap, activeLine]);

  // Build highlighted lines with finding background
  const highlightedLinesHtml = useMemo(() => {
    const htmlLines = highlightedHtml.split("\n");
    return htmlLines.map((html, i) => {
      const n = i + 1;
      const sev = findingLineMap.get(n);
      const isActive = activeLine === n;
      const classes = [
        "finding-line-marker",
        sev ? `finding-line-marker-${sev}` : "",
        sev ? `finding-line-bg-${sev}` : "",
        isActive ? "active-line-bg" : "",
      ].filter(Boolean).join(" ");
      return `<div class="${classes}">${html || " "}</div>`;
    }).join("");
  }, [highlightedHtml, findingLineMap, activeLine]);

  return (
    <div className="flex h-full flex-col">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border bg-muted/30 px-3 py-2">
        <div className="flex items-center gap-2 text-sm font-medium text-foreground">
          <FileCode2 className="h-4 w-4 text-emerald-500" />
          <span>Source</span>
          {fileName && (
            <span className="max-w-[180px] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
              {fileName}
            </span>
          )}
        </div>

        <div className="ml-auto flex flex-wrap items-center gap-2">
          <Select onValueChange={loadSample}>
            <SelectTrigger className="h-8 w-[180px] gap-1 text-xs">
              <Beaker className="h-3.5 w-3.5" />
              <SelectValue placeholder="Load sample…" />
            </SelectTrigger>
            <SelectContent>
              {SAMPLES.map((s) => (
                <SelectItem key={s.id} value={s.id} className="text-xs">
                  <span className="flex items-center gap-2">
                    <span
                      className={`inline-flex h-1.5 w-1.5 rounded-full ${
                        s.expectedVerdict === "dangerous" ||
                        s.expectedVerdict === "malicious"
                          ? "bg-red-500"
                          : s.expectedVerdict === "suspicious"
                            ? "bg-amber-500"
                            : "bg-emerald-500"
                      }`}
                    />
                    {s.name}
                  </span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <input
            ref={fileRef}
            type="file"
            accept=".py,.pyw,.txt"
            multiple={multiSelect}
            className="hidden"
            onChange={(e) => {
              if (e.target.files?.length) handleFiles(e.target.files);
              e.target.value = "";
            }}
          />
          <Button
            variant="outline"
            size="sm"
            className={`h-8 gap-1.5 text-xs ${multiSelect ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" : ""}`}
            onClick={() => {
              const next = !multiSelect;
              setMultiSelect(next);
              // Defer file dialog so the multiple attribute is updated
              setTimeout(() => fileRef.current?.click(), 0);
            }}
            title={multiSelect ? "Multi-file mode: select multiple .py files for batch scan" : "Upload a single .py file"}
          >
            {multiSelect ? <Files className="h-3.5 w-3.5" /> : <Upload className="h-3.5 w-3.5" />}
            {multiSelect ? "Batch" : "Upload"}
          </Button>
          {multiSelect && (
            <Button
              variant="ghost"
              size="sm"
              className="h-8 gap-1.5 text-xs"
              onClick={() => setMultiSelect(false)}
              title="Exit batch mode"
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1.5 text-xs"
            onClick={() => {
              onChange("");
              setFileName("");
            }}
            disabled={!code}
          >
            <Trash2 className="h-3.5 w-3.5" />
            Clear
          </Button>
          <Button
            size="sm"
            className="h-8 gap-1.5 bg-emerald-600 text-xs hover:bg-emerald-700 scan-btn-glow button-press"
            onClick={onScan}
            disabled={!code.trim() || scanning}
          >
            {scanning ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <AlertTriangle className="h-3.5 w-3.5" />
            )}
            {scanning ? "Scanning…" : "Scan for backdoors"}
          </Button>
        </div>
      </div>

      {/* Editor: gutter + overlay (pre + textarea) */}
      <div
        className="relative flex min-h-[320px] flex-1 overflow-hidden bg-background"
        onDragOver={(e) => e.preventDefault()}
        onDrop={onDrop}
      >
        <div
          ref={gutterRef}
          className="select-none overflow-hidden border-r border-border bg-muted/20 px-2 py-3 text-right font-mono text-xs leading-5"
          style={{ minWidth: "3.5rem", lineHeight: "20px" }}
          aria-hidden
        >
          {gutterLines.map(({ n, sev, isActive }) => (
            <div
              key={n}
              className={`relative flex items-center justify-end gap-1 ${
                isActive ? "font-bold text-red-500" : "text-muted-foreground/60"
              }`}
              style={{ height: "20px" }}
            >
              {sev && (
                <span
                  className={`inline-block h-1.5 w-1.5 rounded-full ${
                    sev === "critical" ? "bg-red-500" :
                    sev === "high" ? "bg-orange-500" :
                    sev === "medium" ? "bg-amber-500" :
                    sev === "low" ? "bg-emerald-500" : "bg-slate-500"
                  }`}
                  title={`${sev} finding on line ${n}`}
                />
              )}
              <span>{n}</span>
            </div>
          ))}
        </div>

        <div className="code-overlay-wrap relative min-w-0 flex-1">
          {/* Highlighted background layer */}
          <pre
            ref={preRef}
            aria-hidden
            className="code-overlay-pre"
            dangerouslySetInnerHTML={{ __html: highlightedLinesHtml }}
          />
          {/* Transparent editable textarea on top */}
          <textarea
            ref={taRef}
            value={code}
            onChange={(e) => onChange(e.target.value)}
            onScroll={handleScroll}
            onKeyDown={onKeyDown}
            spellCheck={false}
            placeholder={`# Paste Python source here, drop a .py file, or load a sample.\n# Tip: click "Batch" to scan multiple files at once.\n# Example:\nimport os\nos.system("rm -rf /")  # <- this will be flagged`}
            className="code-overlay-textarea"
          />
        </div>

        {/* Empty-state overlay hint when no code */}
        {!code && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <div className="text-center text-xs text-muted-foreground/60">
              <FileCode2 className="mx-auto mb-2 h-8 w-8 opacity-40" />
              Drop a <code className="rounded bg-muted px-1 py-0.5">.py</code> file or start typing
            </div>
          </div>
        )}
      </div>

      {/* Status bar */}
      <div className="flex items-center justify-between border-t border-border bg-muted/30 px-3 py-1.5 font-mono text-[10px] text-muted-foreground">
        <span className="flex items-center gap-3">
          <span>{lineCount} {lineCount === 1 ? "line" : "lines"}</span>
          <span>{charCount.toLocaleString()} {charCount === 1 ? "char" : "chars"}</span>
          {findings && findings.length > 0 && (
            <span className="flex items-center gap-1 text-amber-500">
              <AlertTriangle className="h-3 w-3" />
              {findings.length} finding{findings.length === 1 ? "" : "s"} mapped
            </span>
          )}
        </span>
        <span className="flex items-center gap-1">
          <CheckCircle2 className="h-3 w-3 text-emerald-500" />
          Python · syntax-highlighted · static analysis
        </span>
      </div>
    </div>
  );
}
