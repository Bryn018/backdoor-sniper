"use client";

import { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Keyboard, Command, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";

interface KeyboardShortcutsProps {
  open: boolean;
  onClose: () => void;
}

interface Shortcut {
  keys: string[];
  description: string;
  group: "Editor" | "Scan" | "Navigation" | "Tools";
}

const SHORTCUTS: Shortcut[] = [
  // Editor
  { keys: ["Tab"], description: "Insert 4 spaces", group: "Editor" },
  { keys: ["Ctrl", "A"], description: "Select all code", group: "Editor" },

  // Scan
  {
    keys: ["Ctrl", "Enter"],
    description: "Run scan now",
    group: "Scan",
  },
  {
    keys: ["W"],
    description: "Toggle watch mode (auto-rescan)",
    group: "Scan",
  },
  {
    keys: ["C"],
    description: "Clear the editor",
    group: "Scan",
  },

  // Navigation
  {
    keys: ["H"],
    description: "Open scan history",
    group: "Navigation",
  },
  {
    keys: ["R"],
    description: "Browse detection rules",
    group: "Navigation",
  },
  {
    keys: ["S"],
    description: "Open scan statistics",
    group: "Navigation",
  },
  {
    keys: ["U"],
    description: "Open custom rule editor",
    group: "Navigation",
  },
  {
    keys: ["B"],
    description: "Open snippet library",
    group: "Navigation",
  },
  {
    keys: ["T"],
    description: "Toggle dark / light theme",
    group: "Navigation",
  },

  // Tools
  {
    keys: ["E"],
    description: "Open enterprise console (API keys, audit, policy, compliance)",
    group: "Tools",
  },
  {
    keys: ["P"],
    description: "Open project scan (zip / tar / multi-file)",
    group: "Tools",
  },
  {
    keys: ["A"],
    description: "Get AI analysis of the current scan",
    group: "Tools",
  },
  {
    keys: ["?"],
    description: "Show this shortcuts dialog",
    group: "Tools",
  },
  {
    keys: ["Esc"],
    description: "Close any open dialog",
    group: "Tools",
  },
];

const GROUPS: Shortcut["group"][] = ["Editor", "Scan", "Navigation", "Tools"];
const GROUP_ICONS: Record<Shortcut["group"], string> = {
  Editor: "⌨️",
  Scan: "🎯",
  Navigation: "🧭",
  Tools: "🛠️",
};

export function KeyboardShortcuts({ open, onClose }: KeyboardShortcutsProps) {
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

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
          className="glass relative w-[95vw] max-w-2xl overflow-hidden rounded-xl border border-border bg-card shadow-2xl"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border bg-muted/30 px-5 py-3">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500/20 to-emerald-700/10 border border-emerald-500/30">
                <Keyboard className="h-4 w-4 text-emerald-500" />
              </div>
              <div>
                <h3 className="text-sm font-semibold">Keyboard Shortcuts</h3>
                <p className="text-[10px] text-muted-foreground">
                  Press{" "}
                  <kbd className="rounded border border-border bg-muted/60 px-1 py-0.5 font-mono text-[9px]">
                    ?
                  </kbd>{" "}
                  anytime to open this dialog
                </p>
              </div>
            </div>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={onClose}
            >
              <X className="h-4 w-4" />
            </Button>
          </div>

          {/* Body */}
          <div className="grid max-h-[60vh] gap-4 overflow-y-auto p-5 sm:grid-cols-2">
            {GROUPS.map((group) => {
              const items = SHORTCUTS.filter((s) => s.group === group);
              if (items.length === 0) return null;
              return (
                <div key={group}>
                  <h4 className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    <span className="text-sm">{GROUP_ICONS[group]}</span>
                    {group}
                  </h4>
                  <div className="space-y-1.5">
                    {items.map((s) => (
                      <div
                        key={s.description}
                        className="flex items-center justify-between gap-2 rounded-md px-2 py-1.5 transition-colors hover:bg-muted/40"
                      >
                        <span className="text-xs text-foreground/80">
                          {s.description}
                        </span>
                        <div className="flex items-center gap-1">
                          {s.keys.map((k, i) => (
                            <span key={i} className="flex items-center gap-1">
                              {i > 0 && (
                                <ArrowRight className="h-2.5 w-2.5 text-muted-foreground/50" />
                              )}
                              <kbd
                                className="inline-flex items-center gap-0.5 rounded border border-border bg-muted/60 px-1.5 py-0.5 font-mono text-[10px] font-medium text-foreground shadow-sm"
                              >
                                {k === "Ctrl" || k === "Cmd" ? (
                                  <Command className="h-2.5 w-2.5" />
                                ) : null}
                                {k === "Ctrl" || k === "Cmd" ? "" : k}
                              </kbd>
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Footer */}
          <div className="border-t border-border bg-muted/20 px-5 py-2.5 text-[10px] text-muted-foreground">
            Tip: shortcuts work from anywhere on the page. Hold off typing in
            form fields to use them.
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
