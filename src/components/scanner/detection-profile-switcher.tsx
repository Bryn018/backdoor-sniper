"use client";

import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldCheck,
  Globe,
  FileCode2,
  PackageSearch,
  Flame,
  GitBranch,
  ChevronDown,
  Check,
  Layers,
} from "lucide-react";
import {
  DETECTION_PROFILES,
  type DetectionProfile,
  getProfile,
} from "@/lib/detector/profiles";
import { toast } from "sonner";

const PROFILE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  ShieldCheck,
  Globe,
  FileCode2,
  PackageSearch,
  Flame,
  GitBranch,
};

const ACCENT_CLASSES: Record<DetectionProfile["accent"], string> = {
  emerald:
    "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  amber: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  orange:
    "border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400",
  red: "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
  slate:
    "border-slate-500/40 bg-slate-500/10 text-slate-600 dark:text-slate-300",
  purple:
    "border-purple-500/40 bg-purple-500/10 text-purple-600 dark:text-purple-400",
};

const STORAGE_KEY = "backdoorsniper.profile.v1";

interface DetectionProfileSwitcherProps {
  activeProfileId: string;
  onChange: (profile: DetectionProfile) => void;
}

export function DetectionProfileSwitcher({
  activeProfileId,
  onChange,
}: DetectionProfileSwitcherProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const active = getProfile(activeProfileId);
  const ActiveIcon = PROFILE_ICONS[active.icon] ?? ShieldCheck;

  // Click outside to close
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className={`hidden h-9 items-center gap-1.5 rounded-md border px-3 text-xs font-medium transition-all hover:scale-[1.02] sm:flex ${ACCENT_CLASSES[active.accent]}`}
        title={`Active profile: ${active.name}`}
      >
        <ActiveIcon className="h-3.5 w-3.5" />
        <span className="max-w-[110px] truncate">{active.name}</span>
        <ChevronDown className={`h-3 w-3 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      <button
        onClick={() => setOpen((v) => !v)}
        className={`flex h-9 w-9 items-center justify-center rounded-md border sm:hidden ${ACCENT_CLASSES[active.accent]}`}
        title={`Active profile: ${active.name}`}
        aria-label="Switch detection profile"
      >
        <ActiveIcon className="h-3.5 w-3.5" />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -4, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -4, scale: 0.97 }}
            transition={{ duration: 0.13 }}
            className="absolute right-0 top-11 z-50 w-80 overflow-hidden rounded-lg border border-border bg-popover shadow-xl"
          >
            <div className="border-b border-border bg-muted/30 px-3 py-2">
              <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                <Layers className="h-3 w-3" />
                Detection Profiles
              </p>
            </div>
            <div className="max-h-[60vh] overflow-y-auto p-1.5">
              {DETECTION_PROFILES.map((p) => {
                const Icon = PROFILE_ICONS[p.icon] ?? ShieldCheck;
                const isActive = p.id === activeProfileId;
                return (
                  <button
                    key={p.id}
                    onClick={() => {
                      onChange(p);
                      setOpen(false);
                      try {
                        localStorage.setItem(STORAGE_KEY, p.id);
                      } catch {
                        /* ignore */
                      }
                      toast.success(`Profile: ${p.name}`, {
                        description:
                          p.id === "all"
                            ? "All rules enabled"
                            : `${p.disabledRuleIds.length} rule${p.disabledRuleIds.length === 1 ? "" : "s"} disabled`,
                      });
                    }}
                    className={`group flex w-full items-start gap-2.5 rounded-md px-2.5 py-2 text-left transition-colors ${
                      isActive ? "bg-accent/50" : "hover:bg-accent/30"
                    }`}
                  >
                    <div
                      className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border ${ACCENT_CLASSES[p.accent]}`}
                    >
                      <Icon className="h-3.5 w-3.5" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <p className="text-xs font-semibold text-foreground">
                          {p.name}
                        </p>
                        {isActive && (
                          <Check className="h-3 w-3 text-emerald-500" />
                        )}
                      </div>
                      <p className="mt-0.5 text-[10px] leading-snug text-muted-foreground">
                        {p.description}
                      </p>
                      <p className="mt-1 font-mono text-[9px] text-muted-foreground/70">
                        {p.id === "all"
                          ? "79 rules enabled"
                          : `${p.disabledRuleIds.length} disabled`}
                      </p>
                    </div>
                  </button>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/** Read the persisted profile id from localStorage (client-only). */
export function loadProfileId(): string {
  if (typeof window === "undefined") return "all";
  try {
    return localStorage.getItem(STORAGE_KEY) ?? "all";
  } catch {
    return "all";
  }
}
