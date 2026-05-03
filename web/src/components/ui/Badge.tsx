import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export type BadgeTone =
  | "neutral"
  | "safe"
  | "review"
  | "breaking"
  | "rolled-back"
  | "stack-skipped"
  | "info";

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
}

const TONE: Record<BadgeTone, string> = {
  neutral: "bg-muted text-foreground",
  info: "bg-sky-100 text-sky-900 dark:bg-sky-900/40 dark:text-sky-100",
  safe: "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/40 dark:text-emerald-100",
  review: "bg-amber-100 text-amber-900 dark:bg-amber-900/40 dark:text-amber-100",
  breaking: "bg-red-100 text-red-900 dark:bg-red-900/40 dark:text-red-100",
  "rolled-back": "bg-red-100 text-red-900 dark:bg-red-900/40 dark:text-red-100",
  "stack-skipped": "bg-zinc-200 text-zinc-900 dark:bg-zinc-800 dark:text-zinc-100",
};

export function Badge({ tone = "neutral", className, ...rest }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
        TONE[tone],
        className,
      )}
      {...rest}
    />
  );
}
