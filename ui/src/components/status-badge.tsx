import type { StatusTone } from "@/features/vpn/vpn-utils"
import { cn } from "@/lib/utils"

const TONE_DOT: Record<StatusTone, string> = {
  connected: "bg-emerald-500",
  pending: "bg-amber-500 animate-pulse",
  failed: "bg-destructive",
  idle: "bg-muted-foreground/50",
}

export function StatusBadge({
  tone,
  label,
  className,
}: {
  tone: StatusTone
  label: string
  className?: string
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-xs font-medium",
        className
      )}
    >
      <span className={cn("size-2 rounded-full", TONE_DOT[tone])} />
      {label}
    </span>
  )
}
