import { SpinnerIcon } from "@phosphor-icons/react"

export function FullScreenLoader() {
  return (
    <div className="flex min-h-svh items-center justify-center bg-background text-muted-foreground">
      <SpinnerIcon className="size-8 animate-spin" weight="duotone" />
    </div>
  )
}
