import { ConnectError } from "@connectrpc/connect"

// Human-readable message from a Connect/JS error for toasts and inline errors.
export function errorMessage(err: unknown): string {
  if (err instanceof ConnectError) {
    return err.message.replace(/^\[[a-z_]+\]\s*/i, "")
  }
  if (err instanceof Error) {
    return err.message
  }
  return String(err)
}
