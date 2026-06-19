import type { ReactNode } from "react"
import { Navigate } from "react-router"
import { hasToken } from "@/lib/token"

// Gate that requires a stored daemon token. Session-state gating (authenticated
// vs. mid-auth) is layered on top of this by the auth wizard.
export function RequireToken({ children }: { children: ReactNode }) {
  if (!hasToken()) {
    return <Navigate to="/setup" replace />
  }
  return children
}
