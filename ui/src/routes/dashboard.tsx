import { Navigate } from "react-router"
import { FullScreenLoader } from "@/components/full-screen-loader"
import { Session_State } from "@/gen/rustylink/daemon/v1/session_pb"
import { useSession } from "@/hooks/use-session"

export function DashboardRoute() {
  const { data, isLoading } = useSession()

  if (isLoading || !data?.session) {
    return <FullScreenLoader />
  }
  if (data.session.state !== Session_State.AUTHENTICATED) {
    return <Navigate to="/auth" replace />
  }

  // Placeholder — replaced by the VPN dashboard in the next stage.
  return (
    <div className="flex min-h-svh items-center justify-center p-6 text-muted-foreground">
      Dashboard
    </div>
  )
}
