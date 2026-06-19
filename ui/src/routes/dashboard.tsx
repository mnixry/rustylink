import { Navigate } from "react-router"
import { AppHeader } from "@/components/app-header"
import { FullScreenLoader } from "@/components/full-screen-loader"
import { ConnectCard } from "@/features/vpn/connect-card"
import { LocationsSection } from "@/features/vpn/locations-section"
import { Session_State } from "@/gen/rustylink/daemon/v1/session_pb"
import { useSession } from "@/hooks/use-session"
import { useWatchTunnel } from "@/hooks/use-tunnel"

export function DashboardRoute() {
  const { data, isLoading } = useSession()

  if (isLoading || !data?.session) {
    return <FullScreenLoader />
  }
  if (data.session.state !== Session_State.AUTHENTICATED) {
    return <Navigate to="/auth" replace />
  }
  return <Dashboard />
}

function Dashboard() {
  // Subscribe to live tunnel state for the whole dashboard.
  useWatchTunnel()

  return (
    <div className="min-h-svh bg-background">
      <AppHeader />
      <main className="mx-auto max-w-3xl space-y-6 px-4 py-6">
        <ConnectCard />
        <LocationsSection />
      </main>
    </div>
  )
}
