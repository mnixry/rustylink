import { Navigate } from "react-router"
import { FullScreenLoader } from "@/components/full-screen-loader"
import { AuthWizard } from "@/features/auth/auth-wizard"
import { Session_State } from "@/gen/rustylink/daemon/v1/session_pb"
import { useSession } from "@/hooks/use-session"

export function AuthRoute() {
  const { data, isLoading } = useSession()

  if (isLoading || !data?.session) {
    return <FullScreenLoader />
  }
  if (data.session.state === Session_State.AUTHENTICATED) {
    return <Navigate to="/" replace />
  }
  return <AuthWizard session={data.session} />
}
