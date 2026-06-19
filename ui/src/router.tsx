import { createBrowserRouter } from "react-router"
import { RequireToken } from "@/components/require-token"
import { AuthRoute } from "@/routes/auth"
import { DashboardRoute } from "@/routes/dashboard"
import { SetupScreen } from "@/routes/setup"

export const router = createBrowserRouter([
  {
    path: "/setup",
    element: <SetupScreen />,
  },
  {
    path: "/auth",
    element: (
      <RequireToken>
        <AuthRoute />
      </RequireToken>
    ),
  },
  {
    path: "/",
    element: (
      <RequireToken>
        <DashboardRoute />
      </RequireToken>
    ),
  },
])
