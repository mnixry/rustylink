import { Code, ConnectError, type Interceptor } from "@connectrpc/connect"
import { createConnectTransport } from "@connectrpc/connect-web"
import { clearToken, getToken } from "./token"

const SETUP_PATH = "/setup"

// Attach the bearer token to every request. On an Unauthenticated response
// (the daemon returns 401 for a missing/invalid token), drop the stored token
// and bounce back to the setup screen so the user can re-enter it.
const authInterceptor: Interceptor = (next) => async (req) => {
  const token = getToken()
  if (token) {
    req.header.set("Authorization", `Bearer ${token}`)
  }
  try {
    return await next(req)
  } catch (err) {
    if (err instanceof ConnectError && err.code === Code.Unauthenticated) {
      clearToken()
      if (window.location.pathname !== SETUP_PATH) {
        window.location.assign(SETUP_PATH)
      }
    }
    throw err
  }
}

// Same-origin: dev proxies /api to the daemon (vite.config.ts); prod serves the
// SPA and /api from the daemon itself (rust-embed), so this works unchanged.
export const transport = createConnectTransport({
  baseUrl: "/api",
  interceptors: [authInterceptor],
})
