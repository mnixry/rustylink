import { TransportProvider } from "@connectrpc/connect-query"
import { QueryClientProvider } from "@tanstack/react-query"
import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { RouterProvider } from "react-router"
import { ThemeProvider } from "@/components/theme-provider"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { queryClient } from "@/lib/query-client"
import { captureTokenFromUrl } from "@/lib/token"
import { transport } from "@/lib/transport"
import { router } from "@/router"
import "./index.css"

// Capture any `?token=…` from the daemon's startup URL before the router runs,
// so the token gate passes without manual entry.
captureTokenFromUrl()

const rootElement = document.getElementById("root")
if (!rootElement) {
  throw new Error("Root element #root not found")
}

createRoot(rootElement).render(
  <StrictMode>
    <ThemeProvider>
      <TransportProvider transport={transport}>
        <QueryClientProvider client={queryClient}>
          <TooltipProvider>
            <RouterProvider router={router} />
            <Toaster richColors closeButton />
          </TooltipProvider>
        </QueryClientProvider>
      </TransportProvider>
    </ThemeProvider>
  </StrictMode>
)
