import { QueryClient } from "@tanstack/react-query"

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The daemon is local; avoid noisy refetches and keep results briefly.
      staleTime: 5_000,
      refetchOnWindowFocus: false,
      retry: false,
    },
  },
})
