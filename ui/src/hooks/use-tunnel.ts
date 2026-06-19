import { create } from "@bufbuild/protobuf"
import { createClient } from "@connectrpc/connect"
import {
  createConnectQueryKey,
  useQuery,
  useTransport,
} from "@connectrpc/connect-query"
import { useQueryClient } from "@tanstack/react-query"
import { useEffect } from "react"
import { VpnService } from "@/gen/rustylink/daemon/v1/daemon_pb"
import { getTunnel } from "@/gen/rustylink/daemon/v1/daemon-VpnService_connectquery"
import {
  GetTunnelResponseSchema,
  type Tunnel,
} from "@/gen/rustylink/daemon/v1/tunnel_pb"

export function useTunnel() {
  return useQuery(getTunnel, {})
}

// Write a Tunnel into the GetTunnel cache (used by ConnectTunnel/DisconnectTunnel
// responses and by the WatchTunnel stream below).
export function useApplyTunnel() {
  const queryClient = useQueryClient()
  const transport = useTransport()
  return (tunnel: Tunnel) => {
    const queryKey = createConnectQueryKey({
      schema: getTunnel,
      transport,
      input: {},
      cardinality: "finite",
    })
    queryClient.setQueryData(
      queryKey,
      create(GetTunnelResponseSchema, { tunnel })
    )
  }
}

// Subscribe to the server-streaming WatchTunnel RPC and pump every update into
// the GetTunnel query cache, so all components read live state via useTunnel().
// Reconnects with capped exponential backoff if the stream drops.
export function useWatchTunnel() {
  const transport = useTransport()
  const queryClient = useQueryClient()

  useEffect(() => {
    const abort = new AbortController()
    let stopped = false
    const queryKey = createConnectQueryKey({
      schema: getTunnel,
      transport,
      input: {},
      cardinality: "finite",
    })

    const run = async () => {
      const client = createClient(VpnService, transport)
      let backoff = 1000
      while (!stopped) {
        try {
          for await (const res of client.watchTunnel(
            {},
            { signal: abort.signal }
          )) {
            if (res.tunnel) {
              queryClient.setQueryData(
                queryKey,
                create(GetTunnelResponseSchema, { tunnel: res.tunnel })
              )
            }
            backoff = 1000
          }
        } catch {
          // fall through to backoff + reconnect
        }
        if (stopped) {
          break
        }
        await new Promise((resolve) => setTimeout(resolve, backoff))
        backoff = Math.min(backoff * 2, 15000)
      }
    }

    void run()
    return () => {
      stopped = true
      abort.abort()
    }
  }, [transport, queryClient])
}
