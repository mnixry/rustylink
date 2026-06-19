import { useMutation, useQuery } from "@connectrpc/connect-query"
import { GaugeIcon } from "@phosphor-icons/react"
import { useState } from "react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import {
  listVpnLocations,
  probeDotLatency,
} from "@/gen/rustylink/daemon/v1/daemon-VpnService_connectquery"
import type { DotLatency } from "@/gen/rustylink/daemon/v1/tunnel_pb"
import { errorMessage } from "@/lib/errors"
import { ConnectDialog } from "./connect-dialog"

export function LocationsSection() {
  const locations = useQuery(listVpnLocations, {})
  const [latencies, setLatencies] = useState<Map<number, DotLatency>>(new Map())

  const probe = useMutation(probeDotLatency, {
    onSuccess: (res) => {
      setLatencies(new Map(res.results.map((r) => [r.dotId, r])))
      toast.success("Latency updated")
    },
    onError: (err) => toast.error(errorMessage(err)),
  })

  const items = locations.data?.locations ?? []

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Locations</CardTitle>
        <Button
          variant="outline"
          size="sm"
          disabled={probe.isPending || items.length === 0}
          onClick={() => probe.mutate({})}
        >
          <GaugeIcon className="size-4" weight="duotone" />
          {probe.isPending ? "Measuring…" : "Measure latency"}
        </Button>
      </CardHeader>
      <CardContent>
        {locations.isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : items.length === 0 ? (
          <p className="text-muted-foreground text-sm">
            No locations available.
          </p>
        ) : (
          <ul className="divide-border divide-y">
            {items.map((loc) => {
              const probed = latencies.get(loc.id)
              const latency = probed?.latencyMs ?? loc.delayMs
              const unreachable = probed && !probed.reachable
              return (
                <li
                  key={loc.id}
                  className="flex items-center justify-between gap-3 py-3"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-medium">
                        {loc.displayName || loc.name}
                      </span>
                      {loc.dedicated ? (
                        <Badge variant="secondary">Dedicated</Badge>
                      ) : null}
                      {loc.tag ? (
                        <Badge variant="outline">{loc.tag}</Badge>
                      ) : null}
                    </div>
                    <div className="text-muted-foreground text-xs">
                      {unreachable
                        ? "Unreachable"
                        : latency > 0
                          ? `${latency} ms`
                          : "—"}
                    </div>
                  </div>
                  <ConnectDialog
                    defaultLocationId={loc.id}
                    trigger={
                      <Button size="sm" variant="outline">
                        Connect
                      </Button>
                    }
                  />
                </li>
              )
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
