import { useMutation, useQuery } from "@connectrpc/connect-query"
import { standardSchemaResolver } from "@hookform/resolvers/standard-schema"
import { type ReactElement, useEffect, useMemo, useState } from "react"
import { Controller, useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import {
  connectTunnel,
  listVpnLocations,
  probeDotLatency,
} from "@/gen/rustylink/daemon/v1/daemon-VpnService_connectquery"
import type { VpnLocation } from "@/gen/rustylink/daemon/v1/tunnel_pb"
import { ProtocolMode, VpnMode } from "@/gen/rustylink/daemon/v1/types_pb"
import { useApplyTunnel } from "@/hooks/use-tunnel"
import { errorMessage } from "@/lib/errors"
import {
  PROTOCOL_MODES,
  protocolModeLabel,
  VPN_MODES,
  vpnModeLabel,
} from "./vpn-utils"

// Sentinel location value: let the daemon pick the lowest-latency node.
const AUTO = "auto"

const schema = z.object({
  locationId: z.string().min(1, "Choose a location"),
  mode: z.number(),
  protocol: z.number(),
  otp: z.string(),
  reconnect: z.boolean(),
})
type Values = z.infer<typeof schema>

/// Protocols the picked location accepts. When `Auto` is the location, every
/// real protocol is allowed because the daemon may land on any dot.
function supportedProtocolsFor(
  locationId: string,
  locations: VpnLocation[] | undefined
): Set<ProtocolMode> {
  if (locationId === AUTO || !locations) {
    return new Set(PROTOCOL_MODES.map((p) => p.value))
  }
  const dot = locations.find((l) => String(l.id) === locationId)
  if (!dot || dot.supportedProtocols.length === 0) {
    return new Set(PROTOCOL_MODES.map((p) => p.value))
  }
  return new Set(dot.supportedProtocols)
}

export function ConnectDialog({
  trigger,
  defaultLocationId,
}: {
  trigger: ReactElement
  defaultLocationId?: number
}) {
  const [open, setOpen] = useState(false)
  const locations = useQuery(listVpnLocations, {}, { enabled: open })
  const applyTunnel = useApplyTunnel()

  const { control, register, handleSubmit, setValue, watch } = useForm<Values>({
    resolver: standardSchemaResolver(schema),
    defaultValues: {
      locationId: AUTO,
      mode: VpnMode.FULL,
      protocol: ProtocolMode.UDP,
      otp: "",
      reconnect: true,
    },
  })

  useEffect(() => {
    if (open && defaultLocationId !== undefined) {
      setValue("locationId", String(defaultLocationId))
    }
  }, [open, defaultLocationId, setValue])

  const locationId = watch("locationId")
  const protocol = watch("protocol")
  const supported = useMemo(
    () => supportedProtocolsFor(locationId, locations.data?.locations),
    [locationId, locations.data?.locations]
  )

  // Snap the protocol to a supported one whenever the dot changes (e.g. user
  // had UDP picked, then chose a TCP-only dot).
  useEffect(() => {
    if (!supported.has(protocol as ProtocolMode)) {
      const fallback = PROTOCOL_MODES.find((p) => supported.has(p.value))
      if (fallback) {
        setValue("protocol", fallback.value)
      }
    }
  }, [supported, protocol, setValue])

  const probe = useMutation(probeDotLatency)
  const connect = useMutation(connectTunnel, {
    onSuccess: (res) => {
      if (res.tunnel) {
        applyTunnel(res.tunnel)
      }
      setOpen(false)
      toast.success("Connecting…")
    },
    onError: (err) => toast.error(errorMessage(err)),
  })

  // For "Auto", probe latency and pick the fastest reachable node; otherwise
  // use the chosen location. (The daemon also latency-ranks nodes, but this
  // lets the user pick the export region with the best round-trip.)
  const onConnect = handleSubmit(async (values) => {
    let exportId: number
    if (values.locationId === AUTO) {
      try {
        const res = await probe.mutateAsync({})
        const best = res.results
          .filter((r) => r.reachable)
          .sort((a, b) => a.latencyMs - b.latencyMs)[0]
        if (!best) {
          toast.error("No reachable location found")
          return
        }
        exportId = best.dotId
      } catch (err) {
        toast.error(errorMessage(err))
        return
      }
    } else {
      exportId = Number(values.locationId)
    }
    connect.mutate({
      mode: values.mode as VpnMode,
      protocolMode: values.protocol as ProtocolMode,
      exportId,
      otp: values.otp ? values.otp : undefined,
      reconnect: values.reconnect,
    })
  })

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={trigger} />
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Connect VPN</DialogTitle>
          <DialogDescription>
            Choose a location and tunnel options.
          </DialogDescription>
        </DialogHeader>

        <form className="space-y-4" onSubmit={onConnect}>
          <div className="space-y-2">
            <Label htmlFor="location">Location</Label>
            <Controller
              control={control}
              name="locationId"
              render={({ field }) => (
                <Select value={field.value} onValueChange={field.onChange}>
                  <SelectTrigger id="location" className="w-full">
                    <SelectValue
                      placeholder={
                        locations.isLoading ? "Loading…" : "Select a location"
                      }
                    >
                      {(value) => {
                        if (value === AUTO) {
                          return "Auto (lowest latency)"
                        }
                        const loc = locations.data?.locations.find(
                          (l) => String(l.id) === value
                        )
                        if (!loc) {
                          return locations.isLoading
                            ? "Loading…"
                            : "Select a location"
                        }
                        return loc.displayName || loc.name
                      }}
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={AUTO}>Auto (lowest latency)</SelectItem>
                    {locations.data?.locations.map((loc) => (
                      <SelectItem key={loc.id} value={String(loc.id)}>
                        {loc.displayName || loc.name}
                        {loc.delayMs > 0 ? ` · ${loc.delayMs}ms` : ""}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label htmlFor="mode">Mode</Label>
              <Controller
                control={control}
                name="mode"
                render={({ field }) => (
                  <Select
                    value={String(field.value)}
                    onValueChange={(v) => field.onChange(Number(v))}
                  >
                    <SelectTrigger id="mode" className="w-full">
                      <SelectValue>
                        {(value) => vpnModeLabel(Number(value) as VpnMode)}
                      </SelectValue>
                    </SelectTrigger>
                    <SelectContent>
                      {VPN_MODES.map((m) => (
                        <SelectItem key={m.value} value={String(m.value)}>
                          {m.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="protocol">Protocol</Label>
              <Controller
                control={control}
                name="protocol"
                render={({ field }) => (
                  <Select
                    value={String(field.value)}
                    onValueChange={(v) => field.onChange(Number(v))}
                  >
                    <SelectTrigger id="protocol" className="w-full">
                      <SelectValue>
                        {(value) =>
                          protocolModeLabel(Number(value) as ProtocolMode)
                        }
                      </SelectValue>
                    </SelectTrigger>
                    <SelectContent>
                      {PROTOCOL_MODES.map((p) => {
                        const enabled = supported.has(p.value)
                        return (
                          <SelectItem
                            key={p.value}
                            value={String(p.value)}
                            disabled={!enabled}
                          >
                            {p.label}
                            {enabled ? "" : " · unavailable"}
                          </SelectItem>
                        )
                      })}
                    </SelectContent>
                  </Select>
                )}
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="otp">One-time code (if required)</Label>
            <Input id="otp" inputMode="numeric" {...register("otp")} />
          </div>

          <div className="flex items-center justify-between">
            <Label htmlFor="reconnect">Auto-reconnect</Label>
            <Controller
              control={control}
              name="reconnect"
              render={({ field }) => (
                <Switch
                  id="reconnect"
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
              )}
            />
          </div>

          <DialogFooter>
            <Button
              type="submit"
              disabled={connect.isPending || probe.isPending}
            >
              {probe.isPending
                ? "Measuring latency…"
                : connect.isPending
                  ? "Connecting…"
                  : "Connect"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
