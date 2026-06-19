import { useMutation, useQuery } from "@connectrpc/connect-query"
import { type ReactElement, useEffect, useState } from "react"
import { toast } from "sonner"
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
} from "@/gen/rustylink/daemon/v1/daemon-VpnService_connectquery"
import { ProtocolMode, VpnMode } from "@/gen/rustylink/daemon/v1/types_pb"
import { useApplyTunnel } from "@/hooks/use-tunnel"
import { errorMessage } from "@/lib/errors"
import { PROTOCOL_MODES, VPN_MODES } from "./vpn-utils"

export function ConnectDialog({
  trigger,
  defaultLocationId,
}: {
  trigger: ReactElement
  defaultLocationId?: number
}) {
  const [open, setOpen] = useState(false)
  const [mode, setMode] = useState<VpnMode>(VpnMode.FULL)
  const [protocol, setProtocol] = useState<ProtocolMode>(ProtocolMode.AUTO)
  const [locationId, setLocationId] = useState<string>("")
  const [otp, setOtp] = useState("")
  const [reconnect, setReconnect] = useState(true)

  const locations = useQuery(listVpnLocations, {}, { enabled: open })
  const applyTunnel = useApplyTunnel()

  useEffect(() => {
    if (!open) {
      return
    }
    if (defaultLocationId !== undefined) {
      setLocationId(String(defaultLocationId))
    } else if (!locationId && locations.data?.locations[0]) {
      setLocationId(String(locations.data.locations[0].id))
    }
  }, [open, defaultLocationId, locations.data, locationId])

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

  const onConnect = () => {
    if (!locationId) {
      toast.error("Choose a location")
      return
    }
    connect.mutate({
      mode,
      protocolMode: protocol,
      exportId: Number(locationId),
      otp: otp ? otp : undefined,
      reconnect,
    })
  }

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

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="location">Location</Label>
            <Select
              value={locationId}
              onValueChange={(v) => setLocationId(v ?? "")}
            >
              <SelectTrigger id="location" className="w-full">
                <SelectValue
                  placeholder={
                    locations.isLoading ? "Loading…" : "Select a location"
                  }
                />
              </SelectTrigger>
              <SelectContent>
                {locations.data?.locations.map((loc) => (
                  <SelectItem key={loc.id} value={String(loc.id)}>
                    {loc.displayName || loc.name}
                    {loc.delayMs > 0 ? ` · ${loc.delayMs}ms` : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label htmlFor="mode">Mode</Label>
              <Select
                value={String(mode)}
                onValueChange={(v) => setMode(Number(v) as VpnMode)}
              >
                <SelectTrigger id="mode" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {VPN_MODES.map((m) => (
                    <SelectItem key={m.value} value={String(m.value)}>
                      {m.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="protocol">Protocol</Label>
              <Select
                value={String(protocol)}
                onValueChange={(v) => setProtocol(Number(v) as ProtocolMode)}
              >
                <SelectTrigger id="protocol" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROTOCOL_MODES.map((p) => (
                    <SelectItem key={p.value} value={String(p.value)}>
                      {p.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="otp">One-time code (if required)</Label>
            <Input
              id="otp"
              inputMode="numeric"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
            />
          </div>

          <div className="flex items-center justify-between">
            <Label htmlFor="reconnect">Auto-reconnect</Label>
            <Switch
              id="reconnect"
              checked={reconnect}
              onCheckedChange={setReconnect}
            />
          </div>
        </div>

        <DialogFooter>
          <Button onClick={onConnect} disabled={connect.isPending}>
            {connect.isPending ? "Connecting…" : "Connect"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
