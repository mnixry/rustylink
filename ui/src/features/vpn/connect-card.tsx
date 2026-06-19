import { timestampDate } from "@bufbuild/protobuf/wkt"
import { useMutation } from "@connectrpc/connect-query"
import { PlugsConnectedIcon, PowerIcon } from "@phosphor-icons/react"
import { toast } from "sonner"
import { StatusBadge } from "@/components/status-badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { disconnectTunnel } from "@/gen/rustylink/daemon/v1/daemon-VpnService_connectquery"
import { Tunnel_State } from "@/gen/rustylink/daemon/v1/tunnel_pb"
import { useApplyTunnel, useTunnel } from "@/hooks/use-tunnel"
import { errorMessage } from "@/lib/errors"
import { ConnectDialog } from "./connect-dialog"
import {
  isActive,
  protocolModeLabel,
  tunnelStateLabel,
  tunnelStateTone,
  vpnModeLabel,
} from "./vpn-utils"

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 py-1.5 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono">{value}</span>
    </div>
  )
}

export function ConnectCard() {
  const { data } = useTunnel()
  const applyTunnel = useApplyTunnel()
  const tunnel = data?.tunnel
  const state = tunnel?.state ?? Tunnel_State.DISCONNECTED
  const active = isActive(state)

  const disconnect = useMutation(disconnectTunnel, {
    onSuccess: (res) => res.tunnel && applyTunnel(res.tunnel),
    onError: (err) => toast.error(errorMessage(err)),
  })

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Connection</CardTitle>
        <StatusBadge
          tone={tunnelStateTone(state)}
          label={tunnelStateLabel(state)}
        />
      </CardHeader>
      <CardContent>
        {tunnel && active ? (
          <div className="divide-border divide-y">
            {tunnel.dotName ? (
              <Detail label="Location" value={tunnel.dotName} />
            ) : null}
            <Detail label="Mode" value={vpnModeLabel(tunnel.mode)} />
            <Detail
              label="Protocol"
              value={protocolModeLabel(tunnel.protocolMode)}
            />
            {tunnel.assignedIp ? (
              <Detail label="Assigned IP" value={tunnel.assignedIp} />
            ) : null}
            {tunnel.endpoint ? (
              <Detail label="Endpoint" value={tunnel.endpoint} />
            ) : null}
            {tunnel.connectedAt ? (
              <Detail
                label="Connected"
                value={timestampDate(tunnel.connectedAt).toLocaleString()}
              />
            ) : null}
            {tunnel.lastHandshakeAt ? (
              <Detail
                label="Last handshake"
                value={timestampDate(
                  tunnel.lastHandshakeAt
                ).toLocaleTimeString()}
              />
            ) : null}
          </div>
        ) : (
          <p className="text-muted-foreground text-sm">
            You are not connected to the VPN.
          </p>
        )}

        {state === Tunnel_State.FAILED && tunnel?.error ? (
          <p className="text-destructive mt-3 text-sm">{tunnel.error}</p>
        ) : null}
      </CardContent>
      <CardFooter>
        {active ? (
          <Button
            variant="destructive"
            className="w-full"
            disabled={disconnect.isPending}
            onClick={() => disconnect.mutate({})}
          >
            <PowerIcon className="size-4" weight="duotone" />
            Disconnect
          </Button>
        ) : (
          <ConnectDialog
            trigger={
              <Button className="w-full">
                <PlugsConnectedIcon className="size-4" weight="duotone" />
                Connect
              </Button>
            }
          />
        )}
      </CardFooter>
    </Card>
  )
}
