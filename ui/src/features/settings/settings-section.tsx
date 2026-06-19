import { create, type MessageInitShape } from "@bufbuild/protobuf"
import {
  createConnectQueryKey,
  useMutation,
  useQuery,
  useTransport,
} from "@connectrpc/connect-query"
import { useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import {
  type Configuration,
  type ConfigurationSchema,
  GetConfigurationResponseSchema,
  type OutboundInterface,
} from "@/gen/rustylink/daemon/v1/configuration_pb"
import {
  getConfiguration,
  listNetworkInterfaces,
  updateConfiguration,
} from "@/gen/rustylink/daemon/v1/daemon-MetaService_connectquery"
import { errorMessage } from "@/lib/errors"

const AUTO = "__auto__"

function interfaceValue(iface?: OutboundInterface): string {
  if (iface?.selector.case === "name") {
    return iface.selector.value
  }
  return AUTO
}
function interfaceSelector(value: string) {
  return value === AUTO
    ? { case: "auto" as const, value: {} }
    : { case: "name" as const, value }
}
export function SettingsSection() {
  const config = useQuery(getConfiguration, {})
  const interfaces = useQuery(listNetworkInterfaces, {})
  const queryClient = useQueryClient()
  const transport = useTransport()

  const update = useMutation(updateConfiguration, {
    onSuccess: (res) => {
      if (res.configuration) {
        const key = createConnectQueryKey({
          schema: getConfiguration,
          transport,
          input: {},
          cardinality: "finite",
        })
        queryClient.setQueryData(
          key,
          create(GetConfigurationResponseSchema, {
            configuration: res.configuration,
          })
        )
      }
      toast.success("Settings saved")
    },
    onError: (err) => toast.error(errorMessage(err)),
  })

  const save = (
    configuration: MessageInitShape<typeof ConfigurationSchema>,
    paths: string[]
  ) => update.mutate({ configuration, updateMask: { paths } })

  if (config.isLoading || !config.data?.configuration) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </CardContent>
      </Card>
    )
  }

  const cfg = config.data.configuration
  const ifaceOptions = interfaces.data?.interfaces ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle>Settings</CardTitle>
        <CardDescription>Daemon configuration.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="flex items-center justify-between gap-4">
          <div>
            <Label htmlFor="auto-reconnect">Auto-reconnect on start</Label>
            <p className="text-muted-foreground text-xs">
              Re-establish the last tunnel when the daemon starts.
            </p>
          </div>
          <Switch
            id="auto-reconnect"
            checked={cfg.autoReconnectOnStart}
            disabled={update.isPending}
            onCheckedChange={(checked) =>
              save({ autoReconnectOnStart: checked }, [
                "auto_reconnect_on_start",
              ])
            }
          />
        </div>

        <Separator />

        <div className="grid gap-2">
          <Label>Outbound interface</Label>
          <Select
            value={interfaceValue(cfg.outboundInterface)}
            disabled={update.isPending}
            onValueChange={(v) =>
              save(
                {
                  outboundInterface: { selector: interfaceSelector(v ?? AUTO) },
                },
                ["outbound_interface"]
              )
            }
          >
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={AUTO}>
                Automatic
                {interfaces.data?.autoSelected
                  ? ` (${interfaces.data.autoSelected})`
                  : ""}
              </SelectItem>
              {ifaceOptions.map((iface) => (
                <SelectItem key={iface.name} value={iface.name}>
                  {iface.name}
                  {iface.ipv4Addrs[0] ? ` · ${iface.ipv4Addrs[0]}` : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="grid gap-2">
          <Label>DNS interface</Label>
          <Select
            value={interfaceValue(cfg.dnsInterface)}
            disabled={update.isPending}
            onValueChange={(v) =>
              save(
                { dnsInterface: { selector: interfaceSelector(v ?? AUTO) } },
                ["dns_interface"]
              )
            }
          >
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={AUTO}>Automatic</SelectItem>
              {ifaceOptions.map((iface) => (
                <SelectItem key={iface.name} value={iface.name}>
                  {iface.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {cfg.deviceIdentity ? (
          <>
            <Separator />
            <DeviceIdentityView identity={cfg.deviceIdentity} />
          </>
        ) : null}

        {cfg.securityReport && cfg.securityReport.items.length > 0 ? (
          <>
            <Separator />
            <SecurityReportView report={cfg.securityReport} />
          </>
        ) : null}
      </CardContent>
    </Card>
  )
}

function DeviceIdentityView({
  identity,
}: {
  identity: NonNullable<Configuration["deviceIdentity"]>
}) {
  const rows: [string, string | undefined][] = [
    ["OS", identity.os],
    ["OS version", identity.osVersion],
    ["App version", identity.appVersion],
    ["Brand", identity.brand],
    ["Model", identity.model],
    ["Device ID", identity.deviceId],
  ]
  return (
    <div className="space-y-1">
      <Label>Device identity</Label>
      <dl className="text-sm">
        {rows
          .filter(([, value]) => Boolean(value))
          .map(([label, value]) => (
            <div key={label} className="flex justify-between gap-4 py-1">
              <dt className="text-muted-foreground">{label}</dt>
              <dd className="truncate font-mono">{value}</dd>
            </div>
          ))}
      </dl>
    </div>
  )
}

function SecurityReportView({
  report,
}: {
  report: NonNullable<Configuration["securityReport"]>
}) {
  return (
    <div className="space-y-1">
      <Label>Security report</Label>
      <ul className="text-sm">
        {report.items.map((item) => (
          <li key={item.key} className="flex justify-between gap-4 py-1">
            <span className="text-muted-foreground">{item.key}</span>
            <span className="font-mono">level {item.level}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
