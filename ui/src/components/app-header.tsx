import { useMutation, useQuery } from "@connectrpc/connect-query"
import {
  CaretDownIcon,
  ShieldCheckIcon,
  SignOutIcon,
} from "@phosphor-icons/react"
import { StatusBadge } from "@/components/status-badge"
import { ThemeToggle } from "@/components/theme-toggle"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { tunnelStateLabel, tunnelStateTone } from "@/features/vpn/vpn-utils"
import { logout } from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import { ping } from "@/gen/rustylink/daemon/v1/daemon-MetaService_connectquery"
import { Tunnel_State } from "@/gen/rustylink/daemon/v1/tunnel_pb"
import { useApplySession } from "@/hooks/use-session"
import { useTunnel } from "@/hooks/use-tunnel"

export function AppHeader() {
  const { data } = useTunnel()
  const state = data?.tunnel?.state ?? Tunnel_State.DISCONNECTED
  const pingQuery = useQuery(ping, {})
  const applySession = useApplySession()
  const logoutMut = useMutation(logout, {
    onSuccess: (res) => res.session && applySession(res.session),
  })

  return (
    <header className="border-border bg-background/80 sticky top-0 z-10 border-b backdrop-blur">
      <div className="mx-auto flex max-w-3xl items-center justify-between gap-4 px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="bg-primary/10 text-primary flex size-8 items-center justify-center rounded-lg">
            <ShieldCheckIcon className="size-5" weight="duotone" />
          </div>
          <span className="font-semibold">RustyLink</span>
          <StatusBadge
            tone={tunnelStateTone(state)}
            label={tunnelStateLabel(state)}
          />
        </div>
        <div className="flex items-center gap-2">
          {pingQuery.data ? (
            <span className="text-muted-foreground hidden text-xs sm:inline">
              daemon v{pingQuery.data.version}
            </span>
          ) : null}
          <ThemeToggle />
          <DropdownMenu>
            <DropdownMenuTrigger render={<Button variant="ghost" size="sm" />}>
              Account
              <CaretDownIcon className="size-4" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem
                onClick={() => logoutMut.mutate({ logoutAll: false })}
              >
                <SignOutIcon className="size-4" weight="duotone" />
                Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  )
}
