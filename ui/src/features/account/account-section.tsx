import { useMutation, useQuery } from "@connectrpc/connect-query"
import { SignOutIcon, UserCircleIcon } from "@phosphor-icons/react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { logout } from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import { getUserInfo } from "@/gen/rustylink/daemon/v1/daemon-MetaService_connectquery"
import { useApplySession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"

export function AccountSection() {
  const user = useQuery(getUserInfo, {})
  const applySession = useApplySession()
  const logoutMut = useMutation(logout, {
    onSuccess: (res) => res.session && applySession(res.session),
    onError: (err) => toast.error(errorMessage(err)),
  })

  const info = user.data?.userInfo
  const rows: [string, string | undefined][] = [
    ["Name", info?.name],
    ["Email", info?.email],
    ["Mobile", info?.mobile],
    ["User ID", info?.uid],
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle>Account</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {user.isLoading ? (
          <Skeleton className="h-20 w-full" />
        ) : (
          <div className="flex items-start gap-3">
            <div className="bg-primary/10 text-primary flex size-10 items-center justify-center rounded-full">
              <UserCircleIcon className="size-6" weight="duotone" />
            </div>
            <dl className="min-w-0 flex-1 text-sm">
              {rows
                .filter(([, value]) => Boolean(value))
                .map(([label, value]) => (
                  <div key={label} className="flex justify-between gap-4 py-1">
                    <dt className="text-muted-foreground">{label}</dt>
                    <dd className="truncate">{value}</dd>
                  </div>
                ))}
            </dl>
          </div>
        )}

        <Separator />

        <div className="flex flex-col gap-2 sm:flex-row">
          <Button
            variant="outline"
            className="flex-1"
            disabled={logoutMut.isPending}
            onClick={() => logoutMut.mutate({ logoutAll: false })}
          >
            <SignOutIcon className="size-4" weight="duotone" />
            Sign out
          </Button>
          <Button
            variant="ghost"
            className="text-muted-foreground flex-1"
            disabled={logoutMut.isPending}
            onClick={() => logoutMut.mutate({ logoutAll: true })}
          >
            Sign out everywhere
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
