import { useMutation, useQuery } from "@connectrpc/connect-query"
import { QrCodeIcon } from "@phosphor-icons/react"
import { useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  listThirdPartyProviders,
  login,
  requestLoginCode,
  startDeviceLogin,
  startThirdPartyLogin,
} from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import type { Session } from "@/gen/rustylink/daemon/v1/session_pb"
import { useApplySession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { useAuthScratch } from "./auth-context"
import { AuthShell } from "./auth-shell"

export function LoginStep({ session }: { session: Session }) {
  const applySession = useApplySession()
  const { account, password, setAccount, setPassword } = useAuthScratch()
  const [codeType, setCodeType] = useState("sms")

  const onSession = (s?: Session) => {
    if (s) {
      applySession(s)
    }
  }
  const onError = (err: unknown) => toast.error(errorMessage(err))

  const loginMut = useMutation(login, {
    onSuccess: (res) => onSession(res.session),
    onError,
  })
  const codeMut = useMutation(requestLoginCode, {
    onSuccess: () => toast.success("Verification code requested"),
    onError,
  })
  const oauthMut = useMutation(startThirdPartyLogin, {
    onSuccess: (res) => {
      if (res.authUrl) {
        window.open(res.authUrl, "_blank", "noopener")
      }
    },
    onError,
  })
  const deviceMut = useMutation(startDeviceLogin, {
    onSuccess: (res) => onSession(res.session),
    onError,
  })

  const providers = useQuery(listThirdPartyProviders, {})

  const pollProvider = providers.data?.providers.find((p) => p.supportsPoll)
  const pending = loginMut.isPending || codeMut.isPending

  return (
    <AuthShell
      tenant={session.tenantName}
      title="Sign in"
      description="Authenticate to your VPN tenant."
    >
      <Tabs defaultValue="password" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="password">Password</TabsTrigger>
          <TabsTrigger value="code">Verification code</TabsTrigger>
        </TabsList>

        <TabsContent value="password" className="space-y-4 pt-4">
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              loginMut.mutate({ account, password })
            }}
          >
            <div className="space-y-2">
              <Label htmlFor="account">Account</Label>
              <Input
                id="account"
                autoFocus
                placeholder="username, email, or phone"
                value={account}
                onChange={(e) => setAccount(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <Button
              type="submit"
              className="w-full"
              disabled={pending || !account || !password}
            >
              {loginMut.isPending ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </TabsContent>

        <TabsContent value="code" className="space-y-4 pt-4">
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              codeMut.mutate({ account, loginType: codeType })
            }}
          >
            <div className="space-y-2">
              <Label htmlFor="code-account">Account</Label>
              <Input
                id="code-account"
                placeholder="email or phone"
                value={account}
                onChange={(e) => setAccount(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="code-type">Delivery</Label>
              <Select
                value={codeType}
                onValueChange={(v) => setCodeType(v ?? "sms")}
              >
                <SelectTrigger id="code-type" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="sms">Text message (SMS)</SelectItem>
                  <SelectItem value="email">Email</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button
              type="submit"
              className="w-full"
              disabled={pending || !account}
            >
              {codeMut.isPending ? "Sending…" : "Send code"}
            </Button>
          </form>
        </TabsContent>
      </Tabs>

      {providers.data && providers.data.providers.length > 0 ? (
        <div className="mt-6 space-y-3">
          <div className="flex items-center gap-3">
            <Separator className="flex-1" />
            <span className="text-muted-foreground text-xs">
              or continue with
            </span>
            <Separator className="flex-1" />
          </div>
          <div className="grid gap-2">
            {providers.data.providers.map((provider) => (
              <Button
                key={provider.aliasKey}
                variant="outline"
                disabled={oauthMut.isPending}
                onClick={() =>
                  oauthMut.mutate({
                    aliasKey: provider.aliasKey,
                    redirectUri: `${window.location.origin}/auth`,
                  })
                }
              >
                {provider.name || provider.aliasKey}
              </Button>
            ))}
          </div>
          {pollProvider ? (
            <Button
              variant="ghost"
              className="w-full"
              disabled={deviceMut.isPending}
              onClick={() =>
                deviceMut.mutate({ aliasKey: pollProvider.aliasKey })
              }
            >
              <QrCodeIcon className="size-4" weight="duotone" />
              Sign in with a QR code
            </Button>
          ) : null}
        </div>
      ) : null}
    </AuthShell>
  )
}
