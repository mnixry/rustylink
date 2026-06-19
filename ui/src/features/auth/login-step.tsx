import { useMutation, useQuery } from "@connectrpc/connect-query"
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
  startThirdPartyLogin,
  verifyLoginCode,
} from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import type { Session } from "@/gen/rustylink/daemon/v1/session_pb"
import { useApplySession, useRefreshSession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { useAuthScratch } from "./auth-context"
import { AuthShell } from "./auth-shell"

// The daemon builds OAuth authorize URLs whose redirect targets the app's
// custom scheme (corplink://). Browsers can't follow that, so the user copies
// the code from the redirected URL and pastes it on the OAuth step.
const REDIRECT_URI = "corplink://login/callback"

export function LoginStep({ session }: { session: Session }) {
  const applySession = useApplySession()
  const refreshSession = useRefreshSession()
  const { account, password, setAccount, setPassword } = useAuthScratch()
  const [codeType, setCodeType] = useState("mobile")
  const [code, setCode] = useState("")

  const onError = (err: unknown) => toast.error(errorMessage(err))
  const onSession = (s?: Session) => s && applySession(s)

  const loginMut = useMutation(login, {
    onSuccess: (res) => onSession(res.session),
    onError,
  })
  const sendCodeMut = useMutation(requestLoginCode, {
    onSuccess: () => toast.success("Verification code sent"),
    onError,
  })
  const verifyCodeMut = useMutation(verifyLoginCode, {
    onSuccess: (res) => onSession(res.session),
    onError,
  })
  const oauthMut = useMutation(startThirdPartyLogin, {
    onSuccess: async (res) => {
      if (res.authUrl) {
        window.open(res.authUrl, "_blank", "noopener")
      }
      // StartThirdPartyLogin returns no session; refetch to reach AWAITING_OAUTH.
      await refreshSession()
    },
    onError,
  })

  const providers = useQuery(listThirdPartyProviders, {})
  const providerList = providers.data?.providers ?? []

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
              disabled={loginMut.isPending || !account || !password}
            >
              {loginMut.isPending ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </TabsContent>

        <TabsContent value="code" className="space-y-4 pt-4">
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
              onValueChange={(v) => setCodeType(v ?? "mobile")}
            >
              <SelectTrigger id="code-type" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="mobile">Text message (SMS)</SelectItem>
                <SelectItem value="email">Email</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="code-input">Verification code</Label>
            <div className="flex gap-2">
              <Input
                id="code-input"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
              <Button
                type="button"
                variant="outline"
                disabled={sendCodeMut.isPending || !account}
                onClick={() =>
                  sendCodeMut.mutate({
                    account,
                    loginType: codeType,
                    accountType: codeType,
                  })
                }
              >
                {sendCodeMut.isPending ? "Sending…" : "Send code"}
              </Button>
            </div>
          </div>
          <Button
            type="button"
            className="w-full"
            disabled={verifyCodeMut.isPending || !account || !code}
            onClick={() =>
              verifyCodeMut.mutate({
                account,
                code,
                loginType: codeType,
                accountType: codeType,
              })
            }
          >
            {verifyCodeMut.isPending ? "Signing in…" : "Sign in"}
          </Button>
        </TabsContent>
      </Tabs>

      {providerList.length > 0 ? (
        <div className="mt-6 space-y-3">
          <div className="flex items-center gap-3">
            <Separator className="flex-1" />
            <span className="text-muted-foreground text-xs">
              or continue with
            </span>
            <Separator className="flex-1" />
          </div>
          <div className="grid gap-2">
            {providerList.map((provider) => (
              <Button
                key={provider.aliasKey}
                variant="outline"
                disabled={oauthMut.isPending}
                onClick={() =>
                  oauthMut.mutate({
                    aliasKey: provider.aliasKey,
                    redirectUri: REDIRECT_URI,
                  })
                }
              >
                {provider.name || provider.aliasKey}
              </Button>
            ))}
          </div>
        </div>
      ) : null}
    </AuthShell>
  )
}
