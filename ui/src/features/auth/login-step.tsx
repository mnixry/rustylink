import { useMutation, useQuery } from "@connectrpc/connect-query"
import { standardSchemaResolver } from "@hookform/resolvers/standard-schema"
import { Controller, useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"
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
  verifyLoginCode,
} from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import type { Session } from "@/gen/rustylink/daemon/v1/session_pb"
import { LoginCodeType } from "@/gen/rustylink/daemon/v1/types_pb"
import { useApplySession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { useAuthScratch } from "./auth-context"
import { AuthShell } from "./auth-shell"

const passwordSchema = z.object({
  account: z.string().trim().min(1, "Enter your account"),
  password: z.string().min(1, "Enter your password"),
})
const codeSchema = z.object({
  account: z.string().trim().min(1, "Enter your account"),
  codeType: z.enum(["mobile", "email"]),
  code: z.string().trim().min(1, "Enter the verification code"),
})
type PasswordValues = z.infer<typeof passwordSchema>
type CodeValues = z.infer<typeof codeSchema>

const codeTypeToEnum = (value: CodeValues["codeType"]) =>
  value === "email" ? LoginCodeType.EMAIL : LoginCodeType.MOBILE

export function LoginStep({ session }: { session: Session }) {
  const applySession = useApplySession()
  const { account, password, setAccount, setPassword } = useAuthScratch()

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
  // Third-party providers use the device/QR poll flow (corplink-rs style):
  // StartDeviceLogin returns an AWAITING_DEVICE_LOGIN session, advancing the
  // wizard to the QR step which polls until the user approves.
  const deviceMut = useMutation(startDeviceLogin, {
    onSuccess: (res) => onSession(res.session),
    onError,
  })

  const providers = useQuery(listThirdPartyProviders, {})
  const providerList = providers.data?.providers ?? []

  const pwForm = useForm<PasswordValues>({
    resolver: standardSchemaResolver(passwordSchema),
    defaultValues: { account, password },
  })
  const codeForm = useForm<CodeValues>({
    resolver: standardSchemaResolver(codeSchema),
    defaultValues: { account, codeType: "mobile", code: "" },
  })

  const onPasswordSubmit = pwForm.handleSubmit((values) => {
    setAccount(values.account)
    setPassword(values.password)
    loginMut.mutate({ account: values.account, password: values.password })
  })

  const onVerifySubmit = codeForm.handleSubmit((values) => {
    setAccount(values.account)
    verifyCodeMut.mutate({
      account: values.account,
      code: values.code,
      loginType: codeTypeToEnum(values.codeType),
      accountType: values.codeType,
    })
  })

  // "Send code" only needs a valid account; validate just that field.
  const onSendCode = async () => {
    if (!(await codeForm.trigger("account"))) {
      return
    }
    const { account: codeAccount, codeType } = codeForm.getValues()
    setAccount(codeAccount)
    sendCodeMut.mutate({
      account: codeAccount,
      loginType: codeTypeToEnum(codeType),
      accountType: codeType,
    })
  }

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
          <form className="space-y-4" onSubmit={onPasswordSubmit}>
            <div className="space-y-2">
              <Label htmlFor="account">Account</Label>
              <Input
                id="account"
                autoFocus
                placeholder="username, email, or phone"
                {...pwForm.register("account")}
              />
              {pwForm.formState.errors.account ? (
                <p className="text-destructive text-sm">
                  {pwForm.formState.errors.account.message}
                </p>
              ) : null}
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                {...pwForm.register("password")}
              />
              {pwForm.formState.errors.password ? (
                <p className="text-destructive text-sm">
                  {pwForm.formState.errors.password.message}
                </p>
              ) : null}
            </div>
            <Button
              type="submit"
              className="w-full"
              disabled={loginMut.isPending}
            >
              {loginMut.isPending ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </TabsContent>

        <TabsContent value="code" className="space-y-4 pt-4">
          <form className="space-y-4" onSubmit={onVerifySubmit}>
            <div className="space-y-2">
              <Label htmlFor="code-account">Account</Label>
              <Input
                id="code-account"
                placeholder="email or phone"
                {...codeForm.register("account")}
              />
              {codeForm.formState.errors.account ? (
                <p className="text-destructive text-sm">
                  {codeForm.formState.errors.account.message}
                </p>
              ) : null}
            </div>
            <div className="space-y-2">
              <Label htmlFor="code-type">Delivery</Label>
              <Controller
                control={codeForm.control}
                name="codeType"
                render={({ field }) => (
                  <Select
                    value={field.value}
                    onValueChange={(v) => field.onChange(v ?? "mobile")}
                  >
                    <SelectTrigger id="code-type" className="w-full">
                      <SelectValue>
                        {(value) =>
                          value === "email" ? "Email" : "Text message (SMS)"
                        }
                      </SelectValue>
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="mobile">Text message (SMS)</SelectItem>
                      <SelectItem value="email">Email</SelectItem>
                    </SelectContent>
                  </Select>
                )}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="code-input">Verification code</Label>
              <div className="flex gap-2">
                <Input
                  id="code-input"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  {...codeForm.register("code")}
                />
                <Button
                  type="button"
                  variant="outline"
                  disabled={sendCodeMut.isPending}
                  onClick={onSendCode}
                >
                  {sendCodeMut.isPending ? "Sending…" : "Send code"}
                </Button>
              </div>
              {codeForm.formState.errors.code ? (
                <p className="text-destructive text-sm">
                  {codeForm.formState.errors.code.message}
                </p>
              ) : null}
            </div>
            <Button
              type="submit"
              className="w-full"
              disabled={verifyCodeMut.isPending}
            >
              {verifyCodeMut.isPending ? "Signing in…" : "Sign in"}
            </Button>
          </form>
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
                disabled={deviceMut.isPending}
                onClick={() =>
                  deviceMut.mutate({ aliasKey: provider.aliasKey })
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
