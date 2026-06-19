import { useMutation } from "@connectrpc/connect-query"
import { type FormEvent, useState } from "react"
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
import {
  requestMfaCode,
  skipPendingChallenge,
  verifyMfa,
} from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import type { Session } from "@/gen/rustylink/daemon/v1/session_pb"
import { useApplySession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { useAuthScratch } from "./auth-context"
import { AuthShell } from "./auth-shell"

export function MfaStep({ session }: { session: Session }) {
  const challenge = session.mfaChallenge
  const { account, password } = useAuthScratch()
  const applySession = useApplySession()
  const authList = challenge?.authList ?? []
  const [method, setMethod] = useState(
    challenge?.mfaType || authList[0] || "otp"
  )
  const [code, setCode] = useState("")
  const isPassword = method === "password"

  const onError = (err: unknown) => toast.error(errorMessage(err))
  const verify = useMutation(verifyMfa, {
    onSuccess: (res) => res.session && applySession(res.session),
    onError,
  })
  const sendCode = useMutation(requestMfaCode, {
    onSuccess: () => toast.success("A new code has been sent"),
    onError,
  })
  const skip = useMutation(skipPendingChallenge, {
    onSuccess: (res) => res.session && applySession(res.session),
    onError,
  })

  const onSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    verify.mutate({
      mfaType: method,
      account,
      code: isPassword ? undefined : code,
      password: isPassword ? password : undefined,
    })
  }

  return (
    <AuthShell
      tenant={session.tenantName}
      title="Multi-factor authentication"
      description="Confirm your identity to finish signing in."
    >
      <form className="space-y-4" onSubmit={onSubmit}>
        {authList.length > 1 ? (
          <div className="space-y-2">
            <Label htmlFor="mfa-method">Method</Label>
            <Select value={method} onValueChange={(v) => setMethod(v ?? "")}>
              <SelectTrigger id="mfa-method" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {authList.map((item) => (
                  <SelectItem key={item} value={item}>
                    {item}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        ) : null}

        {isPassword ? (
          <p className="text-muted-foreground text-sm">
            Your account password will be used to confirm this challenge.
          </p>
        ) : (
          <div className="space-y-2">
            <Label htmlFor="mfa-code">Code</Label>
            <Input
              id="mfa-code"
              autoFocus
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
          </div>
        )}

        <Button
          type="submit"
          className="w-full"
          disabled={verify.isPending || (!isPassword && !code)}
        >
          {verify.isPending ? "Verifying…" : "Verify"}
        </Button>

        {!isPassword ? (
          <Button
            type="button"
            variant="ghost"
            className="w-full"
            disabled={sendCode.isPending}
            onClick={() => sendCode.mutate({ mfaType: method, account })}
          >
            {sendCode.isPending ? "Sending…" : "Send a code"}
          </Button>
        ) : null}

        {challenge?.canSkip ? (
          <Button
            type="button"
            variant="ghost"
            className="text-muted-foreground w-full"
            disabled={skip.isPending}
            onClick={() => skip.mutate({})}
          >
            Skip for now
          </Button>
        ) : null}
      </form>
    </AuthShell>
  )
}
