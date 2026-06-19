import { useMutation } from "@connectrpc/connect-query"
import { type FormEvent, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  requestLoginCode,
  verifyLoginCode,
} from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import type { Session } from "@/gen/rustylink/daemon/v1/session_pb"
import { useApplySession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { useAuthScratch } from "./auth-context"
import { AuthShell } from "./auth-shell"

export function OtpStep({ session }: { session: Session }) {
  const challenge = session.otpChallenge
  const { account } = useAuthScratch()
  const applySession = useApplySession()
  const [code, setCode] = useState("")
  const loginType = challenge?.loginType ?? ""

  const verify = useMutation(verifyLoginCode, {
    onSuccess: (res) => res.session && applySession(res.session),
    onError: (err) => toast.error(errorMessage(err)),
  })
  const resend = useMutation(requestLoginCode, {
    onSuccess: () => toast.success("A new code has been sent"),
    onError: (err) => toast.error(errorMessage(err)),
  })

  const onSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    verify.mutate({ account, code, loginType })
  }

  return (
    <AuthShell
      tenant={session.tenantName}
      title="Enter verification code"
      description={
        challenge?.maskedTarget
          ? `We sent a code to ${challenge.maskedTarget}.`
          : "Enter the code that was sent to you."
      }
    >
      <form className="space-y-4" onSubmit={onSubmit}>
        <div className="space-y-2">
          <Label htmlFor="otp">Verification code</Label>
          <Input
            id="otp"
            autoFocus
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
        </div>
        <Button
          type="submit"
          className="w-full"
          disabled={verify.isPending || !code}
        >
          {verify.isPending ? "Verifying…" : "Verify"}
        </Button>
        <Button
          type="button"
          variant="ghost"
          className="w-full"
          disabled={resend.isPending}
          onClick={() => resend.mutate({ account, loginType })}
        >
          {resend.isPending ? "Sending…" : "Resend code"}
        </Button>
      </form>
    </AuthShell>
  )
}
