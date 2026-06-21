import { useMutation } from "@connectrpc/connect-query"
import { standardSchemaResolver } from "@hookform/resolvers/standard-schema"
import { useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  requestLoginCode,
  verifyLoginCode,
} from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import type { Session } from "@/gen/rustylink/daemon/v1/session_pb"
import { LoginCodeType } from "@/gen/rustylink/daemon/v1/types_pb"
import { useApplySession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { useAuthScratch } from "./auth-context"
import { AuthShell } from "./auth-shell"

const schema = z.object({
  code: z.string().trim().min(1, "Enter the verification code"),
})

type Values = z.infer<typeof schema>

export function OtpStep({ session }: { session: Session }) {
  const challenge = session.otpChallenge
  const { account } = useAuthScratch()
  const applySession = useApplySession()
  const loginType = challenge?.loginType ?? LoginCodeType.MOBILE

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<Values>({
    resolver: standardSchemaResolver(schema),
    defaultValues: { code: "" },
  })

  const verify = useMutation(verifyLoginCode, {
    onSuccess: (res) => res.session && applySession(res.session),
    onError: (err) => toast.error(errorMessage(err)),
  })
  const resend = useMutation(requestLoginCode, {
    onSuccess: () => toast.success("A new code has been sent"),
    onError: (err) => toast.error(errorMessage(err)),
  })

  const onSubmit = handleSubmit((values) =>
    verify.mutate({ account, code: values.code, loginType })
  )

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
            {...register("code")}
          />
          {errors.code ? (
            <p className="text-destructive text-sm">{errors.code.message}</p>
          ) : null}
        </div>
        <Button type="submit" className="w-full" disabled={verify.isPending}>
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
