import { useMutation } from "@connectrpc/connect-query"
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

const schema = z
  .object({
    method: z.string().min(1),
    code: z.string(),
  })
  .refine(
    (values) => values.method === "password" || values.code.trim().length > 0,
    {
      message: "Enter the verification code",
      path: ["code"],
    }
  )
type Values = z.infer<typeof schema>

export function MfaStep({ session }: { session: Session }) {
  const challenge = session.mfaChallenge
  const { account, password } = useAuthScratch()
  const applySession = useApplySession()
  const authList = challenge?.authList ?? []

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

  const {
    control,
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<Values>({
    resolver: standardSchemaResolver(schema),
    defaultValues: {
      method: challenge?.mfaType || authList[0] || "otp",
      code: "",
    },
  })
  const method = watch("method")
  const isPassword = method === "password"

  const onSubmit = handleSubmit((values) =>
    verify.mutate({
      mfaType: values.method,
      account,
      code: values.method === "password" ? undefined : values.code,
      password: values.method === "password" ? password : undefined,
    })
  )

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
            <Controller
              control={control}
              name="method"
              render={({ field }) => (
                <Select
                  value={field.value}
                  onValueChange={(v) => field.onChange(v ?? "")}
                >
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
              )}
            />
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
              {...register("code")}
            />
            {errors.code ? (
              <p className="text-destructive text-sm">{errors.code.message}</p>
            ) : null}
          </div>
        )}

        <Button type="submit" className="w-full" disabled={verify.isPending}>
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
