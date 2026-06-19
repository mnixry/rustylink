import { useMutation } from "@connectrpc/connect-query"
import { standardSchemaResolver } from "@hookform/resolvers/standard-schema"
import { useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { activate } from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import { useApplySession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { AuthShell } from "./auth-shell"

const schema = z.object({
  code: z.string().trim().min(1, "Enter your activation code"),
  baseUrl: z.string().trim().optional(),
})

type Values = z.infer<typeof schema>

export function ActivateStep() {
  const applySession = useApplySession()
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<Values>({
    resolver: standardSchemaResolver(schema),
    defaultValues: { code: "", baseUrl: "" },
  })

  const { mutate, isPending } = useMutation(activate, {
    onSuccess: (res) => {
      if (res.session) {
        applySession(res.session)
      }
    },
    onError: (err) => toast.error(errorMessage(err)),
  })

  const onSubmit = handleSubmit((values) =>
    mutate({
      code: values.code,
      baseUrl: values.baseUrl ? values.baseUrl : undefined,
    })
  )

  return (
    <AuthShell
      title="Activate"
      description="Enter the activation code provided by your organization to discover your tenant."
    >
      <form className="space-y-4" onSubmit={onSubmit}>
        <div className="space-y-2">
          <Label htmlFor="code">Activation code</Label>
          <Input
            id="code"
            autoFocus
            placeholder="e.g. acme"
            {...register("code")}
          />
          {errors.code ? (
            <p className="text-destructive text-sm">{errors.code.message}</p>
          ) : null}
        </div>
        <div className="space-y-2">
          <Label htmlFor="baseUrl">Server URL (optional)</Label>
          <Input
            id="baseUrl"
            placeholder="https://vpn.example.com"
            {...register("baseUrl")}
          />
        </div>
        <Button type="submit" className="w-full" disabled={isPending}>
          {isPending ? "Activating…" : "Continue"}
        </Button>
      </form>
    </AuthShell>
  )
}
