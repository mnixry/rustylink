import { ConnectError, createClient } from "@connectrpc/connect"
import { standardSchemaResolver } from "@hookform/resolvers/standard-schema"
import { PlugIcon } from "@phosphor-icons/react"
import { useForm } from "react-hook-form"
import { useNavigate } from "react-router"
import { toast } from "sonner"
import { z } from "zod"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { MetaService } from "@/gen/rustylink/daemon/v1/daemon_pb"
import { clearToken, setToken } from "@/lib/token"
import { transport } from "@/lib/transport"

const schema = z.object({
  token: z.string().trim().min(1, "Paste the daemon access token"),
})
type Values = z.infer<typeof schema>

// Token entry / onboarding. Validates the pasted token by pinging the daemon,
// then persists it and proceeds into the app.
export function SetupScreen() {
  const navigate = useNavigate()
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<Values>({
    resolver: standardSchemaResolver(schema),
    defaultValues: { token: "" },
  })

  const onSubmit = handleSubmit(async (values) => {
    const token = values.token.trim()
    setToken(token)
    try {
      const client = createClient(MetaService, transport)
      const res = await client.ping({})
      toast.success(`Connected to daemon v${res.version}`)
      navigate("/", { replace: true })
    } catch (err) {
      clearToken()
      const message = err instanceof ConnectError ? err.message : String(err)
      toast.error(`Could not connect: ${message}`)
    }
  })

  return (
    <div className="flex min-h-svh items-center justify-center bg-background p-6">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="bg-primary/10 text-primary mb-2 flex size-10 items-center justify-center rounded-lg">
            <PlugIcon className="size-5" weight="duotone" />
          </div>
          <CardTitle>Connect to the daemon</CardTitle>
          <CardDescription>
            Open the URL printed in the daemon's startup log — it carries the
            access token. Otherwise paste the token below. A fresh token is
            generated each time the daemon starts.
          </CardDescription>
        </CardHeader>
        <form onSubmit={onSubmit}>
          <CardContent className="space-y-2">
            <Label htmlFor="token">Access token</Label>
            <Input
              id="token"
              type="password"
              autoComplete="off"
              autoFocus
              placeholder="daemon access token"
              {...register("token")}
            />
            {errors.token ? (
              <p className="text-destructive text-sm">{errors.token.message}</p>
            ) : null}
          </CardContent>
          <CardFooter className="mt-4">
            <Button type="submit" className="w-full" disabled={isSubmitting}>
              {isSubmitting ? "Connecting…" : "Connect"}
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  )
}
