import { ConnectError, createClient } from "@connectrpc/connect"
import { PlugIcon } from "@phosphor-icons/react"
import { type FormEvent, useState } from "react"
import { useNavigate } from "react-router"
import { toast } from "sonner"
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

// Token entry / onboarding. Validates the pasted token by pinging the daemon,
// then persists it and proceeds into the app.
export function SetupScreen() {
  const navigate = useNavigate()
  const [value, setValue] = useState("")
  const [pending, setPending] = useState(false)

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const token = value.trim()
    if (!token || pending) {
      return
    }
    setPending(true)
    setToken(token)
    try {
      const client = createClient(MetaService, transport)
      const res = await client.ping({})
      toast.success(`Connected to rustylinkd v${res.version}`)
      navigate("/", { replace: true })
    } catch (err) {
      clearToken()
      const message = err instanceof ConnectError ? err.message : String(err)
      toast.error(`Could not connect: ${message}`)
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="flex min-h-svh items-center justify-center bg-background p-6">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="bg-primary/10 text-primary mb-2 flex size-10 items-center justify-center rounded-lg">
            <PlugIcon className="size-5" weight="duotone" />
          </div>
          <CardTitle>Connect to rustylinkd</CardTitle>
          <CardDescription>
            Paste the daemon access token. It is printed once on the daemon's
            standard error output (or regenerate it with{" "}
            <code className="font-mono text-xs">--rotate-token</code>).
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
              placeholder="rustylinkd bearer token"
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
          </CardContent>
          <CardFooter className="mt-4">
            <Button type="submit" className="w-full" disabled={pending}>
              {pending ? "Connecting…" : "Connect"}
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  )
}
