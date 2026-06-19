import { useMutation } from "@connectrpc/connect-query"
import { ArrowSquareOutIcon, SpinnerIcon } from "@phosphor-icons/react"
import { type FormEvent, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import {
  completeThirdPartyLogin,
  logout,
} from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import type { Session } from "@/gen/rustylink/daemon/v1/session_pb"
import { useApplySession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { AuthShell } from "./auth-shell"

export function OauthStep({ session }: { session: Session }) {
  const challenge = session.oauthChallenge
  const applySession = useApplySession()
  const [code, setCode] = useState("")

  const onError = (err: unknown) => toast.error(errorMessage(err))
  const complete = useMutation(completeThirdPartyLogin, {
    onSuccess: (res) => res.session && applySession(res.session),
    onError,
  })
  const cancel = useMutation(logout, {
    onSuccess: (res) => res.session && applySession(res.session),
    onError,
  })

  const onSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    complete.mutate({
      aliasKey: challenge?.aliasKey ?? "",
      code,
      state: challenge?.state ?? "",
    })
  }

  return (
    <AuthShell
      tenant={session.tenantName}
      title="Waiting for sign-in"
      description="Complete authentication in the browser window that opened. This page updates automatically."
    >
      <div className="flex items-center justify-center py-6 text-muted-foreground">
        <SpinnerIcon className="size-8 animate-spin" weight="duotone" />
      </div>

      <div className="flex items-center gap-3 py-2">
        <Separator className="flex-1" />
        <span className="text-muted-foreground text-xs">
          or paste the authorization code
        </span>
        <Separator className="flex-1" />
      </div>

      <form className="space-y-3" onSubmit={onSubmit}>
        <div className="space-y-2">
          <Label htmlFor="oauth-code">Authorization code</Label>
          <Input
            id="oauth-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
        </div>
        <Button
          type="submit"
          className="w-full"
          disabled={complete.isPending || !code}
        >
          <ArrowSquareOutIcon className="size-4" weight="duotone" />
          {complete.isPending ? "Completing…" : "Complete sign-in"}
        </Button>
      </form>

      <Button
        type="button"
        variant="ghost"
        className="text-muted-foreground mt-2 w-full"
        disabled={cancel.isPending}
        onClick={() => cancel.mutate({ logoutAll: false })}
      >
        Cancel
      </Button>
    </AuthShell>
  )
}
