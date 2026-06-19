import { useMutation } from "@connectrpc/connect-query"
import { ArrowSquareOutIcon } from "@phosphor-icons/react"
import { type FormEvent, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  completeThirdPartyLogin,
  logout,
} from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import type { Session } from "@/gen/rustylink/daemon/v1/session_pb"
import { useApplySession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { AuthShell } from "./auth-shell"

// Accept either the full redirect URL (corplink://login/callback?code=…&state=…)
// or a bare code. Returns the extracted code and state (falling back to the
// challenge's state when the pasted value has none).
function parseRedirect(
  input: string,
  fallbackState: string
): { code: string; state: string } {
  const trimmed = input.trim()
  if (trimmed.includes("code=")) {
    const query = trimmed.includes("?")
      ? trimmed.slice(trimmed.indexOf("?") + 1)
      : trimmed
    const params = new URLSearchParams(query)
    const code = params.get("code")
    if (code) {
      return { code, state: params.get("state") ?? fallbackState }
    }
  }
  return { code: trimmed, state: fallbackState }
}

export function OauthStep({ session }: { session: Session }) {
  const challenge = session.oauthChallenge
  const applySession = useApplySession()
  const [value, setValue] = useState("")

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
    const { code, state } = parseRedirect(value, challenge?.state ?? "")
    complete.mutate({
      aliasKey: challenge?.aliasKey ?? "",
      code,
      state,
    })
  }

  return (
    <AuthShell
      tenant={session.tenantName}
      title="Finish single sign-on"
      description="Complete authentication in the window that opened. You'll be redirected to a corplink:// link that the browser can't follow — copy that link (or the code in it) and paste it below."
    >
      <form className="space-y-4" onSubmit={onSubmit}>
        <div className="space-y-2">
          <Label htmlFor="oauth-redirect">Redirect URL or code</Label>
          <Input
            id="oauth-redirect"
            autoFocus
            placeholder="corplink://login/callback?code=…&state=…"
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
        </div>
        <Button
          type="submit"
          className="w-full"
          disabled={complete.isPending || !value.trim()}
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
