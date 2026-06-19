import { useMutation } from "@connectrpc/connect-query"
import { ArrowSquareOutIcon, SpinnerIcon } from "@phosphor-icons/react"
import { QRCodeSVG } from "qrcode.react"
import { useEffect, useRef } from "react"
import { toast } from "sonner"
import { Button, buttonVariants } from "@/components/ui/button"
import {
  completeDeviceLogin,
  logout,
} from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import type { Session } from "@/gen/rustylink/daemon/v1/session_pb"
import { useApplySession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { AuthShell } from "./auth-shell"

export function DeviceLoginStep({ session }: { session: Session }) {
  const challenge = session.deviceLoginChallenge
  const applySession = useApplySession()
  const loginUrl = challenge?.loginUrl ?? ""

  const onError = (err: unknown) => toast.error(errorMessage(err))
  // CompleteDeviceLogin polls /api/tpslogin/token/check server-side (up to 2
  // minutes) and returns the authenticated session once the user approves.
  const complete = useMutation(completeDeviceLogin, {
    onSuccess: (res) => res.session && applySession(res.session),
    onError,
  })
  const cancel = useMutation(logout, {
    onSuccess: (res) => res.session && applySession(res.session),
    onError,
  })

  // Start the poll automatically when the step appears.
  const startPoll = complete.mutate
  const started = useRef(false)
  useEffect(() => {
    if (started.current) {
      return
    }
    started.current = true
    startPoll({})
  }, [startPoll])

  return (
    <AuthShell
      tenant={session.tenantName}
      title="Scan to sign in"
      description="Scan this code with the provider's mobile app, or open the link below. This page completes automatically once you approve."
    >
      <div className="flex flex-col items-center gap-4">
        {loginUrl ? (
          <a
            href={loginUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-lg bg-white p-4 transition-opacity hover:opacity-90"
            aria-label="Open sign-in link"
          >
            <QRCodeSVG value={loginUrl} size={184} />
          </a>
        ) : null}

        {loginUrl ? (
          <a
            href={loginUrl}
            target="_blank"
            rel="noopener noreferrer"
            className={buttonVariants({
              variant: "outline",
              className: "w-full",
            })}
          >
            <ArrowSquareOutIcon className="size-4" weight="duotone" />
            Open sign-in link
          </a>
        ) : null}

        <div className="text-muted-foreground flex items-center gap-2 text-sm">
          {complete.isPending ? (
            <>
              <SpinnerIcon className="size-4 animate-spin" weight="duotone" />
              Waiting for approval…
            </>
          ) : complete.isError ? (
            <Button
              variant="ghost"
              onClick={() => complete.mutate({})}
              className="text-foreground"
            >
              Retry — waiting timed out
            </Button>
          ) : (
            "Approve the sign-in in the provider's app."
          )}
        </div>

        <Button
          type="button"
          variant="ghost"
          className="text-muted-foreground w-full"
          disabled={cancel.isPending}
          onClick={() => cancel.mutate({ logoutAll: false })}
        >
          Cancel
        </Button>
      </div>
    </AuthShell>
  )
}
