import { useMutation } from "@connectrpc/connect-query"
import { ArrowSquareOutIcon } from "@phosphor-icons/react"
import { QRCodeSVG } from "qrcode.react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
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
  const complete = useMutation(completeDeviceLogin, {
    onSuccess: (res) => res.session && applySession(res.session),
    onError,
  })
  const cancel = useMutation(logout, {
    onSuccess: (res) => res.session && applySession(res.session),
    onError,
  })

  return (
    <AuthShell
      tenant={session.tenantName}
      title="Scan to sign in"
      description="Scan this code with the mobile app, then confirm. This page updates automatically."
    >
      <div className="flex flex-col items-center gap-4">
        {loginUrl ? (
          <div className="rounded-lg bg-white p-4">
            <QRCodeSVG value={loginUrl} size={180} />
          </div>
        ) : null}

        {loginUrl ? (
          <a
            href={loginUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary inline-flex items-center gap-1 text-sm hover:underline"
          >
            <ArrowSquareOutIcon className="size-4" weight="duotone" />
            Open sign-in link
          </a>
        ) : null}

        <Button
          type="button"
          className="w-full"
          disabled={complete.isPending}
          onClick={() => complete.mutate({})}
        >
          {complete.isPending
            ? "Waiting for approval…"
            : "I've approved on my device"}
        </Button>
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
