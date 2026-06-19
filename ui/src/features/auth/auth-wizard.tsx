import {
  type Session,
  Session_State,
} from "@/gen/rustylink/daemon/v1/session_pb"
import { ActivateStep } from "./activate-step"
import { AuthScratchProvider } from "./auth-context"
import { DeviceLoginStep } from "./device-login-step"
import { LoginStep } from "./login-step"
import { MfaStep } from "./mfa-step"
import { OauthStep } from "./oauth-step"
import { OtpStep } from "./otp-step"

// Renders the current auth step purely from the daemon's Session.state. The
// scratch provider persists account/password across step transitions.
export function AuthWizard({ session }: { session: Session }) {
  return (
    <AuthScratchProvider>
      <WizardStep session={session} />
    </AuthScratchProvider>
  )
}

function WizardStep({ session }: { session: Session }) {
  switch (session.state) {
    case Session_State.CONFIGURED:
      return <LoginStep session={session} />
    case Session_State.AWAITING_OTP:
      return <OtpStep session={session} />
    case Session_State.AWAITING_MFA:
      return <MfaStep session={session} />
    case Session_State.AWAITING_OAUTH:
      return <OauthStep session={session} />
    case Session_State.AWAITING_DEVICE_LOGIN:
      return <DeviceLoginStep session={session} />
    default:
      // UNSPECIFIED / UNCONFIGURED -> start from activation.
      return <ActivateStep />
  }
}
