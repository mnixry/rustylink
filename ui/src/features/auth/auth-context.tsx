import { createContext, type ReactNode, useContext, useState } from "react"

// The daemon's verify/MFA RPCs require the account (and sometimes password)
// that the session itself does not carry. We stash them client-side for the
// duration of the wizard so OTP/MFA steps can submit them.
type AuthScratch = {
  account: string
  password: string
  setAccount: (value: string) => void
  setPassword: (value: string) => void
}

const AuthScratchContext = createContext<AuthScratch | undefined>(undefined)

export function AuthScratchProvider({ children }: { children: ReactNode }) {
  const [account, setAccount] = useState("")
  const [password, setPassword] = useState("")
  return (
    <AuthScratchContext.Provider
      value={{ account, password, setAccount, setPassword }}
    >
      {children}
    </AuthScratchContext.Provider>
  )
}

export function useAuthScratch() {
  const ctx = useContext(AuthScratchContext)
  if (!ctx) {
    throw new Error("useAuthScratch must be used within AuthScratchProvider")
  }
  return ctx
}
