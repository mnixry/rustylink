// Bearer-token storage. The daemon prints its token once on stderr; the user
// pastes it into the setup screen. We persist it in localStorage and attach it
// to every Connect request via an interceptor (see transport.ts).

const TOKEN_KEY = "rustylink.token"

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token.trim())
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

export function hasToken(): boolean {
  return Boolean(getToken())
}
