// Bearer-token storage. The daemon generates a fresh token each run and prints
// access URLs of the form `http://host:port/?token=…`. We capture that query
// param on load (see captureTokenFromUrl), persist it in localStorage, and
// attach it to every Connect request via an interceptor (see transport.ts).

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

// Capture a `?token=…` query param (as printed by the daemon at startup),
// persist it, then strip it from the address bar so it isn't shared or
// bookmarked. Safe to call on every load; a no-op when no token is present.
export function captureTokenFromUrl(): void {
  const params = new URLSearchParams(window.location.search)
  const token = params.get("token")
  if (!token) {
    return
  }
  setToken(token)
  params.delete("token")
  const query = params.toString()
  const url =
    window.location.pathname + (query ? `?${query}` : "") + window.location.hash
  window.history.replaceState(window.history.state, "", url)
}
