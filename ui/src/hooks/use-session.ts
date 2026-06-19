import { create } from "@bufbuild/protobuf"
import {
  createConnectQueryKey,
  useQuery,
  useTransport,
} from "@connectrpc/connect-query"
import { useQueryClient } from "@tanstack/react-query"
import { getSession } from "@/gen/rustylink/daemon/v1/daemon-AuthService_connectquery"
import {
  GetSessionResponseSchema,
  type Session,
  Session_State,
} from "@/gen/rustylink/daemon/v1/session_pb"

// While waiting on an out-of-band browser/device approval, poll the session so
// the wizard advances automatically once the daemon completes the flow.
const POLLING_STATES = new Set<Session_State>([
  Session_State.AWAITING_OAUTH,
  Session_State.AWAITING_DEVICE_LOGIN,
])

export function useSession() {
  return useQuery(
    getSession,
    {},
    {
      refetchInterval: (query) => {
        const state = query.state.data?.session?.state
        return state !== undefined && POLLING_STATES.has(state) ? 2000 : false
      },
    }
  )
}

// Write a freshly returned session into the GetSession cache so the wizard
// re-renders to the next step without an extra round-trip.
export function useApplySession() {
  const queryClient = useQueryClient()
  const transport = useTransport()
  return (session: Session) => {
    const queryKey = createConnectQueryKey({
      schema: getSession,
      transport,
      input: {},
      cardinality: "finite",
    })
    queryClient.setQueryData(
      queryKey,
      create(GetSessionResponseSchema, { session })
    )
  }
}

// Force a re-fetch of the session. Used after RPCs that change daemon auth
// state without returning a session (e.g. StartThirdPartyLogin).
export function useRefreshSession() {
  const queryClient = useQueryClient()
  return () =>
    queryClient.invalidateQueries({
      queryKey: createConnectQueryKey({
        schema: getSession,
        cardinality: "finite",
      }),
    })
}

export { Session_State }
