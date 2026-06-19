import { Tunnel_State } from "@/gen/rustylink/daemon/v1/tunnel_pb"
import { ProtocolMode, VpnMode } from "@/gen/rustylink/daemon/v1/types_pb"

export type StatusTone = "connected" | "pending" | "failed" | "idle"

export function tunnelStateLabel(state: Tunnel_State): string {
  switch (state) {
    case Tunnel_State.CONNECTED:
      return "Connected"
    case Tunnel_State.CONNECTING:
      return "Connecting"
    case Tunnel_State.CONFIGURING:
      return "Configuring"
    case Tunnel_State.RECONNECTING:
      return "Reconnecting"
    case Tunnel_State.DISCONNECTING:
      return "Disconnecting"
    case Tunnel_State.FAILED:
      return "Failed"
    default:
      return "Disconnected"
  }
}

export function tunnelStateTone(state: Tunnel_State): StatusTone {
  switch (state) {
    case Tunnel_State.CONNECTED:
      return "connected"
    case Tunnel_State.CONNECTING:
    case Tunnel_State.CONFIGURING:
    case Tunnel_State.RECONNECTING:
    case Tunnel_State.DISCONNECTING:
      return "pending"
    case Tunnel_State.FAILED:
      return "failed"
    default:
      return "idle"
  }
}

export function isActive(state: Tunnel_State): boolean {
  return (
    state === Tunnel_State.CONNECTED ||
    state === Tunnel_State.CONNECTING ||
    state === Tunnel_State.CONFIGURING ||
    state === Tunnel_State.RECONNECTING
  )
}

export const VPN_MODES: { value: VpnMode; label: string }[] = [
  { value: VpnMode.FULL, label: "Full tunnel" },
  { value: VpnMode.SPLIT, label: "Split tunnel" },
  { value: VpnMode.RELAY, label: "Relay" },
]

export const PROTOCOL_MODES: { value: ProtocolMode; label: string }[] = [
  { value: ProtocolMode.AUTO, label: "Auto" },
  { value: ProtocolMode.UDP, label: "UDP" },
  { value: ProtocolMode.TCP, label: "TCP" },
]

export function vpnModeLabel(mode: VpnMode): string {
  return VPN_MODES.find((m) => m.value === mode)?.label ?? "Unknown"
}

export function protocolModeLabel(mode: ProtocolMode): string {
  return PROTOCOL_MODES.find((m) => m.value === mode)?.label ?? "Auto"
}
