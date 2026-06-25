//! Outbound networking primitives for bypass traffic.
//!
//! This crate provides the reusable socket / dialer / DNS / connector layer
//! used by ALL traffic that must exit through a physical network interface
//! (bypassing the TUN): `WireGuard` UDP/TCP, DNS transports, and the hyper
//! connector.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐   ┌───────────┐   ┌───────────────┐   ┌────────────────┐
//! │ interface.rs │──>│ dialer.rs │──>│  resolver.rs  │──>│ connector.rs   │
//! │ selection    │   │ sockets   │   │ interface-    │   │ HyperConnector │
//! │ + loop-safe  │   │ + binding │   │ bound DNS     │   │ (tower Svc)    │
//! └─────────────┘   └───────────┘   └───────────────┘   └────────────────┘
//!        │                                   │
//!        v                                   v
//! ┌─────────────┐                   ┌────────────────┐
//! │ snapshot.rs  │                   │  context.rs    │
//! │ change detect│                   │ OutboundContext │
//! └─────────────┘                   └────────────────┘
//! ```
//!
//! # Binding mechanism
//!
//! Per-socket `setsockopt` applied at creation, **before**
//! `bind()`/`connect()`:
//!
//! | OS | Socket option | Semantics |
//! |---|---|---|
//! | Linux | `SO_BINDTOIFINDEX` (kernel >= 5.7) | hard-binds egress to device |
//! | macOS | `IP_BOUND_IF` / `IPV6_BOUND_IF` | forces outgoing interface |
//! | Windows | `IP_UNICAST_IF` / `IPV6_UNICAST_IF` | preferred outgoing interface |
//!
//! This overrides the kernel route lookup, keeping encrypted traffic off the
//! TUN and preventing the self-loop.  No system-level side-effects (routes,
//! rules, marks) are created by this crate -- teardown is just `drop`.

pub mod bypass;
pub mod connector;
pub mod context;
pub mod dialer;
pub mod interface;
pub mod resolver;
pub mod snapshot;

// Re-exports for convenience.
pub use bypass::{Error as BypassError, RouteBypass};
pub use connector::{Error as ConnectorError, HyperConnector, parse_uri_host_port};
pub use context::{Error as ContextError, OutboundConfig, OutboundContext};
pub use dialer::{Dialer, Error as DialerError, should_bind};
pub use interface::{Error as InterfaceError, InterfaceInfo, OutboundInterface, list_interfaces};
pub use resolver::{Error as ResolverError, Resolver, system_dns_servers};
pub use snapshot::{Error as SnapshotError, NetworkSnapshot, pinned_present};
