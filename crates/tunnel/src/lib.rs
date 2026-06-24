pub mod dns;
pub mod error;
pub mod outbound;
pub mod reconnect;
pub mod route;
pub mod session;
pub mod transport;

pub use dns::{
    DnsHijackPlan, DnsQueryTransport, DnsResolver, LivenessProbe, UdpDnsTransport, VpnTun,
    system_dns_servers,
};
pub use error::{Error, Result};
pub use outbound::{BoundUdpSocketFactory, OutboundInterface};
pub use reconnect::{ReconnectController, ReconnectDecision, ReconnectEvent, ReconnectPolicy};
pub use route::VpnRouteMode;
pub use session::{LocalTunnelParams, TunnelConfig, TunnelSession, TunnelStatus};
pub use transport::FeilianTcpTransportFactory;
