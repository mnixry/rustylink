//! DNS resolver for TUN-level hijacking.
//!
//! [`DnsResolver`] is the public API consumed by `VpnTun::recv()` in the
//! tunnel crate. It takes a raw DNS wire payload, routes it through the
//! synthesis + routing pipeline, and always returns a DNS wire response.

use std::{
    net::{IpAddr, SocketAddr},
    time::Instant,
};

use hickory_proto::op::ResponseCode;

use crate::{config::DnsConfig, forwarder, synthesis};

const DNS_PORT: u16 = 53;

/// Routes DNS queries through synthesis → routing rules → parallel upstream
/// forwarding. Always yields a DNS response (upstream answer, synthesized
/// answer, or synthesized SERVFAIL).
pub struct DnsResolver {
    config: DnsConfig,
    /// Pre-resolved VPN resolver endpoints (routed transport).
    vpn_servers: Vec<SocketAddr>,
    /// Pre-resolved system resolver endpoints (directed transport).
    system_servers: Vec<SocketAddr>,
    /// IPs of the VPN resolver(s). Used by `VpnTun::recv()` to skip hijacking
    /// the routed transport's own forwarding traffic (loop prevention).
    vpn_dns_ips: Vec<IpAddr>,
    /// Dialer bound to the physical outbound interface (for non-routed
    /// queries).
    directed_dialer: rustylink_outbound::Dialer,
}

impl DnsResolver {
    /// Build the resolver. Returns `None` (hijack disabled) when the VPN
    /// provided no resolver endpoints.
    #[must_use]
    pub fn build(
        config: DnsConfig, vpn_servers: Vec<SocketAddr>, system_servers: &[IpAddr],
        directed_dialer: rustylink_outbound::Dialer,
    ) -> Option<Self> {
        if config.is_disabled() {
            tracing::info!("DNS hijack disabled: VPN provided no resolver");
            return None;
        }
        let vpn_dns_ips = vpn_servers.iter().map(SocketAddr::ip).collect();
        let system_servers = system_servers
            .iter()
            .map(|ip| SocketAddr::new(*ip, DNS_PORT))
            .collect();
        Some(Self {
            config,
            vpn_servers,
            system_servers,
            vpn_dns_ips,
            directed_dialer,
        })
    }

    /// VPN DNS IPs for loop prevention. `VpnTun::recv()` checks that the
    /// packet's destination is NOT in this set before hijacking.
    #[must_use]
    pub fn vpn_dns_ips(&self) -> &[IpAddr] {
        &self.vpn_dns_ips
    }

    /// Resolve a hijacked DNS query. Always returns a DNS wire response:
    /// a synthesized answer, the upstream answer, or a synthesized SERVFAIL.
    pub async fn resolve(&self, dns_payload: &[u8]) -> Vec<u8> {
        // Layer 1-3: synthesize from dynamic-domain answer tables.
        if let Some(answer) = synthesis::synthesize(&self.config, dns_payload) {
            let domain = synthesis::parse_question_domain(dns_payload);
            tracing::debug!(
                domain = domain.as_deref().unwrap_or("<unknown>"),
                "DNS answered from dynamic-domain table"
            );
            return answer;
        }

        // Layer 6: forward to routed (VPN) or directed (system) upstream.
        let domain = synthesis::parse_question_domain(dns_payload);
        let domain_str = domain.as_deref();

        let (servers, route, use_directed) = if self.config.route_through_vpn(domain_str) {
            (&self.vpn_servers, "routed", false)
        } else {
            (&self.system_servers, "directed", true)
        };
        let name = domain_str.unwrap_or("<unknown>");

        let start = Instant::now();
        let result = if use_directed {
            forwarder::parallel_query_directed(servers, dns_payload, &self.directed_dialer).await
        } else {
            forwarder::parallel_query_routed(servers, dns_payload).await
        };

        match result {
            Ok(response) => {
                tracing::debug!(
                    domain = name,
                    route,
                    rtt_ms = start.elapsed().as_millis(),
                    "DNS resolved"
                );
                response
            }
            Err(error) => {
                tracing::warn!(
                    domain = name,
                    route,
                    %error,
                    "DNS resolution failed; returning SERVFAIL"
                );
                synthesis::synthesize_failure(dns_payload, ResponseCode::ServFail)
            }
        }
    }
}
