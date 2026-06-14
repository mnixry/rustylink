use rustylink_api::VpnConnResponse;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsRule {
    pub domain: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsHijackPlan {
    pub primary_dns: Option<String>,
    pub backup_dns: Option<String>,
    pub central_dns: Option<String>,
    pub domain_rules: Vec<DnsRule>,
}

impl DnsHijackPlan {
    #[must_use]
    pub fn from_vpn_conn(conn: &VpnConnResponse) -> Self {
        let endpoint = conn
            .setting
            .central_dns
            .clone()
            .or_else(|| conn.setting.vpn_dns.clone())
            .unwrap_or_else(|| "127.0.0.1:53".to_string());
        let domain_rules = conn
            .setting
            .vpn_dns_domain_split
            .iter()
            .map(|domain| DnsRule {
                domain: domain.clone(),
                endpoint: endpoint.clone(),
            })
            .collect();
        Self {
            primary_dns: conn.setting.vpn_dns.clone(),
            backup_dns: conn.setting.vpn_dns_backup.clone(),
            central_dns: conn.setting.central_dns.clone(),
            domain_rules,
        }
    }
}
