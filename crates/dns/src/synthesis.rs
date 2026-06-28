//! Dynamic-domain DNS response synthesis.
//!
//! Pure logic — no network I/O, no errors. Matches a DNS query against the
//! dynamic-domain answer tables and synthesizes a DNS wire response if the
//! domain is managed.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::{
    op::{Message as DnsMessage, MessageType, ResponseCode},
    rr::{RData, Record, RecordType},
};

use crate::config::{DnsConfig, normalize_domain, value_token};

/// TTL (seconds) for synthesized records. Matches the native client.
const DYNAMIC_TTL: u32 = 3600;

/// Try to answer a DNS query locally from the dynamic-domain answer tables.
/// Returns the synthesized DNS wire response, or `None` to fall through to the
/// forward path.
pub(crate) fn synthesize(config: &DnsConfig, payload: &[u8]) -> Option<Vec<u8>> {
    if config.dynamic.is_empty() {
        return None;
    }
    let request = DnsMessage::from_vec(payload).ok()?;
    let question = request.queries.first()?;
    let name = normalize_domain(&question.name().to_ascii());
    if name.is_empty() {
        return None;
    }
    match question.query_type() {
        RecordType::A => {
            let qname = question.name().clone();
            let answers: Vec<Record> = config
                .dynamic
                .lookup_v4(&name)?
                .iter()
                .filter_map(|value| value_token(value).parse::<Ipv4Addr>().ok())
                .map(|ip| Record::from_rdata(qname.clone(), DYNAMIC_TTL, RData::A(ip.into())))
                .collect();
            if answers.is_empty() {
                return None;
            }
            build_response(&request, answers)
        }
        RecordType::AAAA => match config.dynamic.lookup_v6(&name) {
            Some(values) => {
                let qname = question.name().clone();
                let answers: Vec<Record> = values
                    .iter()
                    .filter_map(|value| value_token(value).parse::<Ipv6Addr>().ok())
                    .map(|ip| {
                        Record::from_rdata(qname.clone(), DYNAMIC_TTL, RData::AAAA(ip.into()))
                    })
                    .collect();
                build_response(&request, answers)
            }
            // Domain is managed for IPv4 only: suppress AAAA with NODATA.
            None if config.dynamic.lookup_v4(&name).is_some() => {
                build_response(&request, Vec::new())
            }
            None => None,
        },
        _ => None,
    }
}

/// Build a NOERROR response carrying `answers` (empty = NODATA).
fn build_response(request: &DnsMessage, answers: Vec<Record>) -> Option<Vec<u8>> {
    let mut response = request.clone();
    response.metadata.message_type = MessageType::Response;
    response.metadata.response_code = ResponseCode::NoError;
    response.metadata.recursion_available = true;
    for record in answers {
        response.add_answer(record);
    }
    response.to_vec().ok()
}

/// Synthesize a failure response (e.g. SERVFAIL) from a query payload.
pub(crate) fn synthesize_failure(query_payload: &[u8], code: ResponseCode) -> Vec<u8> {
    match DnsMessage::from_vec(query_payload) {
        Ok(mut message) => {
            message.metadata.message_type = MessageType::Response;
            message.metadata.response_code = code;
            message.metadata.recursion_available = true;
            message.to_vec().unwrap_or_else(|_| query_payload.to_vec())
        }
        Err(_) => query_payload.to_vec(),
    }
}

/// Parse the first question domain from a DNS wire payload.
pub(crate) fn parse_question_domain(payload: &[u8]) -> Option<String> {
    let message = DnsMessage::from_vec(payload).ok()?;
    message
        .queries
        .first()
        .map(|query| normalize_domain(&query.name().to_ascii()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::{Message as DnsMessage, MessageType, OpCode, Query, ResponseCode},
        rr::{Name, RData, RecordType},
    };
    use rustylink_api::{VpnConnResponse, models::vpn::VpnConnSetting};

    use super::*;
    use crate::config::DnsConfig;

    fn map(pairs: &[(&str, &[&str])]) -> std::collections::HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(key, values)| {
                (
                    (*key).to_string(),
                    values.iter().map(|v| (*v).to_string()).collect(),
                )
            })
            .collect()
    }

    fn setting() -> VpnConnSetting {
        VpnConnSetting {
            vpn_mtu: 1400,
            vpn_dns: Some("10.0.0.53".to_string()),
            vpn_dns_backup: None,
            vpn_dns_domain_split: None,
            vpn_route_full: None,
            vpn_route_split: None,
            v6_route_full: None,
            v6_route_split: None,
            vpn_dynamic_domain_route_split: None,
            v6_vpn_dynamic_domain_route_split: None,
            vpn_wildcard_dynamic_domain_route_split: None,
            suffix_wildcard_dynamic_domain_route_split: None,
            dynamic_domain: None,
            central_dns: None,
            ip_nats: None,
        }
    }

    fn conn(setting: VpnConnSetting) -> VpnConnResponse {
        VpnConnResponse {
            ip: "10.0.0.2".to_string(),
            ipv6: None,
            ip_mask: Some(24),
            public_key: "server-public-key".to_string(),
            preshared_key: None,
            sign_token: None,
            protocol_version: None,
            setting,
            raw: None,
        }
    }

    fn query_payload(name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = DnsMessage::new(0x1234, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii(name).expect("valid name"),
            record_type,
        ));
        message.to_vec().expect("serialize query")
    }

    fn answers(payload: &[u8]) -> Vec<RData> {
        DnsMessage::from_vec(payload)
            .expect("decode response")
            .answers
            .iter()
            .map(|record| record.data.clone())
            .collect()
    }

    #[test]
    fn synthesizes_exact_a_record_with_dynamic_ttl() {
        let mut s = setting();
        s.dynamic_domain = Some(map(&[("git.corp", &["10.9.9.9"])]));
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);
        let payload =
            synthesize(&config, &query_payload("git.corp.", RecordType::A)).expect("synthesized");
        let message = DnsMessage::from_vec(&payload).unwrap();
        assert_eq!(message.metadata.message_type, MessageType::Response);
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        let records = &message.answers;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ttl, DYNAMIC_TTL);
        assert_eq!(
            records[0].data.clone(),
            RData::A("10.9.9.9".parse().unwrap())
        );
    }

    #[test]
    fn synthesizes_wildcard_and_suffix_matches() {
        let mut s = setting();
        s.vpn_wildcard_dynamic_domain_route_split = Some(map(&[("*.wild.corp", &["10.1.1.1"])]));
        s.suffix_wildcard_dynamic_domain_route_split = Some(map(&[("suffix.corp", &["10.2.2.2"])]));
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);

        let wild = synthesize(&config, &query_payload("host.wild.corp.", RecordType::A))
            .expect("wildcard synthesized");
        assert_eq!(answers(&wild), vec![RData::A("10.1.1.1".parse().unwrap())]);

        let suffix = synthesize(
            &config,
            &query_payload("deep.host.suffix.corp.", RecordType::A),
        )
        .expect("suffix synthesized");
        assert_eq!(
            answers(&suffix),
            vec![RData::A("10.2.2.2".parse().unwrap())]
        );
    }

    #[test]
    fn aaaa_for_v4_only_domain_returns_nodata() {
        let mut s = setting();
        s.vpn_dynamic_domain_route_split = Some(map(&[("v4only.corp", &["10.3.3.3"])]));
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);
        let payload = synthesize(&config, &query_payload("v4only.corp.", RecordType::AAAA))
            .expect("nodata response");
        let message = DnsMessage::from_vec(&payload).unwrap();
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(message.answers.is_empty());
    }

    #[test]
    fn synthesizes_aaaa_from_v6_table() {
        let mut s = setting();
        s.v6_vpn_dynamic_domain_route_split = Some(map(&[("v6.corp", &["fd00::1"])]));
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);
        let payload = synthesize(&config, &query_payload("v6.corp.", RecordType::AAAA))
            .expect("aaaa synthesized");
        assert_eq!(
            answers(&payload),
            vec![RData::AAAA("fd00::1".parse().unwrap())]
        );
    }

    #[test]
    fn unmatched_domain_is_not_synthesized() {
        let mut s = setting();
        s.dynamic_domain = Some(map(&[("git.corp", &["10.9.9.9"])]));
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);
        assert!(synthesize(&config, &query_payload("example.com.", RecordType::A)).is_none());
    }
}
