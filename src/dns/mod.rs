use crate::{
    capture::dns_providers::{get_provider_for_ip, DnsProvider},
    net::extract_ip_addresses,
};
use dns_parser::{Packet, QueryType, RData};

#[derive(Debug)]
pub struct DnsQuery {
    pub name: String,
    pub query_type: QueryType,
}

#[derive(Debug)]
pub struct DnsAnswer {
    pub name: String,
    pub data: String,
}

#[derive(Debug)]
pub struct DnsPacket {
    pub query: Option<DnsQuery>,
    pub answers: Vec<DnsAnswer>,
    pub provider: DnsProvider,
    pub source: String,
    pub destination: String,
}

/// Parse a raw packet captured by pcap into a DNS packet
pub fn parse_packet(packet: &pcap::Packet) -> Option<DnsPacket> {
    // Skip Ethernet header (typically 14 bytes) and IP header (typically 20 bytes)
    // to get to the UDP header (8 bytes), after which comes the DNS data
    let dns_data_start = 42; // 14 (Ethernet) + 20 (IP) + 8 (UDP)

    if packet.data.len() <= dns_data_start {
        return None; // Packet too small to contain DNS data
    }
    let (source, destination) = extract_ip_addresses(packet.data);
    let provider = get_provider_for_ip(&source);

    // Parse DNS packet
    match Packet::parse(&packet.data[dns_data_start..]) {
        Ok(dns) => {
            // Extract query
            let query = if dns.questions.len() > 0 {
                let q = &dns.questions[0];
                Some(DnsQuery {
                    name: q.qname.to_string(),
                    query_type: q.qtype,
                })
            } else {
                None
            };

            // Extract answers
            let answers = dns
                .answers
                .iter()
                .map(|answer| {
                    let data = match &answer.data {
                        RData::A(addr) => addr.0.to_string(),
                        RData::AAAA(addr) => addr.0.to_string(),
                        RData::CNAME(name) => name.to_string(),
                        RData::MX(mx) => format!("{} {}", mx.preference, mx.exchange),
                        RData::NS(name) => name.to_string(),
                        RData::PTR(name) => name.to_string(),
                        RData::SOA(soa) => format!(
                            "{} {} {} {} {} {} {}",
                            soa.primary_ns,
                            soa.mailbox,
                            soa.serial,
                            soa.refresh,
                            soa.retry,
                            soa.expire,
                            soa.minimum_ttl
                        ),
                        RData::SRV(srv) => format!(
                            "{} {} {} {}",
                            srv.priority, srv.weight, srv.port, srv.target
                        ),
                        RData::TXT(txt) => txt
                            .iter()
                            .map(|chunk| String::from_utf8_lossy(chunk).to_string())
                            .collect::<Vec<_>>()
                            .join(""),
                        _ => format!("<unsupported record type>"),
                    };

                    DnsAnswer {
                        name: answer.name.to_string(),
                        data,
                    }
                })
                .collect();

            Some(DnsPacket {
                query,
                answers,
                provider,
                source,
                destination,
            })
        }
        Err(_) => None, // Not a valid DNS packet
    }
}
