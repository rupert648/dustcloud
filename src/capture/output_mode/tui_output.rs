use std::time::SystemTime;

use crate::shared::TxEvent;

use super::{PacketHandler, Tx};

pub struct ChannelOutput(pub Tx);

impl PacketHandler for ChannelOutput {
    fn handle_network_packet(&self, _packet: &pcap::Packet, _args: &crate::cli::Args) {
        // TODO: do something with regular network packets!
        ()
    }

    fn handle_dns_packet(&self, dns_packet: crate::dns::DnsPacket, _args: &crate::cli::Args) {
        if let Some(query) = dns_packet.query {
            self.0
                .send(TxEvent::DnsQuery {
                    domain: query.name.clone(),
                    query_type: format!("{:?}", query.query_type),
                    provider: dns_packet.provider,
                    source: dns_packet.source.clone(),
                    destination: dns_packet.destination.clone(),
                    timestamp: SystemTime::now(),
                })
                .ok();
        }
        // TODO: handle answers
    }
}
