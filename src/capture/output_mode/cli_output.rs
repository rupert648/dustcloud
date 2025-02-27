use chrono::DateTime;

use super::PacketHandler;

pub struct CliOutput;

impl PacketHandler for CliOutput {
    fn handle_dns_packet(&self, dns_packet: crate::dns::DnsPacket, args: &crate::cli::Args) {
        if let Some(query) = dns_packet.query {
            println!(
                "DNS Query: {} (Type: {:?}) -> Estimated Provider: {}",
                query.name,
                query.query_type,
                dns_packet.provider.as_str()
            );

            if args.verbose {
                println!("  From: {}", dns_packet.source);
                println!("  To: {}", dns_packet.destination);
            }
        }

        if !dns_packet.answers.is_empty() {
            println!("DNS Response: {} answers", dns_packet.answers.len());

            for (i, answer) in dns_packet.answers.iter().enumerate() {
                println!("  {}. {} -> {}", i + 1, answer.name, answer.data);
            }
        }
    }

    fn handle_network_packet(&self, packet: &pcap::Packet, args: &crate::cli::Args) {
        let timestamp = packet.header.ts;
        let datetime = DateTime::from_timestamp(timestamp.tv_sec, timestamp.tv_usec as u32 * 1000)
            .unwrap_or_default();

        if args.verbose {
            println!(
                "[{}] Captured packet: {} bytes",
                datetime,
                packet.data.len()
            );
        }

        // TODO(RC): Implement packet analysis based on protocols (TCP, UDP, etc.)
        // e.g. source/destination IPs, ports, etc.
    }
}
