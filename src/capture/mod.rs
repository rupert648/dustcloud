use crate::capture::filter::build_capture_filter;
use crate::cli::Args;
use crate::dns;
use anyhow::{anyhow, Context, Result};
use chrono::DateTime;
use pcap::{Capture, Device};
use std::time::Duration;

pub mod dns_providers;
mod filter;

pub fn start_capture(args: &Args) -> Result<()> {
    let devices = Device::list().context("Failed to list network devices")?;

    if args.verbose {
        println!("Available devices:");
        for (i, device) in devices.iter().enumerate() {
            println!(
                "  {}. {} - {:?}",
                i + 1,
                device.name,
                device.desc.as_deref().unwrap_or("No description")
            );
        }
    }

    // Either use the specified device or find a default one
    let device = match &args.device {
        Some(name) => devices
            .into_iter()
            .find(|d| d.name == *name)
            .ok_or_else(|| anyhow!("Device '{}' not found", name))?,
        None => {
            // Try to find a default device that's up and running
            let default = Device::lookup()?.ok_or_else(|| anyhow!("No default device found"))?;
            if args.verbose {
                println!("Selected default device: {}", default.name);
            }
            default
        }
    };

    println!("Using network device: {}", device.name);

    let mut cap = Capture::from_device(device)?
        .promisc(true) // Promiscuous mode to capture all packets
        .snaplen(65535) // Maximum packet size
        .timeout(1000) // Milliseconds
        .open()?
        .setnonblock()?;

    let filter = build_capture_filter(args);
    if args.verbose {
        println!("Using filter: {}", filter);
    }

    cap.filter(&filter, true)?;

    println!("Listening for network traffic...");
    println!("Press Ctrl+C to stop capture");

    let mut packet_count = 0;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;

                if args.dns_providers.is_some() || args.dns_only {
                    if let Some(dns_packet) = dns::parse_packet(&packet) {
                        handle_dns_packet(dns_packet, args);
                    }
                } else {
                    handle_network_packet(&packet, args);
                }

                // Print stats periodically
                if packet_count % 100 == 0 && args.verbose {
                    println!("Processed {} packets", packet_count);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // This is normal with nonblocking mode
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("Error capturing packet: {}", e);
                if !args.continue_on_error {
                    return Err(anyhow!("Capture error: {}", e));
                }
            }
        }
    }
}

/// Handle a general network packet
fn handle_network_packet(packet: &pcap::Packet, args: &Args) {
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

/// Handle a parsed DNS packet
fn handle_dns_packet(dns_packet: dns::DnsPacket, args: &Args) {
    // Print DNS query information
    if let Some(query) = dns_packet.query {
        println!("DNS Query: {} (Type: {:?})", query.name, query.query_type);

        if args.verbose {
            println!("  From: {}", dns_packet.source);
            println!("  To: {}", dns_packet.destination);
        }
    }

    // Handle DNS responses
    if !dns_packet.answers.is_empty() {
        println!("DNS Response: {} answers", dns_packet.answers.len());

        for (i, answer) in dns_packet.answers.iter().enumerate() {
            println!("  {}. {} -> {}", i + 1, answer.name, answer.data);
        }
    }
}

/// Get available network devices
pub fn list_devices() -> Result<Vec<Device>> {
    Device::list().context("Failed to list network devices")
}
