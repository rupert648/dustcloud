use crate::capture::filter::build_capture_filter;
use crate::cli::Args;
use crate::dns;
use anyhow::{anyhow, Context, Result};
use output_mode::{ChannelOutput, CliOutput, PacketHandler, Tx};
use pcap::{Capture, Device};
use std::time::Duration;

pub mod dns_providers;
mod filter;
mod output_mode;

pub fn start_capture_with_channel(args: &Args, tx: Tx) -> Result<()> {
    run_capture(args, ChannelOutput(tx))
}

pub fn start_capture(args: &Args) -> Result<()> {
    run_capture(args, CliOutput)
}

fn get_selected_device(args: &Args, devices: Vec<Device>) -> Result<Device, anyhow::Error> {
    let device = match &args.device {
        Some(name) => devices
            .into_iter()
            .find(|d| d.name == *name)
            .ok_or_else(|| anyhow!("Device '{}' not found", name))?,
        None => {
            let default = Device::lookup()?.ok_or_else(|| anyhow!("No default device found"))?;
            if args.verbose {
                println!("Selected default device: {}", default.name);
            }
            default
        }
    };
    Ok(device)
}

fn run_capture<C>(args: &Args, capture_mode: C) -> Result<()>
where
    C: PacketHandler,
{
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

    let device = get_selected_device(args, devices)?;
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
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                // TODO: handle more than just dns packets
                if let Some(dns_packet) = dns::parse_packet(&packet) {
                    capture_mode.handle_dns_packet(dns_packet, args);
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

/// Get available network devices
pub fn list_devices() -> Result<Vec<Device>> {
    Device::list().context("Failed to list network devices")
}
