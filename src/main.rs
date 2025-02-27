mod capture;
mod cli;
mod dns;
mod net;
mod shared;
mod tui;
mod util;

use anyhow::Result;
use clap::Parser;
use cli::Args;
use colored::*;
use std::{process, sync::mpsc, thread};

fn main() -> Result<()> {
    let args = Args::parse();

    if let Err(e) = args.validate() {
        eprintln!("{}: {}", "Error".red().bold(), e);
        process::exit(1);
    }

    if args.list_devices {
        return list_devices();
    }

    // Create a channel for DNS events
    let (tx, rx) = mpsc::channel();

    if !args.disable_tui {
        // TUI Mode
        println!("Starting DustCloud DNS Monitor in TUI mode...");

        // Spawn capture thread with tx sender
        let capture_args = args.clone();
        let capture_tx = tx.clone();
        thread::spawn(move || {
            if let Err(e) = capture::start_capture_with_channel(&capture_args, capture_tx) {
                eprintln!("{}: {}", "Error during capture".red().bold(), e);
                process::exit(1);
            }
        });

        tui::run_tui(rx)?;
    } else {
        println!("{}", "DustCloud DNS Monitor".green().bold());
        println!("Version: {}", env!("CARGO_PKG_VERSION"));

        if args.verbose {
            println!("\n{}", "Configuration:".yellow());
            if let Some(dns_providers) = &args.dns_providers {
                println!("  Set providers DNS only: {:?}", dns_providers);
            }
            println!("  DNS traffic only: {}", args.dns_only);
            if let Some(device) = &args.device {
                println!("  Network device: {}", device);
            } else {
                println!("  Network device: <auto-detect>");
            }
            if let Some(output) = &args.output {
                println!("  Output file: {}", output.display());
            }
            if let Some(domains) = &args.filter_domains {
                println!("  Filtering for domains: {}", domains.join(", "));
            }
            println!("  Output format: {}", args.format);
            println!("");
        }

        #[cfg(unix)]
        check_permissions();

        // Start packet capture (standard CLI mode)
        if let Err(e) = capture::start_capture(&args) {
            eprintln!("{}: {}", "Error during capture".red().bold(), e);
            return Err(e);
        }
    }

    Ok(())
}

fn list_devices() -> Result<()> {
    println!("{}", "Available Network Devices:".green().bold());

    let devices = capture::list_devices()?;

    if devices.is_empty() {
        println!("No devices found.");
        return Ok(());
    }

    for (i, device) in devices.iter().enumerate() {
        println!("{}. {}", i + 1, device.name.cyan());

        if let Some(desc) = &device.desc {
            println!("   Description: {}", desc);
        }

        if !device.addresses.is_empty() {
            println!("   Addresses:");
            for addr in device.addresses.clone() {
                println!("     - {}", addr.addr);
            }
        }

        println!();
    }

    println!("To use a specific device, run with: --device DEVICE_NAME");

    Ok(())
}

#[cfg(unix)]
fn check_permissions() {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!(
            "{}",
            "Warning: This program may require root privileges to capture packets."
                .yellow()
                .bold()
        );
        eprintln!("If capture fails, try running with sudo.");
        eprintln!("");
    }
}
