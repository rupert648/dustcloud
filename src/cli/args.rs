use clap::Parser;
use std::path::PathBuf;

use crate::capture::dns_providers::{list_all_providers, DnsProvider};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "A tool for monitoring DNS requests on macOS")]
#[command(
    long_about = "DustCloud monitors DNS traffic on your device, with a focus on requests routed through Cloudflare (1.1.1.1)"
)]
pub struct Args {
    /// Disables the terminal UI
    #[arg(long)]
    pub disable_tui: bool,

    /// Capture all DNS traffic (port 53)
    #[arg(short = 'd', long)]
    pub dns_only: bool,

    /// Specify DNS providers to monitor (comma-separated: cloudflare,google,opendns,quad9,adguard,cleanbrowsing)
    #[arg(long, value_delimiter = ',')]
    pub dns_providers: Option<Vec<String>>,

    /// Specify network interface to use (e.g., en0)
    #[arg(short = 'i', long)]
    pub device: Option<String>,

    /// Optional output file to save results
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// List available network devices and exit
    #[arg(short = 'l', long)]
    pub list_devices: bool,

    /// Continue capturing on error
    #[arg(long)]
    pub continue_on_error: bool,

    /// Filter for specific domain names (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub filter_domains: Option<Vec<String>>,

    /// Maximum number of packets to capture (0 for unlimited)
    #[arg(short = 'n', long, default_value = "0")]
    pub max_packets: usize,

    /// Output format (text, json, csv)
    #[arg(short = 'f', long, default_value = "text")]
    pub format: String,
}

impl Args {
    /// Validate command-line arguments
    pub fn validate(&self) -> Result<(), String> {
        // Validate dns_providers
        if let Some(providers) = &self.dns_providers {
            for provider in providers {
                if DnsProvider::from_str(provider) == DnsProvider::Unknown {
                    return Err(format!(
                        "Unknown DNS provider: {}. Available providers: {}",
                        provider,
                        list_all_providers()
                    ));
                }
            }
        }

        // Validate output format
        match self.format.to_lowercase().as_str() {
            "text" | "json" | "csv" => {}
            _ => return Err(format!("Invalid output format: {}", self.format)),
        }

        Ok(())
    }

    /// Convert dns_providers string list to DnsProvider enum list
    pub fn get_dns_providers(&self) -> Vec<DnsProvider> {
        if let Some(providers) = &self.dns_providers {
            providers.iter().map(|p| DnsProvider::from_str(p)).collect()
        } else {
            vec![]
        }
    }
}
