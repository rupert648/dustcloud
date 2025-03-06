use clap::Parser;

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

    /// Specify DNS providers to monitor (comma-separated: cloudflare,google,opendns,quad9,adguard,cleanbrowsing)
    #[arg(long, value_delimiter = ',')]
    pub dns_providers: Option<Vec<String>>,

    /// Specify network interface to use (e.g., en0)
    #[arg(short = 'i', long)]
    pub device: Option<String>,

    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// List available network devices and exit
    #[arg(short = 'l', long)]
    pub list_devices: bool,

    /// Continue capturing on error
    #[arg(long)]
    pub continue_on_error: bool,
}

impl Args {
    pub fn validate(&self) -> Result<(), String> {
        if let Err(v) = self.validate_dns_providers() {
            return Err(v);
        }

        Ok(())
    }

    fn validate_dns_providers(&self) -> Result<(), String> {
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
        if self.disable_tui && self.verbose {
            return Err(format!("Can't supply verbose argument with tui enabled"));
        }

        Ok(())
    }

    pub fn get_dns_providers(&self) -> Vec<DnsProvider> {
        if let Some(providers) = &self.dns_providers {
            providers.iter().map(|p| DnsProvider::from_str(p)).collect()
        } else {
            vec![]
        }
    }
}
