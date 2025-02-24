use crate::cli::Args;

use super::dns_providers::get_filter_for_providers;

// TODO(RC): make way more generic to allow passing arbitrary data types through this
pub fn build_capture_filter(args: &Args) -> String {
    let providers = args.get_dns_providers();
    let wah = if !providers.is_empty() {
        get_filter_for_providers(&providers)
    } else if args.dns_only {
        // Filter for all DNS traffic
        "udp port 53 or tcp port 53".to_string()
    } else {
        // Capture all traffic
        "".to_string()
    };

    println!("DEBUG: Generated filter: >{}<", wah);
    wah
}
