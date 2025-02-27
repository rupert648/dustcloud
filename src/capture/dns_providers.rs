use once_cell::sync::Lazy;
use std::collections::HashMap;

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub enum DnsProvider {
    Cloudflare,
    Google,
    OpenDNS,
    Quad9,
    AdGuard,
    CleanBrowsing,
    Unknown,
}

impl DnsProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            DnsProvider::Cloudflare => "cloudflare",
            DnsProvider::Google => "google",
            DnsProvider::OpenDNS => "opendns",
            DnsProvider::Quad9 => "quad9",
            DnsProvider::AdGuard => "adguard",
            DnsProvider::CleanBrowsing => "cleanbrowsing",
            DnsProvider::Unknown => "unknown",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "cloudflare" => DnsProvider::Cloudflare,
            "google" => DnsProvider::Google,
            "opendns" => DnsProvider::OpenDNS,
            "quad9" => DnsProvider::Quad9,
            "adguard" => DnsProvider::AdGuard,
            "cleanbrowsing" => DnsProvider::CleanBrowsing,
            _ => DnsProvider::Unknown,
        }
    }
}

// Map of DNS providers to their IP addresses
pub static DNS_PROVIDERS: Lazy<HashMap<DnsProvider, Vec<String>>> = Lazy::new(|| {
    let mut map = HashMap::new();

    map.insert(
        DnsProvider::Cloudflare,
        vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
    );

    map.insert(
        DnsProvider::Google,
        vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
    );

    map.insert(
        DnsProvider::OpenDNS,
        vec!["208.67.222.222".to_string(), "208.67.220.220".to_string()],
    );

    map.insert(
        DnsProvider::Quad9,
        vec!["9.9.9.9".to_string(), "149.112.112.112".to_string()],
    );

    map.insert(
        DnsProvider::AdGuard,
        vec!["94.140.14.14".to_string(), "94.140.15.15".to_string()],
    );

    map.insert(
        DnsProvider::CleanBrowsing,
        vec!["185.228.168.9".to_string(), "185.228.169.9".to_string()],
    );

    map
});

pub fn get_provider_for_ip(ip: &str) -> DnsProvider {
    for (provider, ips) in DNS_PROVIDERS.iter() {
        if ips.contains(&ip.to_string()) {
            return *provider;
        }
    }
    DnsProvider::Unknown
}

pub fn get_filter_for_providers(providers: &[DnsProvider]) -> String {
    if providers.is_empty() {
        return "udp port 53".to_string(); // Default to all DNS traffic if no providers specified
    }

    // Collect all IP addresses from all requested providers
    let mut all_ips: Vec<String> = Vec::new();
    for provider in providers {
        if let Some(ips) = DNS_PROVIDERS.get(provider) {
            all_ips.extend(ips.iter().cloned());
        }
    }

    // Create the filter conditions
    let ip_conditions = all_ips
        .iter()
        .map(|ip| format!("host {}", ip))
        .collect::<Vec<_>>()
        .join(" or ");

    format!("udp port 53 and ({})", ip_conditions)
}

// Get a comma-separated list of all DNS providers
pub fn list_all_providers() -> String {
    let providers: Vec<&str> = DNS_PROVIDERS.keys().map(|p| p.as_str()).collect();

    providers.join(", ")
}
