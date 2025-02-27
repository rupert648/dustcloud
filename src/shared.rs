use std::time::SystemTime;

use crate::capture::dns_providers::DnsProvider;

/// Types for sharing between tx/rx channels
#[derive(Clone, Debug)]
pub enum TxEvent {
    DnsQuery {
        domain: String,
        query_type: String,
        provider: DnsProvider,
        source: String,
        destination: String,
        timestamp: SystemTime,
    },
}
