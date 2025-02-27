use crate::cli::Args;
use crate::{dns::DnsPacket, shared::TxEvent};
use std::sync::mpsc::Sender;

pub mod cli_output;
pub mod tui_output;

pub use cli_output::*;
pub use tui_output::*;

pub type Tx = Sender<TxEvent>;

pub trait PacketHandler {
    fn handle_dns_packet(&self, d: DnsPacket, args: &Args);
    fn handle_network_packet(&self, d: &pcap::Packet, args: &Args);
}
