// Function to extract IP addresses from a packet
pub fn extract_ip_addresses(data: &[u8]) -> (String, String) {
    // Ensure packet is large enough to contain Ethernet + IP headers
    if data.len() < 34 {
        // Minimum size for Ethernet (14) + IPv4 (20) headers
        return ("unknown".to_string(), "unknown".to_string());
    }

    // Skip Ethernet header (typically 14 bytes)
    let ethernet_header_size = 14;

    // Check if this is an IPv4 packet (EtherType 0x0800)
    let ethertype = ((data[12] as u16) << 8) | (data[13] as u16);
    if ethertype != 0x0800 {
        return ("unknown".to_string(), "unknown".to_string());
    }

    // Get IP header fields
    let ip_header = &data[ethernet_header_size..];

    // Extract source IP address (bytes 12-15 of IP header)
    let src_ip = format!(
        "{}.{}.{}.{}",
        ip_header[12], ip_header[13], ip_header[14], ip_header[15]
    );

    // Extract destination IP address (bytes 16-19 of IP header)
    let dst_ip = format!(
        "{}.{}.{}.{}",
        ip_header[16], ip_header[17], ip_header[18], ip_header[19]
    );

    (src_ip, dst_ip)
}
