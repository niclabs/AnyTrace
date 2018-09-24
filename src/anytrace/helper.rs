extern crate ping;
extern crate pnet;

use self::ping::IcmpResponce;
use self::pnet::packet::FromPacket;
use self::pnet::packet::Packet;
use self::pnet::packet::icmp::echo_request::{EchoRequest, EchoRequestPacket};
use self::pnet::packet::ipv4::Ipv4Packet;
use self::pnet::packet::ip::IpNextHeaderProtocols::{Udp, Icmp, Tcp};
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Encode the ip address and the ttl into the id and sequence number
/// Return the tuple (identifier, sequence_number)
pub fn encode_id_seq(address: u32, ttl: u8) -> (u16, u16) {
    let ip = u32::from(address) & 0xFFFFFF00;
    let identifier: u16 = (ip >> 16) as u16;
    let sequence: u16 = (ip as u16) | (ttl as u16);
    return (identifier, sequence);
}

/// Verify the ICMP packet source with his identifier and sequence
pub fn verify_packet(source: Ipv4Addr, identifier: u16, sequence: u16) -> bool {
    let network = u32::from(source) & 0xFFFFFF00;
    let ip = ((identifier as u32) << 16) | (sequence & 0xFF00) as u32;
    return network == ip;
}

/// Calculate the aproximate distance in hops to the given packet
pub fn get_max_ttl(packet: &IcmpResponce) -> u8 {
    let common = [64, 128, 255];
    for item in common.iter() {
        if packet.ttl <= *item {
            return *item - packet.ttl + 1 + 1; // Adding one extra for padding
        }
    }
    unreachable!();
}

/// Get the inner icmp information from a timeout packet.
/// Return the source address and the icmp echo request.
pub fn parse_icmp(data: &Vec<u8>) -> Result<(Ipv4Addr, EchoRequest), ()> {
    if let Some(ipv4) = Ipv4Packet::new(data) {
        if ipv4.get_next_level_protocol() == Icmp {
            return process_icmp(ipv4.payload(), ipv4.get_destination());
        } else if ipv4.get_next_level_protocol() == Udp {
            
        } else {
        }
    }
    return Err(());
}

/// Return the Ipv4Addr, Identifier and Sequence Number
fn process_icmp(payload: &[u8], destination: Ipv4Addr) -> Result<(Ipv4Addr, EchoRequest), ()> {
    if let Some(icmp) = EchoRequestPacket::new(payload) {
        let icmp = icmp.from_packet();
        // If payload is not empty, then is a TCP or UDP packet that contains the id and seq
        if icmp.payload.len() >= 2 {
            // Use first 32 bytes as id and seq
            let id : u16 = ((icmp.payload[0] as u16) << 8) | (icmp.payload[1] as u16);
            let seq : u16 = ((icmp.payload[2] as u16) << 8) | (icmp.payload[3] as u16);
            println!("Detected custom id seq ({}, {})", id, seq);
        }
        // The payload is empty for icmp packets if they are not from TCP or UDP packets
        return Ok((destination, icmp));
    }
    return Err(());
}

fn parse_udp(data: &Vec<u8>) -> Result<(Ipv4Addr, u8, u8),()> {
    if let Some(ipv4) = Ipv4Packet::new(data) {
        if ipv4.get_next_level_protocol() == Udp {
        }
    }
    return Err(());
}

/// Get the /24 mask of the given ip address as an u32
pub fn get_ip_mask(address: Ipv4Addr) -> u32 {
    return u32::from(address) & 0xFFFFFF00;
}

/// Get the current time in milliseconds
pub fn time_from_epoch_ms() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let in_ms =
        since_the_epoch.as_secs() * 1000 + since_the_epoch.subsec_nanos() as u64 / 1_000_000;
    return in_ms;
}
