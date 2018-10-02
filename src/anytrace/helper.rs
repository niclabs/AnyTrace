extern crate ping;
extern crate pnet;

use self::ping::IcmpResponce;
use self::pnet::packet::FromPacket;
use self::pnet::packet::Packet;
use self::pnet::packet::icmp::echo_request::EchoRequestPacket;
use self::pnet::packet::ip::IpNextHeaderProtocols::{Icmp, Udp};
use self::pnet::packet::ipv4::Ipv4Packet;
use self::pnet::packet::udp::UdpPacket;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::ops::BitXor;

/// Encode the ip address and the ttl into the id and sequence number, applying the given key
/// Return the tuple (identifier, sequence_number)
pub fn encode_id_seq_key(address: u32, ttl: u8, key: u16) -> (u16, u16) {
    let (id, seq) = encode_id_seq(address, ttl);
    return (id.bitxor(key), seq.bitxor(key));
}

/// Decode the id and seq to obtain the original (netowrk, ttl) tuple, applying the given key
pub fn decode_id_seq_key(id: u16, seq: u16, key: u16) -> (u32, u8) {
    return decode_id_seq(id.bitxor(key), seq.bitxor(key));
}

/// Decode the id and seq to obtain the original (netowrk, ttl) tuple.
pub fn decode_id_seq(id: u16, seq: u16) -> (u32, u8) {
    return ((id as u32) << 16 | (seq & 0xFF00) as u32, seq as u8);
}
/// Encode the ip address and the ttl into the id and sequence number
/// Return the tuple (identifier, sequence_number)
pub fn encode_id_seq(address: u32, ttl: u8) -> (u16, u16) {
    let ip = u32::from(address) & 0xFFFFFF00;
    let identifier: u16 = (ip >> 16) as u16;
    let sequence: u16 = (ip as u16) | (ttl as u16);
    return (identifier, sequence);
}

pub fn verify_packet_network(source: Ipv4Addr, network: u32) -> bool {
    let source = get_ip_mask(source);
    return source == network;
}

/// Verify the ICMP packet source with his identifier and sequence
pub fn verify_packet(source: Ipv4Addr, identifier: u16, sequence: u16) -> bool {
    let network = u32::from(source) & 0xFFFFFF00;
    let (ip, _) = decode_id_seq(identifier, sequence);
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
pub fn parse_icmp(data: &Vec<u8>) -> Result<(Ipv4Addr, u16, u16), ()> {
    if let Some(ipv4) = Ipv4Packet::new(data) {
        if ipv4.get_next_level_protocol() == Icmp {
            return process_icmp(ipv4.payload(), ipv4.get_destination());
        } else if ipv4.get_next_level_protocol() == Udp {
            return process_udp(ipv4.payload(), ipv4.get_destination());
        } else {
        }
    }
    return Err(());
}

/// Return the Ipv4Addr, Identifier and Sequence Number
fn process_icmp(payload: &[u8], destination: Ipv4Addr) -> Result<(Ipv4Addr, u16, u16), ()> {
    if let Some(icmp) = EchoRequestPacket::new(payload) {
        let icmp = icmp.from_packet();

        // The payload is empty for icmp packets if they are not from TCP or UDP packets
        return Ok((destination, icmp.identifier, icmp.sequence_number));
    }
    return Err(());
}

fn process_udp(payload: &[u8], destination: Ipv4Addr) -> Result<(Ipv4Addr, u16, u16), ()> {
    if let Some(udp) = UdpPacket::new(payload) {
        let payload = udp.payload();
        // Use the stored id and seq on the source/destination port
        let id = udp.get_source();
        let seq = udp.get_destination();
        return Ok((destination, id, seq));
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
