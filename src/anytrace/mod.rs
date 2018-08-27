extern crate ping;
extern crate pnet;

use self::ping::{IcmpResponce, PingHandler, PingHandlerBuilder, PingMethod};
use self::pnet::packet::FromPacket;
use self::pnet::packet::Packet;
use self::pnet::packet::icmp::echo_request::{EchoRequest, EchoRequestPacket};
use self::pnet::packet::ipv4::Ipv4Packet;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct TraceConfiguration {
    source: Ipv4Addr,
    max_hop: u8,
    traces: Vec<Trace>,
}

#[derive(Debug)]
struct Trace {
    router: u32,
    hops: u8,
    ms: u64,
}

impl TraceConfiguration {
    fn new(source: Ipv4Addr, max_hops: u8) -> TraceConfiguration {
        return TraceConfiguration {
            source: source,
            max_hop: max_hops,
            traces: Vec::new(),
        };
    }
}

pub fn run(localip: &str) {
    /// Start listening to ICMP packets, and generating a traceroute as new networks
    /// start coming. Packets can be verified by their identifier, sequence_address and origin
    /// The process is as follow
    ///     Receive [A] EchoResponce
    ///         Check if address is not on HashMap:
    ///             Send EchoRequests to [A] with ttl of 1..n (DONT WRITE THE IP, as its not verified if its spoofing)
    ///             Add to the HashMap
    ///         else
    ///             Check the signature of the packet, to verify that is valid
    ///                 write
    ///     Receive [B] timeout
    ///         Check for original [A] address in HashMap
    ///             if id/seq are valid:
    ///                 Write the result, with the ttl (from the source packet) as the distance
    ///                     and the time diff.
    ///         If not on HashMap, goto [A] (This mean the packet is not verified, or came from
    ///             an invalid ip while sending the data)
    /// 
    /// Hint: Store the u24 ip address and u8 ttl

    let handler = PingHandlerBuilder::new()
        .localip(localip)
        .method(PingMethod::ICMP)
        .rate_limit(10)
        .build();

    handler.writer.send("1.1.1.1".parse().unwrap());
    handler.writer.send("8.8.8.8".parse().unwrap());
    let mut mapping: HashMap<u32, TraceConfiguration> = HashMap::new();
    loop {
        if let Ok(packet) = handler
            .reader
            .reader()
            .recv_timeout(Duration::from_millis(2000))
        {
            match &packet.icmp {
                ping::Responce::Echo(icmp) => {
                    debug!("{:?}, {:?}: ", packet.source, packet.ttl);
                    // Check if this is a new IP Address, only using his /24
                    let ip = u32::from(packet.source) & 0xFFFFFF00;
                    match mapping.entry(ip) {
                        Entry::Occupied(mut trace) => {
                            // TODO: Verify the received packet
                            info!(
                                "Network {}/24 already seen ({}) {}-{}",
                                Ipv4Addr::from(ip),
                                packet.source,
                                packet.ttl,
                                get_max_ttl(&packet)
                            );
                            if let Ok(_) = PingHandler::verify_signature(&icmp.payload) {
                                if verify_packet(packet.source, icmp.identifier, icmp.sequence_number) {
                                    trace.get_mut().traces.push(Trace {
                                        router: u32::from(packet.source),
                                        hops: icmp.sequence_number as u8,
                                        ms: 0,
                                    });
                                } else {
                                    error!("Error verifying");
                                }
                            } else {
                                    error!("Error verifying signature");

                            }
                        }
                        Entry::Vacant(v) => {
                            info!("New Network {}/24, ttl: {}", Ipv4Addr::from(ip), packet.ttl);
                            v.insert(TraceConfiguration::new(packet.source, get_max_ttl(&packet)));
                            for i in 0..get_max_ttl(&packet) {
                                let head : u16 = (ip >> 16) as u16;
                                let tail : u16 = (ip | (i+1) as u32) as u16;
                                // TODO: Remove key from the packets, so we know which one is from the local trace and which no
                                handler.writer.send_complete(
                                    packet.source,
                                    0,
                                    0,
                                    i + 1,    // ttl
                                    head, // identifier
                                    tail, // sequence
                                );
                            }
                        }
                    }
                }
                ping::Responce::Timeout(icmp) => {
                    debug!("{:?}, {:?}: ", packet.source, packet.ttl);
                    // The payload contains the EchoRequest packet + 64 bytes of payload if its over UDP or TCP
                    if let Ok((source, timeout)) = parse_icmp(&icmp.payload) {
                        info!(
                            "Received timeout for ({:?}, {:?}, {})",
                            timeout.identifier, timeout.sequence_number, source
                        );
                        // Verify the packet
                        if verify_packet(source, timeout.identifier, timeout.sequence_number) {
                            // the packet identification match the queried ip address, add it to the measures
                            let net = u32::from(source) & 0xFFFFFF00;
                            if let Some(trace) = mapping.get_mut(&net) {
                                trace.traces.push(Trace {
                                    router: u32::from(packet.source),
                                    hops: timeout.sequence_number as u8,
                                    ms: 0,
                                });
                                debug!("{:?}", trace);
                            }
                        }
                    }
                }
                ping::Responce::Unreachable(_icmp) => {
                    //parse_icmp(&icmp.payload);
                    //println!("Received unreachable for ({:?}, {:?})", icmp.icmp_type, icmp.icmp_code);
                }
            }
        }
    }
}

fn verify_packet(source: Ipv4Addr, identifier: u16, sequence: u16) -> bool {
    let network = u32::from(source) & 0xFFFFFF00;
    let ip = ((identifier as u32) << 16) | (sequence & 0xFF00) as u32;
    return network == ip;
}

fn get_max_ttl(packet: &IcmpResponce) -> u8 {
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
fn parse_icmp(data: &Vec<u8>) -> Result<(Ipv4Addr, EchoRequest), ()> {
    if let Some(ipv4) = Ipv4Packet::new(data) {
        if let Some(icmp) = EchoRequestPacket::new(ipv4.payload()) {
            let icmp = icmp.from_packet();
            // The payload is empty for icmp packets if they are not from TCP or UDP packets
            return Ok((Ipv4Addr::from(ipv4.get_destination()), icmp));
        }
    }
    return Err(());
}

/// Get the current time in milliseconds
fn time_from_epoch_ms() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let in_ms =
        since_the_epoch.as_secs() * 1000 + since_the_epoch.subsec_nanos() as u64 / 1_000_000;
    return in_ms;
}
