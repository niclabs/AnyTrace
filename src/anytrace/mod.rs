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

struct TraceConfiguration {
    source: Ipv4Addr,
    current_hop: u8,
    max_hop: u8,
    traces: Vec<Trace>,
}

struct Trace {
    router: u32,
    hops: u32,
    ms: u64,
}

impl TraceConfiguration {
    fn new(source: Ipv4Addr) -> TraceConfiguration {
        return TraceConfiguration {
            source: source,
            current_hop: 0,
            max_hop: 0,
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
    ///             Check the signature of the packet, to verify that is valid and write
    ///     Receive [B] timeout
    ///         Check for original [A] address in HashMap
    ///             if id/seq are valid:
    ///                 Write the result, with the ttl (from the source packet) as the distance
    ///                     and the time diff.
    ///         If not on HashMap, goto [A] (This mean the packet is not verified, or came from
    ///             an invalid ip while sending the data)
    let handler = PingHandlerBuilder::new()
        .localip(localip)
        .method(PingMethod::ICMP)
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
                    print!("{:?}, {:?}: ", packet.source, packet.ttl);
                    // Check if this is a new IP Address, only using his /24
                    let ip = u32::from(packet.source) & 0xFFFFFF00;
                    match mapping.entry(ip) {
                        Entry::Occupied(trace) => {
                            println!(
                                "Network {}/24 already seen ({}) {}",
                                Ipv4Addr::from(ip),
                                packet.source,
                                get_max_ttl(&packet)
                            );
                        }
                        Entry::Vacant(v) => {
                            println!("New Network {}/24", Ipv4Addr::from(ip));
                            v.insert(TraceConfiguration::new(packet.source));
                            for i in 0..get_max_ttl(&packet) {
                                handler.writer.send_complete(
                                    packet.source,
                                    0,
                                    0,
                                    i + 1,    // ttl
                                    i as u16, // identifier
                                    i as u16, // sequence
                                );
                            }
                        }
                    }

                    // TODO: Store the timestamp at the receiving channel
                    if let Ok(ts) = PingHandler::get_packet_timestamp_ms(&icmp.payload, true) {
                        println!("Echo Verified, delta(ms): {}", time_from_epoch_ms() - ts);
                    }
                }
                ping::Responce::Timeout(icmp) => {
                    print!("{:?}, {:?}: ", packet.source, packet.ttl);
                    // The payload contains the EchoRequest packet + 64 bytes of payload if its over UDP or TCP
                    if let Ok((source, timeout)) = parse_icmp(&icmp.payload) {
                        println!(
                            "Received timeout for ({:?}, {:?}, {})",
                            timeout.identifier, timeout.sequence_number, source
                        );
                    }
                    //println!("{:x?}", icmp.payload);
                }
                ping::Responce::Unreachable(icmp) => {
                    //parse_icmp(&icmp.payload);
                    //println!("Received unreachable for ({:?}, {:?})", icmp.icmp_type, icmp.icmp_code);
                }
            }
        }
    }
}

fn get_max_ttl(packet: &IcmpResponce) -> u8 {
    let common = [64, 128, 255];
    for item in common.iter() {
        if packet.ttl <= *item {
            return *item - packet.ttl + 1;
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
