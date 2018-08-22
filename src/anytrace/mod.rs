extern crate ping;
extern crate pnet;

use self::ping::{PingHandler, PingHandlerBuilder, PingMethod, IcmpResponce};
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
    let handler = PingHandlerBuilder::new()
        .localip(localip)
        .method(PingMethod::ICMP)
        .build();

    let target: Ipv4Addr = "1.1.1.1".parse().unwrap();
    for _ in 0..1 {
        handler.writer.send(target);
    }
    let mut mapping: HashMap<u32, TraceConfiguration> = HashMap::new();
    loop {
        if let Ok(packet) = handler
            .reader
            .reader()
            .recv_timeout(Duration::from_millis(2000))
        {
            print!("{:?}, {:?}: ", packet.source, packet.ttl);
            match &packet.icmp {
                ping::Responce::Echo(icmp) => {
                    // Check if this is a new IP Address, only using his /24
                    let ip = u32::from(packet.source) & 0xFFFFFF00;
                    match mapping.entry(ip) {
                        Entry::Occupied(trace) => {
                            println!("Network {}/24 already seen ({}) {}", Ipv4Addr::from(ip), packet.source, get_max_ttl(&packet));
                        }
                        Entry::Vacant(v) => {
                            println!("Network {}/24 new ({})", Ipv4Addr::from(ip), packet.source);
                            v.insert(TraceConfiguration::new(packet.source));
                            for i in 1..get_max_ttl(&packet) {
                                handler.writer.send_complete(
                                    packet.source,
                                    0,
                                    0,
                                    i,// ttl
                                    i as u16, // identifier
                                    i as u16 // sequence
                                );
                            }
                        }
                    }

                    if let Ok(ts) = PingHandler::get_packet_timestamp_ms(&icmp.payload, true) {
                        //println!("Parsed correctly, delta(ms): {}", time_from_epoch_ms() - ts);
                    }
                }
                ping::Responce::Timeout(icmp) => {
                    // The payload contains the EchoRequest packet + 64 bytes of payload
                    println!("Received timeout for ({:?}, {:?})", icmp.icmp_type, icmp.icmp_code);
                }
                ping::Responce::Unreachable(_packet) => {
                    println!("Received unreachable");
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
