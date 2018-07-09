extern crate pnet;
extern crate ping;

use ping::{PingHandler, PingMethod};
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    let handler = PingHandler::new("10.0.2.15", PingMethod::ICMP);
    let target: Ipv4Addr = "1.1.122.12".parse().unwrap();
    for _ in 0..10 {
        handler.writer.send(target);
    }

    while let Ok(packet) = handler
        .reader
        .reader()
        .recv_timeout(Duration::from_millis(2000))
    {
        print!("{:?}, {:?}: ", packet.source, packet.ttl);
        match packet.icmp {
            ping::Responce::Echo(packet) => {
                if let Ok(ts) = PingHandler::get_packet_timestamp_ms(&packet.payload, true) {
                    println!("Parsed correctly, delta: {}", time_from_epoch_ms() - ts);
                }
            }
            ping::Responce::Timeout(_packet) => {
                // The payload contains the EchoRequest packet + 64 bytes of payload
                println!("Received timeout");
            }
            ping::Responce::Unreachable(_packet) => {
                println!("Received unreachable");
            }
        }
    }
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
