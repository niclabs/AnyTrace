extern crate pnet;

mod icmp;
use icmp::IcmpHandler;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/*
fn send_udp() -> std::io::Result<()> {
    use std::net::Ipv4Addr;
    use std::net::SocketAddrV4;
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:34254")?;

    // Redeclare `buf` as slice of the received data and send reverse data back to origin.
    let buf = [0u8; 0];
    let ip: Ipv4Addr = "1.1.1.33".parse().expect("couldn't parse ip address");
    let address = SocketAddrV4::new(ip, 34254);
    socket.set_ttl(2).unwrap();
    socket.send_to(&buf, address).expect("couldn't send data");
    return Ok(());
}
*/

fn main() {
    let handler = IcmpHandler::new("10.0.2.15");
    let target: Ipv4Addr = "1.1.1.1".parse().unwrap();
    for _ in 0..10 {
        handler.writer.send(target);
    }
    handler.writer.send_complete(target, 4, 33, 33);

    while let Ok(packet) = handler
        .reader
        .reader()
        .recv_timeout(Duration::from_millis(2000))
    {
        println!("{:?}, {:?}", packet.source, packet.ttl);
        match packet.icmp {
            icmp::Responce::Echo(packet) => {
                if let Ok(ts) = IcmpHandler::get_packet_timestamp_ms(&packet.payload) {
                    println!("Parsed correctly, delta: {}", time_from_epoch_ms() - ts);
                }
            }
            icmp::Responce::Timeout(_packet) => {
                // The payload contains the EchoRequest packet + 64 bytes of payload
                println!("Received timeout");
            }
        }
    }

    println!("ended");
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
