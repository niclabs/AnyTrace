extern crate pnet;

mod icmp;
use icmp::IcmpHandler;
use std::net::Ipv4Addr;

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
    use std::{thread, time};
    thread::sleep(time::Duration::from_millis(10000));
    while let Ok(packet) = handler.reader.reader().try_recv() {
        println!("{:?}, {:?}", packet.source, packet.ttl);
    }

    println!("ended");
}
