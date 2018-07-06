extern crate pnet;

mod icmp;
use icmp::IcmpHandler;

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
    IcmpHandler::new("10.0.2.15").run();
}
