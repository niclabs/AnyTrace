extern crate ping;
extern crate pnet;
extern crate ipaddress;
extern crate num;
extern crate num_traits;

use self::ipaddress::IPAddress;
use self::num::bigint::BigUint;
use self::num_traits::identities::One;
use self::ping::{PingHandler, PingHandlerBuilder, PingMethod};
use std::net::Ipv4Addr;
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};



pub fn run(network: &str) {
    let network = "1.1.1.54/24";
    let handler = PingHandlerBuilder::new()
        .localip("172.30.65.57")
        .method(PingMethod::ICMP)
        .build();

    //converts string into ip network
    let ip_network = IPAddress::parse(network).unwrap();
    let st = ip_network.to_s();
    let prefix = ip_network.prefix();
    //last ip adress within the mask network
    let last = ip_network.last().to_s();
    //println!("result {} {:?}", last, prefix);

    let mut i = ip_network.network().host_address;
    while i <= ip_network.broadcast().host_address {
        if let Ok(result) = find_alive_ip((&ip_network.from(&i, &ip_network.prefix)), &handler) {
            break;
        };
        i = i.add(BigUint::one());
    }

    //let ip =ip_network.each( |i| {let _ = find_alive_ip(i, &handler);});
}
fn find_alive_ip(ip: &IPAddress, handler: &PingHandler) -> Result<Ipv4Addr, bool> {
    let st = &ip.to_s();
    let target: Ipv4Addr = st.parse().unwrap();
    handler.writer.send(target); //envia ping a la nube

    // packet respuesta
    while let Ok(packet) = handler
        .reader
        .reader()
        .recv_timeout(Duration::from_millis(2000))
    {
        match packet.icmp {
            // respuesta
            ping::Responce::Echo(packet) => {
                if let Ok(ts) = PingHandler::get_packet_timestamp_ms(&packet.payload, true) {
                    println!("Parsed correctly, delta(ms) {}", target);
                    return Ok(target);
                }
            }
            ping::Responce::Timeout(_packet) => {
                //println!("Received timeout{}", target);
            }
            ping::Responce::Unreachable(_packet) => {
                //println!("Received unreachable {}", target);
            }
        }
    }
    return Err(false);
  
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

