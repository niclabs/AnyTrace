extern crate ipaddress;
extern crate num;
extern crate num_traits;
extern crate ping;
extern crate pnet;
extern crate rustc_serialize;
extern crate serde;
extern crate serde_json;

use self::ipaddress::IPAddress;
use self::num::bigint::BigUint;
use self::num_traits::identities::One;
use self::ping::PingReader;
use self::ping::PingWriter;
use self::ping::{PingHandler, PingHandlerBuilder, PingMethod};
use self::pnet::packet::icmp::destination_unreachable::DestinationUnreachable;
use self::pnet::packet::icmp::echo_reply::EchoReply;
use self::pnet::packet::icmp::time_exceeded::TimeExceeded;
use self::pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

pub enum Responce {
    Echo(EchoReply),
    Timeout(TimeExceeded),
    Unreachable(DestinationUnreachable),
}

pub struct IcmpResponce {
    pub source: Ipv4Addr,
    pub ttl: u8,
    pub icmp: Responce,
}

 /* test funcionality of ipaddess crate*/
pub fn testings(dummy: &str){
    let network= IPAddress::parse("255.255.0.0/16").unwrap();
    let netlast= network.last();
    println!("{:?}", netlast);

    let mut i = network.network().host_address;
    while i <= network.broadcast().host_address {
        println!("{:?}", &network.from(&i, &network.prefix));
        i = i.add(BigUint::one());
    }

/* runs through a vector of common and unknown networks
 for testing*/
pub fn test_run(dummy: &str) {
    let mut vec = vec![
        "1.1.1.0/24",
        "190.124.27.0/24",
        "1.1.1.0/24",
        "5.198.248.0/24",
        "223.233.20.0/20",
        "223.255.235.0/24",
    ];
    let mut network_hash = HashMap::new();
    while vec.len() > 0 {
        let net = vec.pop().unwrap();
        let host_address = str_to_ip(net).network().host_address;
        network_hash.insert(
            net.to_string(),
            network_state {
                current_ip: host_address,
                state: false,
                last: false,
            },
        );
    }
    channel_runner(&mut network_hash);
}

/*returns the network mask significant bit */
pub fn significant_bit (dummy: &str)
{
    let s1 = "193.168.0.0/17";
    let ip1= str_to_ip(&s1);
    let host = ip1.host_address.to_u32().unwrap();
    let mask = ip1.prefix.get_prefix();
    //let i = u32::from(ip1);
    if ((host>> 32-mask)&1)==1 { println!("{:#b}", (host >> (32-mask)) & 1);}
    else {println!("0");}
}
