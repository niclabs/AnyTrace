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

/*
pub fn run (dummy: &str){
    let s1 = "223.233.20.2/16";
    let s2 = "223.233.20.1/20";
    let ip1 = str_to_ip(&s1);
    let ip2= str_to_ip(&s2);
    println!("{:?}", ip1.first());
    println!("{:?}", ip2.gt(&ip1));
}*/

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

#[derive(Debug)]
pub struct network_state {
    current_ip: BigUint,
    state: bool,
    last: bool,
}

struct MyValue
{
    key: IPAddress,
    value: network_state,
}

struct MyTree {
    value: MyValue,
    l_leaf: MyTree,
    r_leaf: MyTree,
}

impl MyTree {

    fn origin() -> Point {
        Point { x: 0.0, y: 0.0 }
    }

    // Another static method, taking two arguments:
    fn new(x: f64, y: f64) -> Point {
        Point { x: x, y: y }
    }
}

#[derive(PartialEq)]
struct MyNode<'a> {
    val: &'a MyValue,
    l: Option<Box<MyNode<'a>>>,
    r: Option<Box<MyNode<'a>>>,
}
impl<'a> MyNode<'a> {
    pub fn insert(&mut self, new_val: &'a MyValue) {
        if self.val.key.eq(& new_val.key) {
            return
        }
        let target_node = if new_val.key.first().lt( & self.val.key.first()) { &mut self.l } else { &mut self.r };
        match target_node {
            &mut Some(ref mut subnode) => subnode.insert(new_val),
            &mut None => {
                let new_node = Node { val: new_val, l: None, r: None };
                let boxed_node = Some(Box::new(new_node));
                *target_node = boxed_node;
            }
        }
    }
}
/*
fn main () {
    let mut x = Node { val: "m", l: None, r: None };
    x.insert("z");
    x.insert("b");
    x.insert("c");
    assert!(x == Node {
        val: "m",
        l: Some(Box::new(Node {
            val: "b",
            l: None,
            r: Some(Box::new(Node { val: "c", l: None, r: None })),
        })),
        r: Some(Box::new(Node { val: "z", l: None, r: None })),
    });
}*/
