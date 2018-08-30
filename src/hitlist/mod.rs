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

/* network_state: saves de current host adress iterator
of a network,
and its state -> alive/not found yet
 */
#[derive(Debug)]
pub struct network_state {
    current_ip: BigUint,
    state: bool,
    last: bool,
}

pub fn str_to_ip(network: &str) -> IPAddress {
    let ip_network = IPAddress::parse(network).unwrap();
    return ip_network;
}

// Dictionary for reading json file
type Dictionary = HashMap<String, Vec<String>>;

pub fn run(dummy: &str) {
    let mut file = File::open("data/asn_prefixes.json").unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    let dict: Dictionary = serde_json::from_str(&data).unwrap();
    let mut network_hash = HashMap::new();

    for (key, value) in dict.into_iter() {
        let mut vec = value;
        //let mut network_hash = HashMap::new();
        while vec.len() > 0 {
            let net = vec.pop().unwrap();
            let host_address = str_to_ip(&net).network().host_address;
            network_hash.insert(
                net.to_string(),
                network_state {
                    current_ip: host_address,
                    state: false,
                    last: false,
                },
            ); 
        }
        //channel_runner_v2(&mut network_hash);
    }
    channel_runner_v2(&mut network_hash);

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
    channel_runner_v2(&mut network_hash);
}

pub fn channel_runner_v2(networks: &mut HashMap<String, network_state>) {
    let handler = PingHandlerBuilder::new()
        .localip("172.30.65.57")
        .method(PingMethod::ICMP)
        .rate_limit(100)
        .build();

    // canal entre thread lectura escritura
    // el proceso sender envía mensajes a receiver
    let (sender, receiver) = mpsc::channel::<IPAddress>();
    let sender = Arc::new(Mutex::new(sender));
    let r_handler = handler.reader;
    let wr_handler = handler.writer;

    //crear thread para lectura
    //proceso sender
    let read = thread::spawn(move || {
        let mut sender = sender.lock().unwrap();
        read_alive_ip(&r_handler, &sender);
    });

    // writer process
    loop {
        //let mut dead = false;
        //let mut dead_nw = 0;
        for (key, value) in networks.into_iter() {
            if value.state || value.last {
                continue;
            }
            let aux_key = key.clone();
            let ip_network = IPAddress::parse(aux_key).unwrap();
            // se crea thread para escritura
            let i = value.current_ip.clone();
            let ip = ip_network.from(&value.current_ip, &ip_network.prefix);
            let last = ip_network.last();
            write_alive_ip(&ip, &wr_handler);
            if (ip == last) {
                value.last = true;
            }
            value.current_ip = i.add(BigUint::one());
        }

        //if an ip was received within the network
        // rewrite the map
       
        while let Ok(ip_received) = receiver.recv_timeout(Duration::from_millis(200)) {
            for (key, value) in networks.into_iter() {
                if value.state {continue;}
                let aux_key = key.clone();
                let mut network = IPAddress::parse(aux_key).unwrap();
                //let mut network = IPAddress::parse(format!("{:?}", key)).unwrap();
                if network.includes(&ip_received){
                    value.state = true;
                    println!("{:?}", ip_received.to_s());
                    //return Ok(ip_received);
                    break;
                }
            }
        }
        let mut mybreak = true;
        for (key, value) in networks.into_iter() {
            if (!value.state && !value.last) {
                mybreak = false;
            }
        }
        if mybreak {
            break;
        }
        // if all true break
    }
}

/* write_aliv_ip : &IPAdress x &PingHAndles -> Void
sends a ping to ip adress "ip" using handler param
*/

fn write_alive_ip(ip: &IPAddress, handler: &PingWriter) {
    let st = &ip.to_s();
    let target: Ipv4Addr = st.parse().unwrap();
    handler.send(target); //pinging
}

/* read_alive_ip : &Pinghandler x & Sender<IPAdress> ->Void
reads the incoming response packages and analizes the traceroute,
sending the source ip from the last alive ip found, back to the writer process
*/
fn read_alive_ip(handler: &PingReader, sender: &mpsc::Sender<IPAddress>) {
    // response packet
    while let Ok(packet) = handler.reader().recv() {
        match packet.icmp {
            // response
            ping::Responce::Echo(icmp) => {
                if let Ok(ts) = PingHandler::get_packet_timestamp_ms(&icmp.payload, true) {
                    let ipv4source = packet.source;
                    let source: IPAddress = IPAddress::parse(format!("{:?}", ipv4source)).unwrap();
                    //sends source back to writer process
                    if let Err(_) = sender.send(source) {
                        // burries child process
                        return;
                    }
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
}
/* time_from_epoch_ms :Void-> Void
 Get the current time in milliseconds*/
fn time_from_epoch_ms() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let in_ms =
        since_the_epoch.as_secs() * 1000 + since_the_epoch.subsec_nanos() as u64 / 1_000_000;
    return in_ms;
}
