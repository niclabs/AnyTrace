extern crate ipaddress;
extern crate num;
extern crate num_traits;
extern crate ping;
extern crate pnet;
extern crate radix_trie;
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
use self::radix_trie::{SubTrie, Trie, TrieCommon};
use std::net::Ipv4Addr;
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hitlist::num::ToPrimitive;
use std::cell::RefCell;
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
    address: IPAddress,
    current_ip: BigUint,
    state: bool,
    last: bool,
}

pub fn str_to_ip(network: &str) -> IPAddress {
    let ip_network = IPAddress::parse(network).unwrap();
    return ip_network;
}

/*net_to_vector recieves a network string and returns a vector of bits 
for the net  */
pub fn net_to_vector(ip: &IPAddress) -> Vec<u8> {
    let host = ip.host_address.to_u32().unwrap();
    let mut vec = Vec::new();
    let mask = ip.prefix.get_prefix();
    for i in 0..mask {
        let num = ((host >> 31 - i) & 1) as u8;
        vec.push(num);
    }
    return vec;
}
/*create_trie : Vector of strings-> Trie key <vector of bits> Value <Network_state>
receives a vector of strings containing network addresses, and orders 
theese in a Trie struct
 */
pub fn create_trie(vec: &mut Vec<String>) -> Trie<Vec<u8>, RefCell<network_state>> {
    let mut trie = Trie::new();
    while vec.len() > 0 {
        let net = vec.pop().unwrap();
        let ip_net = str_to_ip(&net);
        let bit_vec = net_to_vector(&ip_net);
        let host_address = ip_net.network().host_address;
        trie.insert(
            bit_vec,
            RefCell::new(network_state {
                address: ip_net,
                current_ip: host_address,
                state: false,
                last: false,
            }),
        );
    }
    return trie;
}

// Dictionary for reading json file
type Dictionary = HashMap<String, Vec<String>>;

pub fn run(dummy: &str) {
    let mut file = File::open("data/asn_prefixes.json").unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    let dict: Dictionary = serde_json::from_str(&data).unwrap();
    let mut network_vec = Vec::new();

    for (key, value) in dict.into_iter() {
        let mut vec = value;
        network_vec.append(&mut vec);
    }
    //channel_runner(&mut network_hash);
    //println!("vector ready");
    let mut trie = create_trie(&mut network_vec);
    channel_runner(&mut trie);
}

pub fn channel_runner(networks: &mut Trie<Vec<u8>, RefCell<network_state>>) {
    let handler = PingHandlerBuilder::new()
        .localip("172.30.65.57")
        .method(PingMethod::ICMP)
        .rate_limit(100)
        .build();

    // channel between read/write thread
    // sender process sends message to receiver
    let (sender, receiver) = mpsc::channel::<IPAddress>();
    let sender = Arc::new(Mutex::new(sender));
    let r_handler = handler.reader;
    let wr_handler = handler.writer;

    // creating thread for reading
    // sender process
    let read = thread::spawn(move || {
        let mut sender = sender.lock().unwrap();
        read_alive_ip(&r_handler, &sender);
    });

    // writer process
    loop {
        let mut mybreak = true;

        for (key, value) in networks.iter() {
            if value.borrow().last {
                continue;
            }
            mybreak = false;
            let ip_network = value.borrow().address.clone();
            //reading thread created
            let i = value.borrow().current_ip.clone();
            let ip = ip_network.from(&value.borrow().current_ip, &ip_network.prefix);
            let last = ip_network.last();
            write_alive_ip(&ip, &wr_handler);
            if ip == last {
                value.borrow_mut().last = true;
            }
            value.borrow_mut().current_ip = i.add(BigUint::one());
        }

        // if an ip was received within the network
        // rewrite the map

        while let Ok(ip_received) = receiver.recv_timeout(Duration::from_millis(200)) {
            let mut vec = net_to_vector(&ip_received);
            let mut first = true;

            loop {
                let mut node_match_op = networks.get_ancestor(&vec);

                if node_match_op.is_some() {
                    let node = node_match_op.unwrap();
                    let key = node.key().unwrap();
                    let value = node.value().unwrap();
                    //let state = value.borrow().state.clone();
                    let network_add = value.borrow().address.clone();
                    // verify if the network matching isnt 0.0.0.0 (universe)
                    if network_add == str_to_ip(&"0.0.0.0/0") {
                        break;
                    }
                    //if state { break;}
                    if network_add.includes(&ip_received) {
                        networks.remove(&key);
                        //value.borrow_mut().state = true;
                        if first {
                            println!("{}", ip_received.to_s());
                            first = false;
                        }
                        // truncate vetor to ancestors length
                        let len = key.len();
                        vec.truncate(len);
                        continue;
                    }
                } else {
                    break;
                }
            }
        }

        if mybreak {
            break;
        }
        // if all true break
    }
}
/* auxiliary function for unwraping Option type without consuming self*/
fn return_unwrap<'a>(
    op: &'a Option<SubTrie<'a, Vec<u8>, RefCell<network_state>>>,
) -> &'a SubTrie<'a, Vec<u8>, RefCell<network_state>> {
    match op {
        &Some(ref val) => val,
        &None => panic!("called Option::unwrap() on a None value"),
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
