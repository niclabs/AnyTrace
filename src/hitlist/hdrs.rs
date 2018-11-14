extern crate ipaddress;
extern crate num;
extern crate num_traits;
extern crate ping;
extern crate pnet;
extern crate radix_trie;
extern crate ratelimit_meter;
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
use hitlist::ratelimit_meter::Decider;
use std::borrow::Borrow;
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
    pub address: IPAddress,
    pub current_ip: BigUint,
    pub last: bool,
    pub sent: i32,
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
                last: false,
                sent:1,
            }),
        );
    }
    return trie;
}
/* creates a trie from a vector, filtering those networks within the blacklist of ips*/
pub fn create_trie_filtered(vec: &mut Vec<String>, blcklist: &mut Trie<Vec<u8>, RefCell<network_state>>) 
-> Trie<Vec<u8>, RefCell<network_state>> 
{
    let mut trie = Trie::new();
    while vec.len() > 0 {
        let net = vec.pop().unwrap();
        let ip_net = str_to_ip(&net);
        let bit_vec = net_to_vector(&ip_net);
        let host_address = ip_net.network().host_address;
        let node_match_op = blcklist.get_ancestor(&bit_vec);
        if node_match_op.is_some() {
            continue;
        }
        trie.insert(
            bit_vec,
            RefCell::new(network_state {
                address: ip_net,
                current_ip: host_address,
                last: false,
                sent:1,
            }),
        );
    }
    return trie;  
}

// Dictionary for reading json file
pub type Dictionary = HashMap<String, Vec<String>>;

/* write_aliv_ip : &IPAdress x &PingHAndles -> Void
sends a ping to ip adress "ip" using handler param
*/

pub fn write_alive_ip(ip: &IPAddress, handler: &PingWriter) {
    let st = &ip.to_s();
    let target: Ipv4Addr = st.parse().unwrap();
    handler.send(target); //pinging
}

/* read_alive_ip : &Pinghandler x & Sender<IPAdress> ->Void
reads the incoming response packages and analizes the traceroute,
sending the source ip from the last alive ip found, back to the writer process
*/
pub fn read_alive_ip(handler: &PingReader, sender: &mpsc::Sender<IPAddress>) {
    // response packet
    while let Ok(packet) = handler.reader().recv() {
        match packet.icmp {
            // response
            ping::Responce::Echo(icmp) => {
                if let Ok(ts) = PingHandler::get_packet_timestamp_ms(&icmp.payload) {
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
            ping::Responce::LocalSendedEcho(_) => {}
        }
    }
}
