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
mod hdrs;
pub mod refresh;

pub fn run(dummy: &str) {
    let mut file = File::open("data/asn_prefixes.json").unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    let dict: hdrs::Dictionary = serde_json::from_str(&data).unwrap();
    let mut network_vec = Vec::new();

    for (key, value) in dict.into_iter() {
        let mut vec = value;
        network_vec.append(&mut vec);
    }
    info!("{}", network_vec.len());
    let mut trie = hdrs::create_trie(&mut network_vec);
    channel_runner(&mut trie);
}

pub fn channel_runner(networks: &mut Trie<Vec<u8>, RefCell<hdrs::network_state>>) {
    let rate = 10000;
    let handler = PingHandlerBuilder::new()
        .localip("172.30.65.57")
        .method(PingMethod::ICMP)
        .rate_limit(rate)
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
        hdrs::read_alive_ip(&r_handler, &sender);
    });

    // writer process
    let mut ratelimit = ratelimit_meter::LeakyBucket::new(rate, Duration::from_secs(1)).unwrap();
    //let max_pile = 1000u32;
    //let mut pile = 0u32;
    loop {
        let mut mybreak = true;

        for (key, value) in networks.iter() {
            if value.borrow().last {
                continue;
            }
            // todo let mut cnt= 0 cnt ++ si cnt > rate terminar
            if let Err(_) = ratelimit.check() {
                mybreak = false;
                break;
            }

            mybreak = false;
            let ip_network = value.borrow().address.clone();
            //reading thread created
            let i = value.borrow().current_ip.clone();
            let ip = ip_network.from(&value.borrow().current_ip, &ip_network.prefix);
            let last = ip_network.last();
            hdrs::write_alive_ip(&ip, &wr_handler);
            //let pile = pile + 1;
            if ip == last {
                value.borrow_mut().last = true;
            }
            value.borrow_mut().current_ip = i.add(BigUint::one());
        }

        // if an ip was received within the network
        // rewrite the map

        while let Ok(ip_received) = receiver.recv_timeout(Duration::from_millis(200)) {
            //let pile = pile.saturating_sub(1);
            let vec = hdrs::net_to_vector(&ip_received);
            let mut first = true;

            loop {
                let key;
                let mut remove = false;

                {
                    let mut node_match_op = networks.get_ancestor(&vec);

                    if node_match_op.is_some() {
                        let node = node_match_op.unwrap();
                        key = node.key().unwrap().clone();
                        let value = node.value().unwrap();
                        //let state = value.borrow().state.clone();
                        let network_add = value.borrow().address.clone();
                        // verify if the network matching isnt 0.0.0.0 (universe)
                        if network_add == hdrs::str_to_ip(&"0.0.0.0/0") {
                            //remove 0.0.0.0
                            remove = true;
                            break;
                        }
                        //if state { break;}
                        if network_add.includes(&ip_received) {
                            remove = true;
                            if first {
                                println!("{}", ip_received.to_s());
                                first = false;
                            }
                            // truncate vector to ancestors length
                            let len = key.len();
                        }
                    } else {
                        break;
                    }
                }
                if remove {
                    //todo
                    debug!("{}trielen", networks.len());
                    networks.remove(&key);
                }
            }
        }

        if mybreak {
            break;
        }
        // if all true break
    }
}
