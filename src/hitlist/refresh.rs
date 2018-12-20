extern crate ipaddress;
extern crate num;
extern crate num_traits;
extern crate ping;
extern crate pnet;
extern crate radix_trie;
extern crate rustc_serialize;
extern crate serde;
extern crate serde_json;
extern crate ratelimit_meter;

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
use std::borrow::Borrow;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use hitlist::ratelimit_meter::Decider;
use hitlist::num::ToPrimitive;
use std::cell::RefCell;
use std::collections::HashMap;

use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::io::Read;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use ::hitlist::hdrs;

pub fn refresh_file(jsonpath: &String, ipfilepath: &String, local_ip: &String, blacklist_path: Option<&String>)
{   
    //creating trie from asn file
    let mut jsonfile = File::open(jsonpath).unwrap();
    let mut jsondata = String::new();
    jsonfile.read_to_string(&mut jsondata).unwrap();
    let dict: hdrs:: Dictionary = serde_json::from_str(&jsondata).unwrap();
    let mut network_vec = Vec::new();

    for (key, value) in dict.into_iter() {
        let mut vec = value;
        network_vec.append(&mut vec);
    }

     //reading black list of networks
    let mut bdata =  Vec::new();
    if blacklist_path.is_some(){
        let this_path= (&blacklist_path.unwrap()).clone();
        let bf= File::open(this_path).unwrap();
        let bfile= BufReader::new(&bf);
        for (num, line) in bfile.lines().enumerate() {
            let l = line.unwrap();
            bdata.push(l);
        }
    }
    //black list trie
    let mut blist_trie = hdrs::create_trie(&mut bdata);
    // general trie
    let mut trie = hdrs::create_trie(&mut network_vec);

    //reading ip file into a vector

    let f = File::open(ipfilepath).unwrap();
    let file = BufReader::new(&f);
    let mut data = Vec::new();
    for (num, line) in file.lines().enumerate() {
        let l = line.unwrap();
        data.push(l);
        }

    //initilizing handler for ping
    let rate= 10000;
    let handler = PingHandlerBuilder::new()
        .localip(local_ip)
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
     
    // visits every ip in the ip file
    loop{
        //verify if every ip in the file was already pinged

        let mut iter =0;
        let mut j= 0;
        for ip in data.iter(){
            //rate limit was reached
            if let Err(_) = ratelimit.check() {
                break;
            }
            iter+=1;
            let this_ip= hdrs::str_to_ip(ip);
            hdrs::write_alive_ip(&this_ip, &wr_handler);
            
        }
        while j<iter{
            data.remove(0);
            j+=1;
        }
       
        refresh_trie(&mut trie,&receiver);

        if data.len()==0{
            break;}
        
    }
    
    /*once the entire ip file is pinged
     the remaining networks in the trie must be pinged*/
    loop{
        let mut mybreak = true;
        let mut remove_vec= Vec::new();

        debug!("sending");
        for (key, value) in trie.iter() {

            if let Err(_) = ratelimit.check() {
                    mybreak = false;
                    break;
                }

            if value.borrow().last {
                remove_vec.push(key.clone());
                continue;
            }

            // verify if actual network is in blacklist
            let node_match_op = blist_trie.get_ancestor(key);
            if node_match_op.is_some() {
                value.borrow_mut().last = true;
                continue;
            }
            
            mybreak = false;

            let mut it =0;
            while it< value.borrow().sent{
                   
                if let Err(_) = ratelimit.check() {
                    mybreak = false;
                    break;
                }

                let ip_network = value.borrow().address.clone();
                let i = value.borrow().current_ip.clone();
                let ip = ip_network.from(&value.borrow().current_ip, &ip_network.prefix);
                //verify if this ip is the last ip to be consulted
                let last = ip_network.last();
                // ip in mask 32
                let ip_32= ip.change_prefix(32).unwrap();
                if ip == last {
                        hdrs::write_alive_ip(&ip, &wr_handler);
                        value.borrow_mut().last = true;
                        break;
                    }
                // verify if  ip is in blacklist
                let node_match_op = blist_trie.get_ancestor(&hdrs::net_to_vector(&ip_32));
                if node_match_op.is_some() {
                    debug!("skipped ip in blacklist");
                    value.borrow_mut().current_ip = i.add(BigUint::one());
                    it+=1;
                    continue;
                }
                else
                {   
                    hdrs::write_alive_ip(&ip_32, &wr_handler);
                    value.borrow_mut().current_ip = i.add(BigUint::one());
                    it+=1;
                }
            }
            let n= value.borrow_mut().sent;
            value.borrow_mut().sent += 2;
        }
        refresh_trie(&mut trie, &receiver);
        
        
        if mybreak {
            break;
        }

        while remove_vec.len() > 0 {
            let k = remove_vec.pop().unwrap();
            trie.remove(&k);
        }

        debug!("{} new trielen", trie.len());

    }
}

/* 
refresh_trie: trie: trie<vector, refcell>-> void 
verifiying if that ip belongs to a network from
the trie
->removes the network from the trie*/

pub fn refresh_trie(trie: &mut Trie<Vec<u8>, RefCell<hdrs::network_state>>, receiver: &Receiver<IPAddress>){

    while let Ok(ip_received) = receiver.recv_timeout(Duration::from_millis(200)){
            let vec = hdrs::net_to_vector(&ip_received);
            
            let mut first = true;
            loop {
                    let key;
                    let mut remove = false;
                    {
                        let mut node_match_op = trie.get_ancestor(&vec);

                        if node_match_op.is_some() {
                            let node = node_match_op.unwrap();
                            key = node.key().unwrap().clone();
                            remove= true;
                            if first {
                                    println!("{}", ip_received.to_s());
                                    first = false;
                                }
                            
                        } else {
                            break;
                        }
                    }
                    if remove {
                        trie.remove(&key);
                        debug!("{}trielen",trie.len());
                    }
                }
        }

}

// UNIT TESTING

#[test]
 // this tests verifies blacklist functionality
 fn test1(){
     let mut b_vec = vec![
         String::from("10.0.0.0/8"),
         String::from("13.0.0.0/8"),
         String::from("1.0.0.0/8"),
    
     ];
     let mut l_vec = vec![
         String::from("13.79.45.3/32"),
     ];
    let vec= hdrs:: net_to_vector(&IPAddress::parse("1.1.1.1/32").unwrap());
    let b_trie= hdrs::create_trie(& mut b_vec);
    let l_trie= hdrs::create_trie(&mut l_vec);
    assert_eq!(b_trie.get_ancestor(&vec).is_some() ,true);
    
    
    for(key,value) in l_trie.iter(){
        let node= b_trie.get_ancestor(key);
        assert_eq!(node.is_some(), true);
    }


 }

#[test]
 // this test verifies universe network contains every network
 fn test2(){

     let mut b_vec = vec![
         String::from("1.0.0.0/1"),
         String::from("128.0.0.0/1"),
     ];
     
    let b_trie= hdrs::create_trie(& mut b_vec);
    assert_eq!(b_trie.get_ancestor(&hdrs:: net_to_vector(&IPAddress::parse("255.255.255.245/32").unwrap())).is_some() ,true);
    assert_eq!(b_trie.get_ancestor(&hdrs:: net_to_vector(&IPAddress::parse("0.0.0.1/32").unwrap())).is_some() ,true);


    let test_ip = IPAddress::parse("1.1.1.1").unwrap();
    assert_eq!(test_ip.prefix.get_prefix(), 32);
 }

 #[test]
 // test verifies ip is skipped if it is in a blacklisted network

  fn test3(){

     let mut b_vec = vec![
         String::from("1.0.0.0/1"),
         String::from("128.0.0.0/1"),
     ];
    //---------part1------------------------------------------------------------------
    let b_trie= hdrs::create_trie(& mut b_vec);
    let mut vec = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
    assert_eq!(vec, hdrs::net_to_vector(&IPAddress::parse("255.255.255.255/32").unwrap()));

    //---------part2------------------------------------------------------------------
    
    let test_ip = IPAddress::parse("0.0.0.0/0").unwrap();
    let first= test_ip.first();
    let first_32 = first.change_prefix(32).unwrap();
    println!("{}", first.to_s());
    println!("{}", first.prefix.get_prefix());
    let mut vec2 = vec![0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
    assert_eq!(vec2, hdrs::net_to_vector(&first_32));
    

    //---------part3------------------------------------------------------------------
    
    let ip_net = IPAddress::parse("0.0.0.0/8").unwrap();
    let last = ip_net.last();
    println!("{}", last.to_s());
    let bit_vec = hdrs::net_to_vector(&ip_net);
    let mut host_address = ip_net.network().host_address.add(BigUint::one());;
    let ip = ip_net.from(&host_address, &ip_net.prefix);
    let new_ip= ip.change_prefix(32).unwrap();
    println!("{}", ip.prefix.get_prefix());
    assert_eq!(IPAddress::parse("0.0.0.1").unwrap(), new_ip);
    
    
 }

