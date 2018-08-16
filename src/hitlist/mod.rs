extern crate ipaddress;
extern crate num;
extern crate num_traits;
extern crate ping;
extern crate pnet;

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

use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::collections::VecDeque;
use std::collections::HashMap;
use std::ops::Not;

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
pub fn run(network: &str){
    let mut networks = VecDeque::new();
    //let mut hnetworks= HashMap::new();
    //run2(network, &mut networks);
    let mut vec = vec!["1.1.1.0/24", "190.124.27.0/24", "1.1.1.0/24"]; 
    run3(&mut vec, &mut networks);
}

pub fn run2(network: &str, networks: &mut VecDeque<IPAddress>) -> Result<IPAddress, bool> {

    let network = "1.1.1.0/24";
    let handler = PingHandlerBuilder::new()
        .localip("172.30.65.57")
        .method(PingMethod::ICMP)
        .build();

    //converts string into ip network
    let ip_network = IPAddress::parse(network).unwrap();
    let ip_network_aux = IPAddress::parse(network).unwrap();
    networks.push_front(ip_network_aux);
    let st = ip_network.to_s();
    let mut i = ip_network.network().host_address;

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

    // se crea thread para escritura
    while i <= ip_network.broadcast().host_address {
        write_alive_ip((&ip_network.from(&i, &ip_network.prefix)), &wr_handler);
        i = i.add(BigUint::one());
        // while
        if let Ok(ip_received) = receiver.recv_timeout(Duration::from_millis(200)) {
            //if received_ip in network
            let mut i=0;
            while i<= networks.len(){
                let ip_network_aux = networks.pop_back().unwrap();
                if ip_network_aux.includes(&ip_received)
                    {
                    println!("{:?}", ip_received.to_s());
                    return Ok(ip_received);
                    }
                networks.push_front(ip_network_aux);
                i= i + 1;
            }
        }
    }
    return Err(false);
}

pub fn run3(Vnetwork: &mut Vec<&str>, networks: &mut VecDeque<IPAddress>) -> Result<IPAddress, bool> {

    let handler = PingHandlerBuilder::new()
        .localip("172.30.65.57")
        .method(PingMethod::ICMP)
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


    while Vnetwork.len()>0
    {
        let network= Vnetwork.pop().unwrap();
        let ip_network = IPAddress::parse(network).unwrap();
        let ip_network_aux = IPAddress::parse(network).unwrap();
        networks.push_front(ip_network_aux);
        let mut i = ip_network.network().host_address;

    // se crea thread para escritura
    while i <= ip_network.broadcast().host_address {
        write_alive_ip((&ip_network.from(&i, &ip_network.prefix)), &wr_handler);
        i = i.add(BigUint::one());
        // while
        if let Ok(ip_received) = receiver.recv_timeout(Duration::from_millis(200)) {
            //if received_ip in network
            let mut i=0; 
            while i< networks.len(){
                let ip_network_aux = networks.pop_back().unwrap();
                if ip_network_aux.includes(&ip_received)
                    {
                    println!("{:?}", ip_received.to_s());
                    //return Ok(ip_received);
                    break;
                    }
                networks.push_front(ip_network_aux);
                i= i + 1;
            }
        }
    }
    }
    return Err(false);
    
}


//envía un ping de cierta dirección ip a la nube
fn write_alive_ip(ip: &IPAddress, handler: &PingWriter) {
    let st = &ip.to_s();
    let target: Ipv4Addr = st.parse().unwrap();
    handler.send(target); //envia ping a la nube
}

// lee el paquete de respueste y analiza el traceroute,
// si la respuesta viene de la ip correspondiente notifica
// que la dirección esta viva
fn read_alive_ip(handler: &PingReader, sender: &mpsc::Sender<IPAddress>) {
    // packet respuesta
    while let Ok(packet) = handler.reader().recv() {
        match packet.icmp {
            // respuesta
            ping::Responce::Echo(icmp) => {
                if let Ok(ts) = PingHandler::get_packet_timestamp_ms(&icmp.payload, true) {
                    // todo pasar de IPv4Addr a IPAdress
                    let ipv4source = packet.source;
                    let source: IPAddress = IPAddress::parse(format!("{:?}", ipv4source)).unwrap();
                    // mandar el source hacia afuera
                    if let Err(_) = sender.send(source) {
                        // entierra el proceso hijo
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
