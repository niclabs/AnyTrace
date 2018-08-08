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
use std::thread;



pub fn run(network: &str) -> IPAddress {
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


    // canal entre thread lectura escritura
    // el proceso sender envía mensajes a receiver
    let (sender, receiver) = mpsc::channel::<IpAddress>();
    let sender = Arc::new(Mutex::new(sender));

    //crear thread para lectura
    //proceso sender
    let read = thread::spawn(move || {
        let mut sender = sender.lock().unwrap();
        read_alive_ip(handler, &sender);
    });

    // se crea thread para escritura
    while i <= ip_network.broadcast().host_address 
        {
            write_alive_ip((&ip_network.from(&i, &ip_network.prefix)), &handler);
            i = i.add(BigUint::one());
            let ip_received = receiver.recv().unwrap();
            //if received_ip in network break return received_ip  ?
            if ip_network.includes(ip_received)
            { 
                // todo enterrar el proceso hijo
                return ip_received;
            }
        }    

    
}

//envía un ping de cierta dirección ip a la nube
fn write_alive_ip(ip: &IPAddress, handler: &PingHandler) {
    let st = &ip.to_s();
    let target: Ipv4Addr = st.parse().unwrap();
    handler.writer.send(target); //envia ping a la nube
  
}

// lee el paquete de respueste y analiza el traceroute,
// si la respuesta viene de la ip correspondiente notifica 
// que la dirección esta viva 
fn read_alive_ip(handler: &PingHandler, sender: &mpsc::Sender<IcmpResponce>) {
     // packet respuesta
    while let Ok(packet) = handler
        .reader
        .reader()
        .recv()
    {
        match packet.icmp {
            // respuesta
            ping::Responce::Echo(icmp) => {
                if let Ok(ts) = PingHandler::get_packet_timestamp_ms(&icmp.payload, true) {

                    // todo pasar de IPv4Addr a IPAdress
                    let source = packet.source;
                    // mandar el source hacia afuera
                    
                    sender.send(source).unwrap();
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
};

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

