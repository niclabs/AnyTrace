extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmp::echo_reply::{EchoReply, EchoReplyPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::FromPacket;
use pnet::transport::{transport_channel, TransportReceiver, ipv4_packet_iter};

use pnet::transport::TransportChannelType::Layer3;

use std::net::Ipv4Addr;

use std::cell::RefCell;

use icmp::writer::IcmpWriter;

use std::thread;
use std::sync::mpsc;
use std::sync::Mutex;
use std::sync::Arc;

pub struct IcmpReader {
    reader: Arc<Mutex<RefCell<TransportReceiver>>>,
    _local: Ipv4Addr,
}

pub struct IcmpResponce {
    source: Ipv4Addr,
    icmp: EchoReply,
}

impl IcmpReader {
    pub fn new(local: Ipv4Addr) -> (IcmpReader, IcmpWriter) {
        let protocol = Layer3(IpNextHeaderProtocols::Icmp);
        let (tx, rx) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!(
                "An error occurred when creating the transport channel:
                            {}",
                e
            ),
        };

        return (IcmpReader {
            reader: Arc::new(Mutex::new(RefCell::new(rx))),
            _local: local,
        }, IcmpWriter::new(tx, local));
    }

    pub fn run(&mut self) -> mpsc::Receiver<IcmpResponce> {
        let reader = self.reader.clone();
        let local = self._local;

        let (sender, receiver) = mpsc::channel::<IcmpResponce>();
        thread::spawn(move || {
            match reader.try_lock() {
                Err(_) => panic!("You are not allowd to call IcmpReader::run() Twice"),
                Ok(lock) => {
                    let mut borrowed = lock.try_borrow_mut().unwrap();
                    let mut iter = ipv4_packet_iter(&mut borrowed);
                    loop {
                        let packet = iter.next();
                        if let Ok((packet, _)) = packet {
                            if let Err(_) = Self::process_ipv4(&packet, local, &sender) {
                                // Channel is closed, exit
                                return;
                            }
                        }
                    }
                }
            };          
        });

        return receiver;
    }

    fn process_ipv4(packet: &Ipv4Packet, local: Ipv4Addr, sender: &mpsc::Sender<IcmpResponce>) -> Result<(), ()> {
        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
             return Self::process_icmp4(packet.payload(), &packet, local, sender)
        }
        return Ok(());
    }

    fn process_icmp4(packet: &[u8], header: &Ipv4Packet, local: Ipv4Addr, sender: &mpsc::Sender<IcmpResponce>) -> Result<(), ()> {
        let icmp_packet = IcmpPacket::new(packet);
        if let Some(icmp) = icmp_packet {
            match icmp.get_icmp_type() {
                IcmpTypes::EchoReply => {
                    if let Some(icmp) = EchoReplyPacket::new(&packet) {
                        let responce = IcmpResponce {
                            source: Ipv4Addr::from(header.get_source()),
                            icmp: icmp.from_packet(),
                        };
                        if let Err(e) = sender.send(responce) {
                            return Err(());
                        }
                    }
                }
                IcmpTypes::TimeExceeded => {
                    let src = Ipv4Addr::from(header.get_source());
                    println!("TTL exceeded from {:?}", src);
                }
                IcmpTypes::EchoRequest => {
                    //let request = echo_request::EchoRequestPacket::new(&packet).unwrap();
                    println!("Request Sent");
                    println!("{:?}", header.packet());
                    let _src = Ipv4Addr::from(header.get_source());
                    //self.writer.try_borrow_mut().unwrap().send_icmp();
                }
                _ => {},           
            }
        }
        return Ok(());
    }
}
