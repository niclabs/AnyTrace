extern crate pnet;

use pnet::packet::icmp::echo_reply::{EchoReply, EchoReplyPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::FromPacket;
use pnet::packet::Packet;
use pnet::transport::{ipv4_packet_iter, transport_channel, TransportReceiver};

use pnet::transport::TransportChannelType::Layer3;

use std::net::Ipv4Addr;

use icmp::writer::IcmpWriter;

use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

pub struct IcmpReader {
    pub reader: mpsc::Receiver<IcmpResponce>,
}

pub struct IcmpResponce {
    pub source: Ipv4Addr,
    pub ttl: u8,
    pub icmp: EchoReply,
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

        return (
            IcmpReader {
                reader: Self::run(local, rx),
            },
            IcmpWriter::new(tx, local),
        );
    }

    fn run(local: Ipv4Addr, reader: TransportReceiver) -> mpsc::Receiver<IcmpResponce> {
        let (sender, receiver) = mpsc::channel::<IcmpResponce>();
        let reader = Arc::new(Mutex::new(reader));
        thread::spawn(move || {
            let mut reader = reader.lock().unwrap();
            let mut iter = ipv4_packet_iter(&mut reader);
            loop {
                let packet = iter.next();
                if let Ok((packet, _)) = packet {
                    if let Err(_) = Self::process_ipv4(&packet, local, &sender) {
                        // Channel is closed, exit
                        return;
                    }
                }
            }
        });

        return receiver;
    }

    fn process_ipv4(
        packet: &Ipv4Packet,
        local: Ipv4Addr,
        sender: &mpsc::Sender<IcmpResponce>,
    ) -> Result<(), ()> {
        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
            return Self::process_icmp4(packet.payload(), &packet, local, sender);
        }
        return Ok(());
    }

    fn process_icmp4(
        packet: &[u8],
        header: &Ipv4Packet,
        _local: Ipv4Addr,
        sender: &mpsc::Sender<IcmpResponce>,
    ) -> Result<(), ()> {
        let icmp_packet = IcmpPacket::new(packet);
        if let Some(icmp) = icmp_packet {
            match icmp.get_icmp_type() {
                IcmpTypes::EchoReply => {
                    if let Some(icmp) = EchoReplyPacket::new(&packet) {
                        let responce = IcmpResponce {
                            source: Ipv4Addr::from(header.get_source()),
                            ttl: header.get_ttl(),
                            icmp: icmp.from_packet(),
                        };
                        if let Err(_) = sender.send(responce) {
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
                _ => {}
            }
        }
        return Ok(());
    }
}
