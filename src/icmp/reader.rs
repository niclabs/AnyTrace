extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet};
use pnet::transport::{transport_channel, TransportReceiver, ipv4_packet_iter};

use pnet::transport::TransportChannelType::Layer3;

use std::net::Ipv4Addr;

use std::cell::RefCell;

use icmp::writer::IcmpWriter;

pub struct IcmpReader {
    reader: RefCell<TransportReceiver>,
    writer: RefCell<IcmpWriter>,
    _local: Ipv4Addr,
}

impl IcmpReader {
    pub fn new(local: Ipv4Addr) -> IcmpReader {
        let protocol = Layer3(IpNextHeaderProtocols::Icmp);
        let (tx, rx) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!(
                "An error occurred when creating the transport channel:
                            {}",
                e
            ),
        };

        return IcmpReader {
            reader: RefCell::new(rx),
            writer: RefCell::new(IcmpWriter::new(tx, local)),
            _local: local,
        };
    }

    pub fn run(&mut self) {
        let mut reader = self.reader.try_borrow_mut().unwrap();
        let mut reader = ipv4_packet_iter(&mut reader);
        self.writer.try_borrow_mut().unwrap().send_icmp();
        loop {
            let packet = reader.next();
            match packet {
                Ok((packet, _)) => {
                    self.process_ipv4(&packet);
                }
                Err(_) => {}
            }
        }
    }

    fn process_ipv4(&self, packet: &Ipv4Packet) {
        match packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Icmp => self.process_icmp4(packet.payload(), &packet),
            _ => {}
        }
    }

    fn process_icmp4(&self, packet: &[u8], header: &Ipv4Packet) {
        let icmp_packet = IcmpPacket::new(packet);
        if let Some(icmp) = icmp_packet {
            match icmp.get_icmp_type() {
                IcmpTypes::EchoReply => {
                    println!("Reply");
                    println!("{:?}", header.packet());
                    //self.writer.try_borrow_mut().unwrap().send_icmp();
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
    }
}
