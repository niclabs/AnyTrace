extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::icmp::{checksum, echo_request, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, ipv4_packet_iter, TransportSender, TransportReceiver};

use pnet::transport::TransportChannelType::{Layer3, Layer4};

use std::net::Ipv4Addr;

use std::cell::RefCell;

pub struct IcmpReader {
    reader: RefCell<TransportReceiver>,
    writer: RefCell<IcmpWriter>,
}

impl IcmpReader {
    pub fn new() -> IcmpReader {
        let protocol = Layer3(IpNextHeaderProtocols::Icmp);
        let (_, rx) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!(
                "An error occurred when creating the transport channel:
                            {}",
                e
            ),
        };

        return IcmpReader {
            reader: RefCell::new(rx),
            writer: RefCell::new(IcmpWriter::new("asd")),
        };
    }

    pub fn run(&mut self) {
        let mut reader = self.reader.try_borrow_mut().unwrap();
        let mut reader = ipv4_packet_iter(&mut reader);
        loop {
            let packet = reader.next();
            println!("asd");
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
                }
                IcmpTypes::TimeExceeded => {
                    let src = Ipv4Addr::from(header.get_source());
                    println!("TTL exceeded from {:?}", src);
                }
                IcmpTypes::EchoRequest => {
                    //let request = echo_request::EchoRequestPacket::new(&packet).unwrap();
                    println!("Request Sent");
                    let _src = Ipv4Addr::from(header.get_source());
                    self.writer.try_borrow_mut().unwrap().send_icmp();
                }
                _ => {}
            }
        }
    }
}

pub struct IcmpWriter {
    tx: TransportSender,
}

impl IcmpWriter {
    fn new(_: &str) -> IcmpWriter {
        let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
        let (tx, _) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!(
                "An error occurred when creating the transport channel:
                            {}",
                e
            ),
        };

        return IcmpWriter { tx: tx };
    }

    fn send_icmp(&mut self) {
        let mut buffer = [0; 8 + 2];
        {
            
        }
        {
            let mut icmp = echo_request::MutableEchoRequestPacket::new(&mut buffer).unwrap();
            icmp.set_icmp_type(IcmpTypes::EchoRequest);
            icmp.set_icmp_code(echo_request::IcmpCodes::NoCode);
            icmp.set_identifier(1);
            icmp.set_sequence_number(2);
            icmp.set_payload(b"mt"); // TODO: Add timestamp
        }
        {
            let mut icmp = MutableIcmpPacket::new(&mut buffer).unwrap();
            let check = checksum(&icmp.to_immutable());
            icmp.set_checksum(check);
        }

        println!("Sended {:?}", buffer);
        match self.tx.send_to(
            IcmpPacket::new(&buffer).unwrap(),
            "127.0.0.1".parse().unwrap(),
        ) {
            Ok(_) => println!("ok"),
            Err(e) => panic!("failed to send packet: {}", e),
        };
    }
}
