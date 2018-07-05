extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::icmp::{checksum, echo_request, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::transport::{transport_channel, ipv4_packet_iter, TransportSender, TransportReceiver};

use pnet::transport::TransportChannelType::Layer3;

use std::net::Ipv4Addr;

use std::cell::RefCell;

pub struct IcmpReader {
    reader: RefCell<TransportReceiver>,
    writer: RefCell<IcmpWriter>,
}

impl IcmpReader {
    pub fn new() -> IcmpReader {
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
            writer: RefCell::new(IcmpWriter::new(tx)),
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

pub struct IcmpWriter {
    tx: TransportSender,
}

impl IcmpWriter {
    fn new(tx: TransportSender) -> IcmpWriter {
        return IcmpWriter { tx: tx };
    }

    fn send_icmp(&mut self) {
        let mut buffer = [0; 20 + 8 + 2];
        Self::format_icmp(&mut buffer[20..]);
        Self::format_ipv4(&mut buffer);

        println!("Sending {:?}", buffer);
        match self.tx.send_to(
            Ipv4Packet::new(&buffer).unwrap(),
            "1.1.1.1".parse().unwrap(),
        ) {
            Ok(_) => println!("ok"),
            Err(e) => panic!("failed to send packet: {}", e),
        };
    }

    fn format_icmp(buffer: &mut [u8]) {
        {
            let mut icmp = echo_request::MutableEchoRequestPacket::new(buffer).unwrap();
            icmp.set_icmp_type(IcmpTypes::EchoRequest);
            icmp.set_icmp_code(echo_request::IcmpCodes::NoCode);
            icmp.set_identifier(1);
            icmp.set_sequence_number(2);
            icmp.set_payload(b"mt"); // TODO: Add timestamp
        }
        {
            let mut icmp = MutableIcmpPacket::new(buffer).unwrap();
            let check = checksum(&icmp.to_immutable());
            icmp.set_checksum(check);
        }
    }

    fn format_ipv4(buffer: &mut [u8]) {
        let length = buffer.len() as u16;
		let mut ipv4 = MutableIpv4Packet::new(buffer).unwrap();
		ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_identification(1);
        ipv4.set_flags(2);
		ipv4.set_header_length(5);
		ipv4.set_total_length(length);
		ipv4.set_ttl(64);
		ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
		ipv4.set_source("10.0.2.15".parse().unwrap());
		ipv4.set_destination("1.1.1.1".parse().unwrap());
		let checksum = ipv4::checksum(&ipv4.to_immutable());
		ipv4.set_checksum(checksum);
    }
}
