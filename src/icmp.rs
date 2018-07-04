extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::{DataLinkReceiver};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{checksum, echo_request, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, TransportSender};

use pnet::transport::TransportChannelType::Layer4;

use std::net::Ipv4Addr;

use std::cell::RefCell;

pub struct IcmpReader {
    reader: RefCell<Box<DataLinkReceiver>>,
    writer: RefCell<IcmpWriter>,
}

impl IcmpReader {
    pub fn new() -> IcmpReader {
        let iface_name = "enp0s3";
        // Find the network interface with the provided name
        let interfaces = datalink::interfaces();

        let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;
        let interface = interfaces
            .into_iter()
            .filter(interface_names_match)
            .next()
            .unwrap();

        // Create a channel to receive on
        let (_, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("packetdump: unhandled channel type: {}"),
            Err(e) => panic!("packetdump: unable to create channel: {}", e),
        };
        return IcmpReader {
            reader: RefCell::new(rx),
            writer: RefCell::new(IcmpWriter::new(iface_name)),
        };
    }

    pub fn run(&mut self) {
        let mut reader = self.reader.try_borrow_mut().unwrap();
        loop {
            let packet = reader.next();
            match packet {
                Ok(packet) => {
                    self.process_data(packet);
                }
                Err(_) => {}
            }
        }
    }

    fn process_data(&self, packet: &[u8]) {
        let ethernet = EthernetPacket::new(packet).unwrap();
        self.process_ethernet(&ethernet);
    }

    fn process_ethernet(&self, packet: &EthernetPacket) {
        match packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                self.process_ipv4(packet.payload());
            }
            _ => {}
        }
    }

    fn process_ipv4(&self, packet: &[u8]) {
        let header = Ipv4Packet::new(packet);
        if let Some(header) = header {
            match header.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => self.process_icmp4(header.payload(), &header),
                _ => {}
            }
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
