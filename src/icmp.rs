extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::Packet;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkSender, DataLinkReceiver};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;

use std::net::Ipv4Addr;
use std::cell::RefCell;

pub struct IcmpReader {
    reader: RefCell<Box<DataLinkReceiver>>,
    writer: IcmpWriter
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
        let (tx, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("packetdump: unhandled channel type: {}"),
            Err(e) => panic!("packetdump: unable to create channel: {}", e),
        };
        return IcmpReader {
            reader: RefCell::new(rx),
            writer: IcmpWriter::new(tx),
        };
    }

    pub fn run(&mut self) {
        let mut reader = self.reader.try_borrow_mut().unwrap();
        loop {
            let packet = reader.next();
            match packet {
                Ok(packet) => {
                    self.process_data(packet);
                },
                Err(_) => {},
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
                IpNextHeaderProtocols::Icmp => {
                    self.process_icmp4(header.payload(), &header)
                },
                _ => {},
            }
        }
    }

    fn process_icmp4(&self, packet: &[u8], header: &Ipv4Packet) {
        let icmp_packet = IcmpPacket::new(packet);
        if let Some(icmp) = icmp_packet {
            match icmp.get_icmp_type() {
                IcmpTypes::EchoReply => {
                    println!("Reply");
                },
                IcmpTypes::TimeExceeded => {
                    let src = Ipv4Addr::from(header.get_source());
                    println!("TTL exceeded from {:?}", src);
                },
                IcmpTypes::EchoRequest => {
                    //let request = echo_request::EchoRequestPacket::new(&packet).unwrap();
                    println!("Request Sent");
                },
                _ => {}
            }
        }
    }
}

pub struct IcmpWriter {
    tx: Box<DataLinkSender>,
}

impl IcmpWriter {
    fn new(tx: Box<DataLinkSender>) -> IcmpWriter {
        return IcmpWriter {
            tx: tx,
        }
    }
}