extern crate pnet;

use pnet::packet::icmp::{checksum, echo_request, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::transport::{TransportSender};

use std::time::{SystemTime, UNIX_EPOCH};

use std::mem::transmute;

pub struct IcmpWriter {
    tx: TransportSender,
}

impl IcmpWriter {
    pub fn new(tx: TransportSender) -> IcmpWriter {
        return IcmpWriter { tx: tx };
    }

    pub fn send_icmp(&mut self) {
        // Buffer is [20 ipv4, 8 ICMP, 10 Payload]
        let mut buffer = [0; 20 + 8 + 10];
        Self::format_icmp(&mut buffer[20..]);
        Self::format_ipv4(&mut buffer);

        println!("Sending {:?}", &buffer as &[u8]);
        match self.tx.send_to(
            Ipv4Packet::new(&buffer).unwrap(),
            "1.1.1.1".parse().unwrap(),
        ) {
            Ok(_) => println!("ok"),
            Err(e) => panic!("failed to send packet: {}", e),
        };
    }

    fn format_icmp(buffer: &mut [u8]) {
        let mut payload = [0u8; 2 + 8];
        payload[0] = b'm';
        payload[1] = b't';
        payload[2..].clone_from_slice(unsafe {
            &transmute::<u64, [u8; 8]>(Self::time_from_epoch_ms().to_be())
        });
        {
            let mut icmp = echo_request::MutableEchoRequestPacket::new(buffer).unwrap();
            icmp.set_icmp_type(IcmpTypes::EchoRequest);
            icmp.set_icmp_code(echo_request::IcmpCodes::NoCode);
            icmp.set_identifier(1);
            icmp.set_sequence_number(2);
            icmp.set_payload(&payload); // TODO: Add timestamp
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
        println!("checksum: {:?}", checksum);
        ipv4.set_checksum(checksum);
    }

    fn time_from_epoch_ms() -> u64 {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let in_ms =
            since_the_epoch.as_secs() * 1000 + since_the_epoch.subsec_nanos() as u64 / 1_000_000;
        return in_ms;
    }
}
