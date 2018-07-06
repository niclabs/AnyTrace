extern crate pnet;

use pnet::packet::icmp::{checksum, echo_request, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::transport::TransportSender;

use std::time::{SystemTime, UNIX_EPOCH};

use std::mem::transmute;

use std::net::{IpAddr, Ipv4Addr};

use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

pub struct IcmpWriter {
    writer: mpsc::Sender<IcmpRequest>,
}

pub struct IcmpRequest {
    target: Ipv4Addr,
    ttl: u8,
    identifier: u16,
    sequence: u16,
}

impl IcmpWriter {
    pub fn new(tx: TransportSender, local: Ipv4Addr) -> IcmpWriter {
        return IcmpWriter {
            writer: Self::run(tx, local),
        };
    }

    pub fn send(&self, target: Ipv4Addr) {
        self.send_complete(target, 64, 1, 1);
    }

    pub fn send_complete(&self, target: Ipv4Addr, ttl: u8, identifier: u16, sequence: u16) {
        self.writer
            .send(IcmpRequest {
                target: target,
                ttl: ttl,
                identifier: identifier,
                sequence: sequence,
            })
            .unwrap();
    }

    fn run(tx: TransportSender, local: Ipv4Addr) -> mpsc::Sender<IcmpRequest> {
        let tx = Arc::new(Mutex::new(tx));
        let (sender, receiver) = mpsc::channel::<IcmpRequest>();

        thread::spawn(move || {
            let mut sender = tx.lock().unwrap();
            while let Ok(request) = receiver.recv() {
                Self::send_icmp(&mut sender, local, request);
            }
        });

        return sender;
    }

    fn send_icmp(tx: &mut TransportSender, src: Ipv4Addr, request: IcmpRequest) {
        // Buffer is [20 ipv4, 8 ICMP, 10 Payload]
        let mut buffer = [0; 20 + 8 + 10];
        Self::format_icmp(&mut buffer[20..], request.identifier, request.sequence);
        Self::format_ipv4(&mut buffer, src, request.target);

        match tx.send_to(
            Ipv4Packet::new(&buffer).unwrap(),
            IpAddr::V4(request.target),
        ) {
            Ok(_) => {}
            Err(e) => println!("failed to send packet: {}", e),
        };
    }

    fn format_icmp(buffer: &mut [u8], identifier: u16, sequence: u16) {
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
            icmp.set_identifier(identifier);
            icmp.set_sequence_number(sequence);
            icmp.set_payload(&payload);
        }
        {
            let mut icmp = MutableIcmpPacket::new(buffer).unwrap();
            let check = checksum(&icmp.to_immutable());
            icmp.set_checksum(check);
        }
    }

    fn format_ipv4(buffer: &mut [u8], src: Ipv4Addr, target: Ipv4Addr) {
        let length = buffer.len() as u16;
        let mut ipv4 = MutableIpv4Packet::new(buffer).unwrap();
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_identification(1323); // Not used by the responce
        ipv4.set_flags(2);
        ipv4.set_header_length(5);
        ipv4.set_total_length(length);
        ipv4.set_ttl(64);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ipv4.set_source(src);
        ipv4.set_destination(target);
        let checksum = ipv4::checksum(&ipv4.to_immutable());
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
