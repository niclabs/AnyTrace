extern crate pnet;
extern crate ratelimit_meter;

use pnet::packet::icmp::{checksum, echo_request, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::transport::TransportSender;

use std::time::{SystemTime, UNIX_EPOCH};

use std::net::{IpAddr, Ipv4Addr};

use ping::PingMethod;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc;
use std::thread;

use ::{Responce, IcmpResponce};

pub struct PingWriter {
    writer: mpsc::Sender<PingRequest>,
    method: PingMethod,
}

struct PingRequest {
    target: Ipv4Addr,
    ttl: u8,
    identifier: u16,
    sequence: u16,
    src_port: u16,
    dst_port: u16,
}

impl PingWriter {
    /// Construct a new PingWriter. The writer will use the local ip as the source of the IPv4 packets.
    ///
    /// This function will spawn a thread that process any received request asynchronously, sending the packet with a frequency of `rate_limit`.
    pub fn new(
        tx: TransportSender,
        local: Ipv4Addr,
        method: PingMethod,
        rate_limit: u32,
        loopback: mpsc::Sender<IcmpResponce>
    ) -> PingWriter {
        return PingWriter {
            writer: Self::run(tx, local, method.clone(), rate_limit, loopback),
            method: method,
        };
    }

    /// Send a generic Echo request to the ipv4 target asynchronously.
    ///
    /// If sending an ICMP packet, it will have a default identification and sequence of 1.
    /// The payload will contain the timestamp in milliseconds, followed by the character 'mt'.
    pub fn send(&self, target: Ipv4Addr) {
        self.send_complete(target, 33434, 33434, 64, 1, 1);
    }

    /// Send an ICMP request with the given parameters
    pub fn send_icmp(&self, target: Ipv4Addr, ttl: u8, identifier: u16, sequence: u16) {
        assert_eq!(
            self.method,
            PingMethod::ICMP,
            "Calling send_udp is not allowed when the method is not PingMethod::ICMP"
        );
        self.send_complete(target, 0, 0, ttl, identifier, sequence)
    }

    /// Send an UDP request with the given parameters
    pub fn send_udp(&self, target: Ipv4Addr, ttl: u8, src_port: u16, dst_port: u16) {
        assert_eq!(
            self.method,
            PingMethod::UDP,
            "Calling send_udp is not allowed when the method is PingMethod::UDP"
        );
        self.send_complete(target, src_port, dst_port, ttl, 0, 0);
    }

    /// Send the Echo request to the ipv4 target asynchronously with the given parameters.
    ///
    /// The payload will contain the timestamp in milliseconds, followed by the character 'mt'.
    pub fn send_complete(
        &self,
        target: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        ttl: u8,
        identifier: u16,
        sequence: u16,
    ) {
        self.writer
            .send(PingRequest {
                target: target,
                ttl: ttl,
                identifier: identifier,
                sequence: sequence,
                src_port: src_port,
                dst_port: dst_port,
            })  
            .unwrap();
    }

    /// Create a new thread and a channel to receive requests asynchronously.
    /// 
    /// Use process_icmp or process_udp depending on the selected method.
    fn run(
        tx: TransportSender,
        local: Ipv4Addr,
        method: PingMethod,
        rate_limit: u32,
        loopback: mpsc::Sender<IcmpResponce>,
    ) -> mpsc::Sender<PingRequest> {
        let tx = Arc::new(Mutex::new(tx));
        let (sender, receiver) = mpsc::channel::<PingRequest>();
        let process = match method {
            PingMethod::ICMP => Self::process_icmp,
            PingMethod::UDP => Self::process_tcp,
        };
        use ping::writer::ratelimit_meter::Decider;
        use std::time::Duration;
        thread::spawn(move || {
            let mut ratelimit = ratelimit_meter::LeakyBucket::new(rate_limit, Duration::from_secs(1)).unwrap();

            let mut sender = tx.lock().unwrap();
            while let Ok(request) = receiver.recv() {
                match ratelimit.check() {
                    Ok(()) => { 
                        process(&mut sender, local, &request, &loopback);
                    }
                    Err(_) => {
                        // Wait for 100 millis to fill the bucket with more than one item,
                        // preveting wakeups of one packet
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        });

        return sender;
    }

    /// Send a UDP packet with the given parameters
    fn process_udp(tx: &mut TransportSender, src: Ipv4Addr, request: &PingRequest, loopback: &mpsc::Sender<IcmpResponce>) {
        // Buffer is [20 ipv4, 8 UDP, 14 Payload]
        let mut buffer = [0; 20 + 8 + 14];
        Self::format_udp(&mut buffer[20..], request);
        Self::format_ipv4(
            &mut buffer,
            IpNextHeaderProtocols::Udp,
            src,
            request.target,
            request.ttl,
        );
        match tx.send_to(
            Ipv4Packet::new(&buffer).unwrap(),
            IpAddr::V4(request.target),
        ) {
            Ok(_) => {
                // send the packet to the loopback to store the send_time
                let _ = loopback.send(IcmpResponce {
                    source: src,
                    ttl: request.ttl,
                    icmp: Responce::LocalSendedEcho(request.target),
                    time_ms: Self::time_from_epoch_ms(),
                });
            }
            Err(e) => error!("failed to send packet: {}", e),
        };
    }

    /// Format the buffer as a UDP packet.
    fn format_udp(buffer: &mut [u8], request: &PingRequest) {
        {
            let mut udp = MutableUdpPacket::new(buffer).unwrap();
            udp.set_source(request.src_port);
            udp.set_destination(request.dst_port);
            udp.set_length(8+14);
            udp.set_checksum(0);
        }
        Self::set_payload(&mut buffer[8..], request.identifier, request.sequence);
    }

    /// Send a ICMP packet with the given parameters
    fn process_icmp(tx: &mut TransportSender, src: Ipv4Addr, request: &PingRequest, loopback: &mpsc::Sender<IcmpResponce>) {
        // Buffer is [20 ipv4, 8 ICMP, 14 Payload]
        let mut buffer = [0; 20 + 8 + 14];

        Self::format_icmp(&mut buffer[20..], request.identifier, request.sequence);
        Self::format_ipv4(
            &mut buffer,
            IpNextHeaderProtocols::Icmp,
            src,
            request.target,
            request.ttl,
        );

        match tx.send_to(
            Ipv4Packet::new(&buffer).unwrap(),
            IpAddr::V4(request.target),
        ) {
            Ok(_) => {
                // send the packet to the loopback to store the send_time
                let _ = loopback.send(IcmpResponce {
                    source: src,
                    ttl: request.ttl,
                    icmp: Responce::LocalSendedEcho(request.target),
                    time_ms: Self::time_from_epoch_ms(),
                });
            }
            Err(e) => error!("failed to send packet to {}: {}", request.target, e),
        };
    }

    /// Format the buffer as a ICMP packet.
    ///
    /// The payload of the packet will be the u64 timestamp, followed by the characters 'mt'.
    fn format_icmp(buffer: &mut [u8], identifier: u16, sequence: u16) {
        let mut payload = [0u8; 14];
        Self::set_payload(&mut payload, identifier, sequence);
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

    /// Process and send a TCP Packet
    /// 
    /// TODO: Handle the ack responces.
    fn process_tcp(tx: &mut TransportSender, src: Ipv4Addr, request: &PingRequest, loopback: &mpsc::Sender<IcmpResponce>) {
        // Buffer is [20 ipv4, 20 TCP, 14 Payload]
        let mut buffer = [0; 20 + 20 + 14];

        Self::format_tcp(&mut buffer[20..], request, src);
        Self::format_ipv4(
            &mut buffer,
            IpNextHeaderProtocols::Tcp,
            src,
            request.target,
            request.ttl,
        );

        match tx.send_to(
            Ipv4Packet::new(&buffer).unwrap(),
            IpAddr::V4(request.target),
        ) {
            Ok(_) => {
                // send the packet to the loopback to store the send_time
                let _ = loopback.send(IcmpResponce {
                    source: src,
                    ttl: request.ttl,
                    icmp: Responce::LocalSendedEcho(request.target),
                    time_ms: Self::time_from_epoch_ms(),
                });
            }
            Err(e) => error!("failed to send packet to {}: {}", request.target, e),
        };
    }

    /// Format the buffer as a TCP packet.
    /// 
    /// The Ack returned by the target host will be the current sequence+1
    fn format_tcp(buffer: &mut [u8], request: &PingRequest, src: Ipv4Addr) {
        let mut payload = [0; 14];
        Self::set_payload(&mut payload, request.identifier, request.sequence);
        {
            let mut tcp = MutableTcpPacket::new(buffer).unwrap();
            tcp.set_source(request.src_port);
            tcp.set_destination(80);//request.dst_port);
            tcp.set_payload(&payload);
            tcp.set_data_offset(5 + 3);
            tcp.set_flags(TcpFlags::SYN);
            tcp.set_sequence(1523232);

            use pnet::packet::tcp::ipv4_checksum;
            let checksum = ipv4_checksum(&tcp.to_immutable(), &src, &request.target);
            tcp.set_checksum(checksum);
        }
    }

    /// Format the buffer IPv4 Header
    fn format_ipv4(
        buffer: &mut [u8],
        protocol: IpNextHeaderProtocol,
        src: Ipv4Addr,
        target: Ipv4Addr,
        ttl: u8,
    ) {
        let length = buffer.len() as u16;
        let mut ipv4 = MutableIpv4Packet::new(buffer).unwrap();
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_identification(1323); // Not used by the responce
        ipv4.set_flags(2);
        ipv4.set_header_length(5);
        ipv4.set_total_length(length);
        ipv4.set_ttl(ttl);
        ipv4.set_next_level_protocol(protocol);
        ipv4.set_source(src);
        ipv4.set_destination(target);
        let checksum = ipv4::checksum(&ipv4.to_immutable());
        ipv4.set_checksum(checksum);
    }

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

    /// Transform a u64 to a byte array
    fn u64_to_array(x: u64) -> [u8; 8] {
        return [
            ((x >> 56) & 0xff) as u8,
            ((x >> 48) & 0xff) as u8,
            ((x >> 40) & 0xff) as u8,
            ((x >> 32) & 0xff) as u8,
            ((x >> 24) & 0xff) as u8,
            ((x >> 16) & 0xff) as u8,
            ((x >> 8) & 0xff) as u8,
            (x & 0xff) as u8,
        ];
    }

    /// Set the payload of the packet, with a minimun of 14 bytes of payload.
    /// The format used is [id(2), seq(2), timestamp(8), key(2)].
    fn set_payload(payload: &mut [u8], identifier: u16, sequence: u16) {
        if payload.len() < 14 {
            panic!("Payload buffer of incorrect length {}", payload.len());
        }
        payload[0..4].clone_from_slice(&[
            (identifier >> 8) as u8, identifier as u8,
            (sequence >> 8) as u8, sequence as u8
        ]);
        payload[4..12].clone_from_slice(&Self::u64_to_array(Self::time_from_epoch_ms().to_be()));
        payload[12..14].clone_from_slice(Self::get_payload_key());
    }



    /// Get the current key of the packets
    pub fn get_payload_key() -> &'static [u8; 2] {
        return b"mt";
    }
}
