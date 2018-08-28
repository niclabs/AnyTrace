extern crate pnet;

use pnet::packet::FromPacket;
use pnet::packet::Packet;
use pnet::packet::icmp::destination_unreachable::{DestinationUnreachable,
                                                  DestinationUnreachablePacket};
use pnet::packet::icmp::echo_reply::{EchoReply, EchoReplyPacket};
use pnet::packet::icmp::time_exceeded::{TimeExceeded, TimeExceededPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::transport::{TransportReceiver, ipv4_packet_iter};

use std::net::Ipv4Addr;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PingReader {
    reader: mpsc::Receiver<IcmpResponce>,
}

pub enum Responce {
    Echo(EchoReply),
    Timeout(TimeExceeded),
    Unreachable(DestinationUnreachable),
}

pub struct IcmpResponce {
    pub source: Ipv4Addr,
    pub ttl: u8,
    pub icmp: Responce,
    pub time_ms: u64,
}

impl PingReader {
    pub fn new(tx: TransportReceiver, local: Ipv4Addr) -> PingReader {
        return PingReader {
            reader: Self::run(local, tx),
        };
    }

    pub fn reader(&self) -> &mpsc::Receiver<IcmpResponce> {
        return &self.reader;
    }

    /// Create a new thread and channel to receive requests asynchronously.
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

    /// Parse the IPv4 packet, only continuing if the ICMP protocol was used.
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

    /// Parse the ICMP packet and send EchoReply to the channel.
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
                            icmp: Responce::Echo(icmp.from_packet()),
                            time_ms: Self::time_from_epoch_ms(),
                        };
                        if let Err(_) = sender.send(responce) {
                            // Return error if the channel is closed.
                            return Err(());
                        }
                    }
                }
                IcmpTypes::TimeExceeded => {
                    if let Some(icmp) = TimeExceededPacket::new(&packet) {
                        let responce = IcmpResponce {
                            source: Ipv4Addr::from(header.get_source()),
                            ttl: header.get_ttl(),
                            icmp: Responce::Timeout(icmp.from_packet()),
                            time_ms: Self::time_from_epoch_ms(),
                        };
                        if let Err(_) = sender.send(responce) {
                            // Return error if the channel is closed.
                            return Err(());
                        }
                    }
                }
                IcmpTypes::DestinationUnreachable => {
                    if let Some(icmp) = DestinationUnreachablePacket::new(&packet) {
                        let responce = IcmpResponce {
                            source: Ipv4Addr::from(header.get_source()),
                            ttl: header.get_ttl(),
                            icmp: Responce::Unreachable(icmp.from_packet()),
                            time_ms: Self::time_from_epoch_ms(),
                        };
                        if let Err(_) = sender.send(responce) {
                            // Return error if the channel is closed.
                            return Err(());
                        }
                    }
                }
                IcmpTypes::EchoRequest => {
                    // This is not received unless we parse from the DataLink layer.
                }
                _ => {}
            }
        }
        return Ok(());
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
}
