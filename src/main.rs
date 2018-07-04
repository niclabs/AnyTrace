extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{checksum, echo_reply, echo_request, time_exceeded, Icmp, IcmpCode,
                         IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::transport_channel;

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;

use pnet::transport::TransportChannelType::{Layer3, Layer4};

fn send_udp() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:34254")?;

    // Redeclare `buf` as slice of the received data and send reverse data back to origin.
    let buf = [0u8; 0];
    let ip: Ipv4Addr = "1.1.1.33".parse().expect("couldn't parse ip address");
    let address = SocketAddrV4::new(ip, 34254);
    socket.set_ttl(2);
    socket.send_to(&buf, address).expect("couldn't send data");
    return Ok(());
}

fn send_icmp() {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel:
                        {}",
            e
        ),
    };

    let message = Icmp {
        icmp_type: IcmpTypes::EchoRequest,
        icmp_code: IcmpCode::new(0),
        checksum: 0,
        payload: Vec::new(),
    };
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
    //return;
    match tx.send_to(
        IcmpPacket::new(&buffer).unwrap(),
        "1.1.1.1".parse().unwrap(),
    ) {
        Ok(n) => println!("ok"),
        Err(e) => panic!("failed to send packet: {}", e),
    };

    //let mut buffer = [u8; MutableIcmpPacket.]
    //let newpacket = MutableIcmpPacket
}

use pnet::packet::ipv4::Ipv4Packet;

fn receive_icmp() -> std::io::Result<()> {
    use pnet::datalink::Channel::Ethernet;

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
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type: {}"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();
                match ethernet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let header = Ipv4Packet::new(ethernet.payload());
                        if let Some(header) = header {
                            match header.get_next_level_protocol() {
                                IpNextHeaderProtocols::Icmp => {
                                    //println!("{:?}", header.get_source());
                                    let icmp_packet = IcmpPacket::new(header.payload());
                                    if let Some(icmp) = icmp_packet {
                                        match icmp.get_icmp_type() {
                                            IcmpTypes::EchoReply => {
                                                // Only received by the final responce
                                                println!("Reply");
                                                // send again
                                                send_icmp();
                                            }
                                            IcmpTypes::TimeExceeded => {
                                                let request = time_exceeded::TimeExceededPacket::new(header.payload()).unwrap();
                                                println!(
                                                    "ttl0 from {} to {} ({:?})",
                                                    IpAddr::V4(header.get_source()),
                                                    IpAddr::V4(header.get_destination()),
                                                    request.payload()
                                                );
                                                //let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                                                //println!("Received from {} to {}", IpAddr::V4(header.get_source()), IpAddr::V4(header.get_destination()));
                                            }
                                            IcmpTypes::EchoRequest => {
                                                //bien
                                                let request = echo_request::EchoRequestPacket::new(header.payload()).unwrap();
                                                //println!("Req: {:?} {:?} {:?}", request.get_icmp_type(), request.get_icmp_code(), request.get_sequence_number());
                                                //println!("Received from {} to {}", IpAddr::V4(header.get_source()), IpAddr::V4(header.get_destination()));
                                                println!("Received {:?}", header.payload());
                                            }
                                            _ => println!(
                                                "ICMP type {:?} not handled",
                                                icmp.get_icmp_type()
                                            ),
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => panic!("Unable to receive packet: {}", e),
        }
    }

    Ok(())
}

fn main() {
    // -> std::io::Result<()> {
    receive_icmp();
    //send_udp();
    //send_icmp();
}
