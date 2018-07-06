mod reader;
mod writer;

use self::reader::IcmpReader;
use self::writer::IcmpWriter;

use std::net::Ipv4Addr;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer3;

pub struct IcmpHandler {
    reader: IcmpReader,
    writer: IcmpWriter,
}

impl IcmpHandler {
    /// Construct a new IcmpHandler.
    ///
    /// This will write and read the received ICMP packets asynchronously.
    pub fn new(localip: &str) -> IcmpHandler {
        let local: Ipv4Addr = localip.parse().unwrap();
        let (reader, writer) = Self::generate_transport(local);
        return IcmpHandler {
            reader: reader,
            writer: writer,
        };
    }

    pub fn run(&mut self) {
        let target: Ipv4Addr = "1.1.1.1".parse().unwrap();
        for _ in 0..10 {
            self.writer.send(target);
        }
        use std::{thread, time};
        thread::sleep(time::Duration::from_millis(10000));
        while let Ok(packet) = self.reader.reader.try_recv() {
            println!("{:?}, {:?}", packet.source, packet.ttl);
        }

        println!("ended");
    }

    /// Construct the IcmpReader and IcmpWriter using the given local IPv4 Address.
    fn generate_transport(local: Ipv4Addr) -> (IcmpReader, IcmpWriter) {
        let protocol = Layer3(IpNextHeaderProtocols::Icmp);
        let (tx, rx) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!(
                "An error occurred when creating the transport channel:
                            {}",
                e
            ),
        };

        return (IcmpReader::new(rx, local), IcmpWriter::new(tx, local));
    }
}
